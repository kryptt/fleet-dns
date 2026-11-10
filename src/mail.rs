//! MailAccount reconciler: turns MailAccount resources into LDAP entries that
//! Stalwart serves as mailboxes.
//!
//! Trust model: a namespace may hold MailAccounts only if `MAIL_DOMAINS` maps
//! it to a domain, and the address is always `<localPart>@<that domain>`. The
//! map lives in fleet-dns's own deployment, so a tenant that can write its own
//! namespace (including its Organization) still cannot mint addresses outside
//! the domain the operator gave it. fleet-dns only ever writes, changes or
//! deletes entries under the bots OU that carry its ownership marker, and
//! refuses any local part or address already used anywhere in the directory:
//! Stalwart names its principals after the local part, so a cross-domain
//! local-part clash would merge two tenants' mailboxes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;

use base64::Engine;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Patch, PatchParams};
use kube::runtime::reflector::Store;
use kube::{Api, Client, Resource, ResourceExt};
use ldap3::exop::PasswordModify;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry, dn_escape, ldap_escape,
};
use tracing::{info, warn};

use crate::config::read_secret;
use crate::crd::{MailAccount, MailAccountStatus};
use crate::error::Error;

const MARKER: &str = "fleet-dns MailAccount ";
const FIELD_MANAGER: &str = "fleet-dns";
/// RFC 2142 role mailboxes plus the obvious privileged names.
const RESERVED: &[&str] = &[
    "postmaster",
    "abuse",
    "hostmaster",
    "webmaster",
    "mailer-daemon",
    "root",
    "admin",
    "administrator",
];
const ATTRS: &[&str] = &[
    "description",
    "mail",
    "mailAlias",
    "sn",
    "uid",
    "displayName",
];

/// Mail reconciler configuration, from the environment.
#[derive(Debug)]
pub struct MailConfig {
    /// namespace -> mail domain.
    pub domains: BTreeMap<String, String>,
    pub ldap_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    /// Subtree searched for address conflicts (the whole directory).
    pub base_dn: String,
    /// OU the accounts are written under.
    pub bots_dn: String,
    /// Skip certificate verification (in-cluster service name not in the SAN).
    pub tls_insecure: bool,
}

impl MailConfig {
    /// `None` when `MAIL_DOMAINS` is unset: mail management disabled.
    ///
    /// - `MAIL_DOMAINS` — `ns=domain[,ns=domain...]`, e.g. `quota=quota.fitness`
    /// - `LDAP_URL` (default `ldap://openldap.system.svc.cluster.local:389`,
    ///   STARTTLS for `ldap://`)
    /// - `LDAP_BIND_DN` (default `cn=fleet-dns,ou=services,{LDAP_BASE_DN}`)
    /// - `LDAP_BIND_PASSWORD` or `LDAP_BIND_PASSWORD_FILE` (required)
    /// - `LDAP_BASE_DN` (default `dc=hr-home,dc=xyz`)
    /// - `LDAP_BOTS_DN` (default `ou=bots,{LDAP_BASE_DN}`)
    /// - `LDAP_TLS_INSECURE` (default false)
    pub fn from_env() -> Result<Option<Self>, Error> {
        let Ok(raw) = std::env::var("MAIL_DOMAINS") else {
            return Ok(None);
        };
        let domains = parse_domains(&raw)?;
        let var = |k: &str, d: String| std::env::var(k).unwrap_or(d);
        let base_dn = var("LDAP_BASE_DN", "dc=hr-home,dc=xyz".into());
        Ok(Some(Self {
            domains,
            ldap_url: var(
                "LDAP_URL",
                "ldap://openldap.system.svc.cluster.local:389".into(),
            ),
            bind_dn: var(
                "LDAP_BIND_DN",
                format!("cn=fleet-dns,ou=services,{base_dn}"),
            ),
            bind_password: read_secret("LDAP_BIND_PASSWORD")?,
            bots_dn: var("LDAP_BOTS_DN", format!("ou=bots,{base_dn}")),
            base_dn,
            tls_insecure: matches!(
                std::env::var("LDAP_TLS_INSECURE").as_deref(),
                Ok("true" | "1")
            ),
        }))
    }
}

fn parse_domains(raw: &str) -> Result<BTreeMap<String, String>, Error> {
    raw.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (ns, domain) = pair
                .split_once('=')
                .map(|(n, d)| (n.trim(), d.trim().to_ascii_lowercase()))
                .filter(|(n, d)| !n.is_empty() && d.contains('.'))
                .ok_or_else(|| Error::Config(format!("MAIL_DOMAINS: bad entry {pair:?}")))?;
            Ok((ns.to_owned(), domain))
        })
        .collect()
}

/// Lowercase `[a-z0-9._-]`, 1-64 chars, no leading/trailing/double dot.
fn valid_local_part(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

/// A user-fixable reason the account was not provisioned (goes to status).
struct Rejected(String);

/// One managed LDAP entry under the bots OU.
struct Entry {
    owner: String,
    attrs: HashMap<String, Vec<String>>,
}

pub struct MailReconciler {
    cfg: MailConfig,
    store: Store<MailAccount>,
    kube: Client,
    dry_run: bool,
}

impl MailReconciler {
    #[must_use]
    pub fn new(cfg: MailConfig, store: Store<MailAccount>, kube: Client, dry_run: bool) -> Self {
        Self {
            cfg,
            store,
            kube,
            dry_run,
        }
    }

    pub async fn run_once(&self) -> Result<(), Error> {
        // An unsynced store looks like "every account was deleted".
        self.store
            .wait_until_ready()
            .await
            .map_err(|e| Error::Mail(format!("MailAccount store: {e}")))?;
        if self.dry_run {
            info!("[dry-run] skipping MailAccount reconciliation");
            return Ok(());
        }

        let mut ldap = self.connect().await?;
        let managed = self.managed_entries(&mut ldap).await?;

        let mut accounts = self.store.state();
        // Oldest first, so the first claimant of a duplicate address keeps it.
        accounts.sort_by(|a, b| {
            a.metadata
                .creation_timestamp
                .cmp(&b.metadata.creation_timestamp)
        });
        let live: HashSet<String> = accounts.iter().map(|a| owner_of(a)).collect();

        let mut claimed: HashSet<String> = HashSet::new();
        for acct in &accounts {
            let status = match self
                .reconcile_one(&mut ldap, acct, &managed, &live, &mut claimed)
                .await?
            {
                Ok(status) => status,
                Err(Rejected(msg)) => {
                    warn!(account = %owner_of(acct), reason = %msg, "MailAccount rejected");
                    MailAccountStatus {
                        message: Some(msg),
                        ..Default::default()
                    }
                }
            };
            self.patch_status(acct, status).await?;
        }

        for (dn, entry) in &managed {
            if claimed.contains(dn) || live.contains(&entry.owner) {
                continue;
            }
            let ns = entry.owner.split('/').next().unwrap_or_default();
            if !self.cfg.domains.contains_key(ns) {
                warn!(%dn, owner = %entry.owner, "managed mail entry for a namespace no longer in MAIL_DOMAINS; leaving it");
                continue;
            }
            ldap.delete(dn).await?.success()?;
            info!(%dn, owner = %entry.owner, "deleted mail account (mailbox data stays in Stalwart)");
        }

        ldap.unbind().await.ok();
        Ok(())
    }

    async fn connect(&self) -> Result<Ldap, Error> {
        let settings = LdapConnSettings::new()
            .set_starttls(self.cfg.ldap_url.starts_with("ldap://"))
            .set_no_tls_verify(self.cfg.tls_insecure);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.cfg.ldap_url).await?;
        ldap3::drive!(conn);
        ldap.simple_bind(&self.cfg.bind_dn, &self.cfg.bind_password)
            .await?
            .success()?;
        Ok(ldap)
    }

    /// Entries under the bots OU carrying the ownership marker, keyed by
    /// lowercased DN.
    async fn managed_entries(&self, ldap: &mut Ldap) -> Result<HashMap<String, Entry>, Error> {
        let filter = format!("(description={}*)", ldap_escape(MARKER));
        let (rs, _) = ldap
            .search(&self.cfg.bots_dn, Scope::OneLevel, &filter, ATTRS)
            .await?
            .success()?;
        Ok(rs
            .into_iter()
            .map(SearchEntry::construct)
            .filter_map(|e| {
                let owner = e
                    .attrs
                    .get("description")?
                    .iter()
                    .find_map(|d| d.strip_prefix(MARKER))?
                    .to_owned();
                Some((
                    e.dn.to_ascii_lowercase(),
                    Entry {
                        owner,
                        attrs: e.attrs,
                    },
                ))
            })
            .collect())
    }

    /// Outer `Err` = infrastructure failure (abort the pass); inner `Err` =
    /// this account is refused.
    async fn reconcile_one(
        &self,
        ldap: &mut Ldap,
        acct: &MailAccount,
        managed: &HashMap<String, Entry>,
        live: &HashSet<String>,
        claimed: &mut HashSet<String>,
    ) -> Result<Result<MailAccountStatus, Rejected>, Error> {
        let owner = owner_of(acct);
        let ns = acct.namespace().unwrap_or_default();
        let Some(domain) = self.cfg.domains.get(&ns) else {
            return Ok(Err(Rejected(format!(
                "namespace {ns} is not allowed to hold mail accounts"
            ))));
        };
        let local = acct.spec.local_part.as_str();
        for part in std::iter::once(local).chain(acct.spec.aliases.iter().map(String::as_str)) {
            if !valid_local_part(part) {
                return Ok(Err(Rejected(format!("invalid local part {part:?}"))));
            }
            if RESERVED.contains(&part) {
                return Ok(Err(Rejected(format!("local part {part:?} is reserved"))));
            }
        }
        let address = format!("{local}@{domain}");
        let aliases: Vec<String> = acct
            .spec
            .aliases
            .iter()
            .map(|a| format!("{a}@{domain}"))
            .filter(|a| *a != address)
            .collect();
        let dn = format!("cn={},{}", dn_escape(&address), self.cfg.bots_dn);
        let key = dn.to_ascii_lowercase();

        if !claimed.insert(key.clone()) {
            return Ok(Err(Rejected(format!(
                "{address} is already claimed by another MailAccount"
            ))));
        }
        let existing = managed.get(&key);
        if let Some(e) = existing
            && e.owner != owner
            && live.contains(&e.owner)
        {
            return Ok(Err(Rejected(format!(
                "{address} is owned by MailAccount {}",
                e.owner
            ))));
        }

        // Anything else in the directory using this local part or any of
        // these addresses?
        let mut clauses = vec![
            format!("(uid={})", ldap_escape(local)),
            format!("(mail={}@*)", ldap_escape(local)),
            format!("(mailAlias={}@*)", ldap_escape(local)),
        ];
        for a in &aliases {
            clauses.push(format!("(mail={})", ldap_escape(a)));
            clauses.push(format!("(mailAlias={})", ldap_escape(a)));
        }
        let filter = format!("(|{})", clauses.concat());
        let (rs, _) = ldap
            .search(&self.cfg.base_dn, Scope::Subtree, &filter, vec!["1.1"])
            .await?
            .success()?;
        let clashes: Vec<String> = rs
            .into_iter()
            .map(|r| SearchEntry::construct(r).dn)
            .filter(|d| d.to_ascii_lowercase() != key)
            .collect();
        if !clashes.is_empty() {
            return Ok(Err(Rejected(format!(
                "{address} (or an alias, or local part {local:?} in another domain) is already used by {}",
                clashes.join(", ")
            ))));
        }

        let display = acct
            .spec
            .display_name
            .clone()
            .unwrap_or_else(|| local.to_owned());
        let mut desired: Vec<(&str, Vec<String>)> = vec![
            ("description", vec![format!("{MARKER}{owner}")]),
            ("mail", vec![address.clone()]),
            ("mailAlias", aliases),
            ("sn", vec![display.clone()]),
            ("uid", vec![local.to_owned()]),
            ("displayName", vec![display]),
        ];

        let created = match existing {
            None => {
                let mut attrs: Vec<(String, HashSet<String>)> = vec![
                    (
                        "objectClass".into(),
                        ["inetOrgPerson", "PostfixBookMailAccount"]
                            .map(String::from)
                            .into(),
                    ),
                    ("cn".into(), HashSet::from([address.clone()])),
                ];
                attrs.extend(
                    desired
                        .drain(..)
                        .filter(|(_, v)| !v.is_empty())
                        .map(|(k, v)| (k.to_owned(), v.into_iter().collect())),
                );
                let res = ldap.add(&dn, attrs).await?;
                if res.rc == 68 {
                    return Ok(Err(Rejected(format!(
                        "{dn} exists but is not managed by fleet-dns"
                    ))));
                }
                res.success()?;
                info!(%dn, %owner, "created mail account");
                true
            }
            Some(e) => {
                let mods: Vec<Mod<String>> = desired
                    .into_iter()
                    .filter(|(k, v)| {
                        let mut have = e.attrs.get(*k).cloned().unwrap_or_default();
                        let mut want = v.clone();
                        have.sort();
                        want.sort();
                        have != want
                    })
                    .map(|(k, v)| Mod::Replace(k.to_owned(), v.into_iter().collect()))
                    .collect();
                if !mods.is_empty() {
                    ldap.modify(&dn, mods).await?.success()?;
                    info!(%dn, %owner, "updated mail account");
                }
                false
            }
        };

        let secret_name = format!("mail-{}", acct.name_any());
        let secrets: Api<Secret> = Api::namespaced(self.kube.clone(), &ns);
        let has_password = secrets
            .get_opt(&secret_name)
            .await?
            .and_then(|s| s.data)
            .is_some_and(|d| d.contains_key("password"));
        if created || !has_password {
            let password = random_password()?;
            ldap.extended(PasswordModify {
                user_id: Some(&dn),
                old_pass: None,
                new_pass: Some(&password),
            })
            .await?
            .success()?;
            let secret = Secret {
                metadata: kube::api::ObjectMeta {
                    name: Some(secret_name.clone()),
                    namespace: Some(ns.clone()),
                    owner_references: acct.controller_owner_ref(&()).map(|r| vec![r]),
                    labels: Some(BTreeMap::from([(
                        "app.kubernetes.io/managed-by".into(),
                        "fleet-dns".into(),
                    )])),
                    ..Default::default()
                },
                data: Some(BTreeMap::from([
                    ("address".into(), ByteString(address.clone().into_bytes())),
                    ("password".into(), ByteString(password.into_bytes())),
                ])),
                ..Default::default()
            };
            secrets
                .patch(
                    &secret_name,
                    &PatchParams::apply(FIELD_MANAGER).force(),
                    &Patch::Apply(&secret),
                )
                .await?;
            info!(%dn, secret = %format!("{ns}/{secret_name}"), "set mail account password");
        }

        Ok(Ok(MailAccountStatus {
            address: Some(address),
            ready: true,
            message: None,
            secret_name: Some(secret_name),
        }))
    }

    async fn patch_status(
        &self,
        acct: &MailAccount,
        status: MailAccountStatus,
    ) -> Result<(), Error> {
        if acct.status.as_ref() == Some(&status) {
            return Ok(());
        }
        let api: Api<MailAccount> =
            Api::namespaced(self.kube.clone(), &acct.namespace().unwrap_or_default());
        api.patch_status(
            &acct.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await?;
        Ok(())
    }
}

fn owner_of(acct: &MailAccount) -> String {
    format!(
        "{}/{}",
        acct.namespace().unwrap_or_default(),
        acct.name_any()
    )
}

fn random_password() -> Result<String, Error> {
    let mut buf = [0u8; 24];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| Error::Mail(format!("/dev/urandom: {e}")))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_parts() {
        for ok in ["dave", "a", "first.last", "x_y-z9"] {
            assert!(valid_local_part(ok), "{ok}");
        }
        for bad in [
            "", "Dave", ".a", "a.", "a..b", "a@b", "a b", "*", "a)(uid=*",
        ] {
            assert!(!valid_local_part(bad), "{bad}");
        }
        assert!(!valid_local_part(&"a".repeat(65)));
    }

    #[test]
    fn domains_parse() {
        let m = parse_domains(" quota=Quota.Fitness , fida=fida.finance,").unwrap();
        assert_eq!(m["quota"], "quota.fitness");
        assert_eq!(m["fida"], "fida.finance");
        assert!(parse_domains("quota").is_err());
        assert!(parse_domains("=quota.fitness").is_err());
        assert!(parse_domains("quota=localhost").is_err());
    }

    #[test]
    fn passwords_are_random() {
        let a = random_password().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, random_password().unwrap());
    }
}
