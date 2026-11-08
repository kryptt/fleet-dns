use std::time::Duration;

use crate::{error::Error, state::parse_duration};

/// Application configuration, loaded from environment variables.
///
/// Secrets support a `_FILE` suffix convention: if `OPNSENSE_API_KEY_FILE` is
/// set, the file's contents are read and trimmed. Direct env vars are used as
/// a fallback.
#[derive(Debug)]
pub struct Config {
    pub cloudflare_api_token: String,
    pub opnsense_url: String,
    pub opnsense_api_key: String,
    pub opnsense_api_secret: String,
    pub default_reconcile_interval: Duration,
    pub default_dns_ttl: Duration,
    pub wan_interface: String,
    pub dry_run: bool,

    /// Organizations (tenants) this deployment manages. Always holds at least
    /// the default organization, built from the DNS_ZONE / CLOUDFLARE_* vars.
    pub orgs: Orgs,

    /// Name of the Zitadel organization to treat as the default, i.e. the one
    /// used by any CRD that names no organization.
    pub default_org: String,

    // Optional: Zitadel OIDC management (all must be set to enable)
    pub zitadel_url: Option<String>,
    pub zitadel_key_id: Option<String>,
    pub zitadel_user_id: Option<String>,
    pub zitadel_private_key: Option<String>,
}

/// A single organization (tenant): one Zitadel org paired with one DNS zone.
///
/// Every record fleet-dns writes belongs to exactly one organization. The
/// organization is picked by DNS-zone suffix for hostnames, and by explicit
/// `spec.org` / `hr-home.xyz/org` for resources that carry no hostname (OIDC
/// applications, DHCP reservations).
///
/// - `name` — the Zitadel organization name, used as the tenant key in CRDs
///   (e.g. `hr-home`, `quota-fitness`).
/// - `zone` — the bare DNS zone (e.g. `quota.fitness`).
/// - `managed_zone` — the leading-dot suffix (`.quota.fitness`).
/// - `unbound_anchor` — the Unbound anchor hostname holding the Traefik
///   macvlan A record; IngressRoute hostnames in this zone become aliases of
///   it. Defaults to `ha.{zone}`.
/// - `cloudflare_zone_id` — `None` disables Cloudflare for this organization;
///   CoreDNS and Unbound still apply.
/// - `cloudflare_cname_target` — hostname holding the WAN A record that
///   service CNAMEs point at. Defaults to `origin.{zone}`.
/// - `zitadel_org_id` — resolved Zitadel org ID, sent as `x-zitadel-orgid`.
///   `None` means "the service account's default organization", which is what
///   every Zitadel call used before organizations existed.
/// - `manage_dns` — whether fleet-dns writes DNS for this zone. When false the
///   organization is registry-only: usable for OIDC and for qualifying DHCP
///   hostnames, but its zone is invisible to every DNS target, so hostnames in
///   it are ignored rather than reconciled. False is the safe default, because
///   managing a zone also means orphan-deleting records in it that fleet-dns
///   did not create.
#[derive(Debug, Clone)]
pub struct Org {
    pub name: String,
    pub zone: String,
    pub managed_zone: String,
    pub unbound_anchor: String,
    pub cloudflare_zone_id: Option<String>,
    pub cloudflare_cname_target: String,
    pub zitadel_org_id: Option<String>,
    pub manage_dns: bool,
}

impl Org {
    /// Build an organization from a name and zone, filling the derived
    /// defaults (`managed_zone`, `unbound_anchor`, `cloudflare_cname_target`).
    #[must_use]
    pub fn new(name: &str, zone: &str) -> Self {
        Self {
            name: name.to_owned(),
            zone: zone.to_owned(),
            managed_zone: format!(".{zone}"),
            unbound_anchor: format!("ha.{zone}"),
            cloudflare_zone_id: None,
            cloudflare_cname_target: format!("origin.{zone}"),
            zitadel_org_id: None,
            manage_dns: false,
        }
    }

    /// True when `hostname` belongs to this organization's zone.
    ///
    /// Zone membership only; it does not imply fleet-dns manages the record.
    /// Callers that write DNS must also check [`Self::manage_dns`], or go
    /// through [`Orgs::for_hostname`], which filters on it.
    #[must_use]
    pub fn owns_hostname(&self, hostname: &str) -> bool {
        hostname.ends_with(self.managed_zone.as_str()) || hostname == self.zone
    }

    /// Fixed organization used by unit tests. Mirrors the historical
    /// compiled-in defaults so existing test fixtures keep their hostnames.
    #[cfg(test)]
    #[must_use]
    pub fn test() -> Self {
        Self {
            name: "hr-home".to_owned(),
            zone: "hr-home.xyz".to_owned(),
            managed_zone: ".hr-home.xyz".to_owned(),
            unbound_anchor: "ha.hr-home.xyz".to_owned(),
            cloudflare_zone_id: Some("zone-123".to_owned()),
            cloudflare_cname_target: "origin.hr-home.xyz".to_owned(),
            zitadel_org_id: None,
            manage_dns: true,
        }
    }
}

/// Pick an organization's DNS zone from its Zitadel facts.
///
/// The `dnsZone` org-metadata value wins, because a Zitadel organization's
/// primary domain is not always a zone fleet-dns should manage: a freshly
/// created organization gets `{name}.zitadel.{instance}`, which is an identity
/// hostname, not a DNS zone. Returns `None` when neither is usable, so the
/// caller skips the organization instead of inventing a zone.
#[must_use]
pub fn org_zone(metadata_dns_zone: Option<&str>, primary_domain: Option<&str>) -> Option<String> {
    metadata_dns_zone
        .or(primary_domain)
        .map(str::trim)
        .filter(|z| !z.is_empty())
        .map(str::to_owned)
}

/// The set of organizations fleet-dns manages, with one marked default.
///
/// The default organization is always present and always built from the
/// `DNS_ZONE` / `CLOUDFLARE_*` environment variables, so a deployment that
/// names no organization anywhere behaves exactly as it did before
/// organizations existed. Additional organizations are discovered from Zitadel
/// at startup (see `Orgs::extend`).
#[derive(Debug, Clone)]
pub struct Orgs {
    orgs: Vec<Org>,
    default_name: String,
}

impl Orgs {
    /// Build a registry holding a single default organization.
    #[must_use]
    pub fn single(org: Org) -> Self {
        let default_name = org.name.clone();
        Self {
            orgs: vec![org],
            default_name,
        }
    }

    /// Record the resolved Zitadel organization ID for an existing entry.
    pub fn set_zitadel_org_id(&mut self, name: &str, org_id: &str) {
        if let Some(org) = self.orgs.iter_mut().find(|o| o.name == name) {
            org.zitadel_org_id = Some(org_id.to_owned());
        }
    }

    /// Add organizations discovered at runtime. An entry whose name matches an
    /// organization already present is ignored, so the env-configured default
    /// always wins over anything discovered later.
    pub fn extend(&mut self, discovered: impl IntoIterator<Item = Org>) {
        for org in discovered {
            if self.by_name(&org.name).is_none() {
                self.orgs.push(org);
            }
        }
    }

    /// The default organization, used whenever no organization is named.
    ///
    /// # Panics
    /// Never: the registry is constructed with at least one organization and
    /// `default_name` always refers to it.
    #[must_use]
    pub fn default_org(&self) -> &Org {
        self.orgs
            .iter()
            .find(|o| o.name == self.default_name)
            .unwrap_or_else(|| {
                // Unreachable by construction; fall back to the first entry
                // rather than panicking in a reconcile loop.
                &self.orgs[0]
            })
    }

    /// Look up an organization by name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Org> {
        self.orgs.iter().find(|o| o.name == name)
    }

    /// Resolve an optional organization name to an organization, falling back
    /// to the default. Returns `None` when a name is given but unknown, so
    /// callers can warn and skip rather than write to the wrong tenant.
    #[must_use]
    pub fn resolve(&self, name: Option<&str>) -> Option<&Org> {
        match name {
            None => Some(self.default_org()),
            Some(n) => self.by_name(n),
        }
    }

    /// Find the DNS-managing organization owning `hostname`, matching the most
    /// specific (longest) zone suffix so a zone nested inside another still
    /// resolves to the inner one.
    ///
    /// Organizations with `manage_dns == false` are skipped, so a hostname in
    /// a registered-but-unmanaged zone resolves to nothing and is ignored by
    /// every DNS target — the same treatment an unknown zone gets.
    #[must_use]
    pub fn for_hostname(&self, hostname: &str) -> Option<&Org> {
        self.orgs
            .iter()
            .filter(|o| o.manage_dns && o.owns_hostname(hostname))
            .max_by_key(|o| o.zone.len())
    }

    /// Iterate the organizations whose DNS fleet-dns manages.
    pub fn dns_managed(&self) -> impl Iterator<Item = &Org> {
        let default = self.default_org().name.clone();
        self.orgs
            .iter()
            .filter(move |o| o.manage_dns || o.name == default)
    }

    /// Iterate every organization, default first.
    pub fn iter(&self) -> impl Iterator<Item = &Org> {
        let default = self.default_org();
        std::iter::once(default).chain(self.orgs.iter().filter(move |o| o.name != default.name))
    }

    /// Number of organizations in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.orgs.len()
    }

    /// Always false: the registry holds at least the default organization.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Load the default organization from environment variables.
    ///
    /// Optional (with defaults):
    /// - `ORG_NAME` (default `"hr-home"`) — the default organization's name
    /// - `DNS_ZONE` (default `"example.com"`)
    /// - `DNS_MANAGED_ZONE` (default: `.{DNS_ZONE}`)
    /// - `UNBOUND_ANCHOR` (default: `ha.{DNS_ZONE}`)
    /// - `CLOUDFLARE_CNAME_TARGET` (default: `origin.{DNS_ZONE}`)
    /// - `ORG_NAME` (default `"hr-home"`) — name of the default organization
    pub fn from_env(cloudflare_zone_id: String) -> Self {
        let name = std::env::var("ORG_NAME").unwrap_or_else(|_| "hr-home".to_owned());
        let zone = std::env::var("DNS_ZONE").unwrap_or_else(|_| "example.com".to_owned());

        let mut org = Org::new(&name, &zone);
        if let Ok(managed) = std::env::var("DNS_MANAGED_ZONE") {
            org.managed_zone = managed;
        }
        if let Ok(anchor) = std::env::var("UNBOUND_ANCHOR") {
            org.unbound_anchor = anchor;
        }
        if let Ok(target) = std::env::var("CLOUDFLARE_CNAME_TARGET") {
            org.cloudflare_cname_target = target;
        }
        org.cloudflare_zone_id = Some(cloudflare_zone_id);
        // The deployment's own zone, configured by hand: always managed.
        org.manage_dns = true;

        Self::single(org)
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Required:
    /// - `CLOUDFLARE_API_TOKEN`
    /// - `CLOUDFLARE_ZONE_ID`
    /// - `OPNSENSE_URL`
    /// - `OPNSENSE_API_KEY` or `OPNSENSE_API_KEY_FILE`
    /// - `OPNSENSE_API_SECRET` or `OPNSENSE_API_SECRET_FILE`
    ///
    /// Optional (with defaults):
    /// - `DEFAULT_RECONCILE_INTERVAL` (default `"5m"`)
    /// - `DEFAULT_DNS_TTL` (default `"300s"`)
    /// - `WAN_INTERFACE` (default `"wan"`)
    /// - `DRY_RUN` (default `"false"`)
    /// - `DNS_ZONE` (default `"example.com"`)
    /// - `DNS_MANAGED_ZONE` (default: `.{DNS_ZONE}`)
    /// - `UNBOUND_ANCHOR` (default: `ha.{DNS_ZONE}`)
    /// - `CLOUDFLARE_CNAME_TARGET` (default: `origin.{DNS_ZONE}`)
    /// - `ORG_NAME` (default `"hr-home"`) — name of the default organization
    pub fn from_env() -> Result<Self, Error> {
        let cloudflare_api_token = require_env("CLOUDFLARE_API_TOKEN")?;
        let cloudflare_zone_id = require_env("CLOUDFLARE_ZONE_ID")?;
        let orgs = Orgs::from_env(cloudflare_zone_id);
        let default_org = orgs.default_org().name.clone();
        let opnsense_url = require_env("OPNSENSE_URL")?;
        let opnsense_api_key = read_secret("OPNSENSE_API_KEY")?;
        let opnsense_api_secret = read_secret("OPNSENSE_API_SECRET")?;

        let default_reconcile_interval =
            optional_duration("DEFAULT_RECONCILE_INTERVAL", Duration::from_secs(300))?;

        let default_dns_ttl = optional_duration("DEFAULT_DNS_TTL", Duration::from_secs(300))?;

        let wan_interface = std::env::var("WAN_INTERFACE").unwrap_or_else(|_| "wan".to_owned());

        let dry_run = std::env::var("DRY_RUN")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        // Zitadel OIDC (all optional — feature disabled if any are missing)
        let zitadel_url = std::env::var("ZITADEL_URL").ok();
        let zitadel_key_id = std::env::var("ZITADEL_KEY_ID").ok();
        let zitadel_user_id = std::env::var("ZITADEL_USER_ID").ok();
        let zitadel_private_key = read_secret("ZITADEL_PRIVATE_KEY").ok();

        Ok(Self {
            cloudflare_api_token,
            opnsense_url,
            opnsense_api_key,
            opnsense_api_secret,
            default_reconcile_interval,
            default_dns_ttl,
            wan_interface,
            dry_run,
            orgs,
            default_org,
            zitadel_url,
            zitadel_key_id,
            zitadel_user_id,
            zitadel_private_key,
        })
    }
}

/// Read a required env var, returning a config error if absent.
fn require_env(name: &str) -> Result<String, Error> {
    std::env::var(name)
        .map_err(|_| Error::Config(format!("required environment variable {name} is not set")))
}

/// Read a secret value, trying `{name}_FILE` first (reading and trimming the
/// file contents), then falling back to the direct `{name}` env var.
fn read_secret(name: &str) -> Result<String, Error> {
    let file_var = format!("{name}_FILE");

    if let Ok(path) = std::env::var(&file_var) {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("failed to read {file_var} ({path}): {e}")))?;
        let trimmed = contents.trim().to_owned();
        if trimmed.is_empty() {
            return Err(Error::Config(format!(
                "{file_var} ({path}) is empty after trimming"
            )));
        }
        return Ok(trimmed);
    }

    require_env(name)
}

/// Read an optional duration env var, falling back to a default.
fn optional_duration(name: &str, default: Duration) -> Result<Duration, Error> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(val) => parse_duration(&val)
            .ok_or_else(|| Error::Config(format!("invalid duration for {name}: {val:?}"))),
    }
}

/// Unit tests for configuration loading.
#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _lock = ENV_LOCK.lock().unwrap();
        for (k, v) in vars {
            // SAFETY: serialised by ENV_LOCK.
            unsafe { std::env::set_var(k, v) };
        }
        f();
        for (k, _) in vars {
            // SAFETY: serialised by ENV_LOCK.
            unsafe { std::env::remove_var(k) };
        }
    }

    /// Minimum set of env vars required for `Config::from_env` to succeed.
    fn base_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CLOUDFLARE_API_TOKEN", "cf-token"),
            ("CLOUDFLARE_ZONE_ID", "zone-123"),
            ("OPNSENSE_URL", "https://opnsense.local"),
            ("OPNSENSE_API_KEY", "key"),
            ("OPNSENSE_API_SECRET", "secret"),
        ]
    }

    #[test]
    fn from_env_with_all_required_vars() {
        with_env(&base_env(), || {
            let config = Config::from_env().expect("should succeed");
            assert_eq!(config.cloudflare_api_token, "cf-token");
            assert_eq!(
                config.orgs.default_org().cloudflare_zone_id.as_deref(),
                Some("zone-123")
            );
            assert_eq!(config.default_org, "hr-home");
            assert_eq!(config.opnsense_url, "https://opnsense.local");
            assert_eq!(config.opnsense_api_key, "key");
            assert_eq!(config.opnsense_api_secret, "secret");
            assert_eq!(config.default_reconcile_interval, Duration::from_secs(300));
            assert_eq!(config.default_dns_ttl, Duration::from_secs(300));
            assert_eq!(config.wan_interface, "wan");
            assert!(!config.dry_run);
        });
    }

    #[test]
    fn from_env_reads_file_secrets() {
        let dir = std::env::temp_dir().join("fleet-dns-test-secrets");
        let _ = std::fs::create_dir_all(&dir);

        let key_path = dir.join("api_key");
        let secret_path = dir.join("api_secret");
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(b"  file-key\n")
            .unwrap();
        std::fs::File::create(&secret_path)
            .unwrap()
            .write_all(b"file-secret  \n")
            .unwrap();

        let mut vars = base_env();
        // Replace direct key/secret with _FILE variants.
        vars.retain(|&(k, _)| k != "OPNSENSE_API_KEY" && k != "OPNSENSE_API_SECRET");
        vars.push(("OPNSENSE_API_KEY_FILE", key_path.to_str().unwrap()));
        vars.push(("OPNSENSE_API_SECRET_FILE", secret_path.to_str().unwrap()));

        with_env(&vars, || {
            let config = Config::from_env().expect("should succeed");
            assert_eq!(config.opnsense_api_key, "file-key");
            assert_eq!(config.opnsense_api_secret, "file-secret");
        });

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_env_missing_required_var_fails() {
        let _lock = ENV_LOCK.lock().unwrap();
        // SAFETY: serialised by ENV_LOCK.
        unsafe {
            std::env::remove_var("CLOUDFLARE_API_TOKEN");
            std::env::remove_var("CLOUDFLARE_ZONE_ID");
            std::env::remove_var("OPNSENSE_URL");
            std::env::remove_var("OPNSENSE_API_KEY");
            std::env::remove_var("OPNSENSE_API_KEY_FILE");
            std::env::remove_var("OPNSENSE_API_SECRET");
            std::env::remove_var("OPNSENSE_API_SECRET_FILE");
        }

        let err = Config::from_env().unwrap_err();
        assert!(err.to_string().contains("CLOUDFLARE_API_TOKEN"));
    }

    #[test]
    fn org_zone_prefers_metadata_over_primary_domain() {
        // A new Zitadel org's primary domain is an identity hostname, so the
        // dnsZone metadata value is what makes it a usable DNS zone.
        assert_eq!(
            org_zone(
                Some("quota.fitness"),
                Some("quota-fitness.zitadel.hr-home.xyz")
            )
            .as_deref(),
            Some("quota.fitness")
        );
    }

    #[test]
    fn org_zone_falls_back_to_primary_domain() {
        assert_eq!(
            org_zone(None, Some("fida.finance")).as_deref(),
            Some("fida.finance")
        );
    }

    #[test]
    fn org_zone_rejects_missing_and_blank_values() {
        assert_eq!(org_zone(None, None), None);
        assert_eq!(org_zone(Some("   "), None), None);
        // A blank metadata value falls through to nothing rather than
        // producing an organization with an empty zone, which would match
        // every hostname.
        assert_eq!(org_zone(Some(""), Some("")), None);
    }

    #[test]
    fn default_organization_is_unaffected_by_discovery() {
        let mut orgs = Orgs::single(Org::new("hr-home", "hr-home.xyz"));
        // Discovery tries to redefine the default with a different zone.
        orgs.extend([Org::new("hr-home", "bogus.example")]);
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs.default_org().zone, "hr-home.xyz");
    }

    #[test]
    fn iter_yields_the_default_organization_first() {
        let mut orgs = Orgs::single(Org::new("hr-home", "hr-home.xyz"));
        orgs.extend([
            Org::new("aaa-first-alphabetically", "aaa.example"),
            Org::new("quota-fitness", "quota.fitness"),
        ]);
        let names: Vec<&str> = orgs.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(names[0], "hr-home");
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn optional_duration_parsing() {
        const KEY: &str = "TEST_DUR";
        let fallback = Duration::from_secs(60);

        // Not set -> falls back to the provided default.
        // SAFETY: test-only; serialised via --test-threads=1.
        unsafe { std::env::remove_var(KEY) };
        assert_eq!(optional_duration(KEY, fallback).unwrap(), fallback);

        // A valid human-readable duration parses correctly.
        unsafe { std::env::set_var(KEY, "10m") };
        let ten_min = optional_duration(KEY, fallback).unwrap();
        assert_eq!(ten_min, Duration::from_secs(600));
        unsafe { std::env::remove_var(KEY) };

        // A bogus string produces an error.
        unsafe { std::env::set_var(KEY, "bogus") };
        assert!(optional_duration(KEY, fallback).is_err());
        unsafe { std::env::remove_var(KEY) };
    }

    /// Parse `Config::from_env` with base env + an extra DRY_RUN value and assert dry_run is set.
    fn assert_dry_run_enabled(dry_run_value: &str) {
        let mut vars = base_env();
        vars.push(("DRY_RUN", dry_run_value));
        with_env(&vars, || {
            let config = Config::from_env().unwrap();
            assert!(
                config.dry_run,
                "DRY_RUN={dry_run_value} should enable dry_run"
            );
        });
    }

    #[test]
    fn dry_run_parsing_true_string() {
        assert_dry_run_enabled("true");
    }

    #[test]
    fn dry_run_parsing_numeric_one() {
        assert_dry_run_enabled("1");
    }
}
