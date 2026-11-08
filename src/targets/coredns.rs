use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Arc;

use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{ObjectMeta, Patch, PatchParams};
use kube::{Api, Client};
use tracing::{debug, info};

use crate::crd::CoreDnsPolicy;
use crate::error::Error;
use crate::state::DnsEntry;
use crate::{Org, Orgs};

/// ConfigMap key holding an organization's zone server block.
///
/// `hr-home.xyz` yields `hr-home-xyz.server`, the key this ConfigMap has
/// always used, so a single-organization deployment keeps its exact key.
#[must_use]
pub fn server_key(zone: &str) -> String {
    format!("{}.server", zone.replace('.', "-"))
}

/// ConfigMap name in kube-system that CoreDNS reads custom overrides from.
const CONFIGMAP_NAME: &str = "coredns-custom";

/// Namespace where CoreDNS runs.
const CONFIGMAP_NAMESPACE: &str = "kube-system";

/// Resolve the zone a policy applies to: explicit `spec.zone` wins, else the
/// zone of `spec.org`, else `None` for a non-zone policy.
fn policy_zone(policy: &CoreDnsPolicy, orgs: &Orgs) -> Option<String> {
    if let Some(zone) = policy.spec.zone.as_deref() {
        return Some(zone.to_owned());
    }
    let org_name = policy.spec.org.as_deref()?;
    match orgs.by_name(org_name) {
        Some(org) => Some(org.zone.clone()),
        None => {
            debug!(
                policy = policy.spec.key.as_str(),
                org = org_name,
                "CoreDnsPolicy names an unknown organization; treating as non-zone policy"
            );
            None
        }
    }
}

/// Render the ConfigMap `data` keys from DNS entries and CoreDNS policies.
///
/// Policies scoped to no zone (neither `spec.zone` nor `spec.org`) each become
/// their own ConfigMap key. Everything else is grouped by organization: each
/// organization holding at least one entry or zone-scoped policy gets a
/// `{zone-with-dashes}.server` key containing a CoreDNS server block.
#[must_use]
pub fn render_configmap_data(
    entries: &[DnsEntry],
    policies: &[Arc<CoreDnsPolicy>],
    orgs: &Orgs,
) -> BTreeMap<String, String> {
    let mut data = BTreeMap::new();

    // --- Non-zone policies: each gets its own key ---
    for policy in policies {
        if policy_zone(policy, orgs).is_none() {
            data.insert(policy.spec.key.clone(), policy.spec.content.clone());
        }
    }

    // --- One server block per organization ---
    for org in orgs.iter() {
        let org_entries: Vec<DnsEntry> = entries
            .iter()
            .filter(|e| e.org == org.name)
            .cloned()
            .collect();

        // The default organization always renders a server block, even when
        // empty, so its key never disappears from the ConfigMap. Additional
        // organizations appear only once they have something to say.
        let has_policies = policies
            .iter()
            .any(|p| policy_zone(p, orgs).as_deref() == Some(org.zone.as_str()));
        if org.name != orgs.default_org().name && org_entries.is_empty() && !has_policies {
            continue;
        }

        let server_block = render_server_block(org, &org_entries, policies, orgs);
        data.insert(server_key(&org.zone), server_block);
    }

    data
}

/// Build the `hr-home.xyz:53 { ... }` server block for one organization.
fn render_server_block(
    org: &Org,
    entries: &[DnsEntry],
    policies: &[Arc<CoreDnsPolicy>],
    orgs: &Orgs,
) -> String {
    let zone = org.zone.as_str();

    // Group hostnames by lan_ip, sorted for determinism.
    let hosts_block = render_hosts_block(entries);

    // Collect zone-scoped policy content fragments.
    let mut zone_policies: Vec<&str> = policies
        .iter()
        .filter(|p| policy_zone(p, orgs).as_deref() == Some(zone))
        .map(|p| p.spec.content.as_str())
        .collect();
    zone_policies.sort();

    let mut out = String::new();
    let _ = writeln!(out, "{zone}:53 {{");
    let _ = writeln!(out, "  errors");
    let _ = writeln!(out, "  hosts {{");

    for line in hosts_block.lines() {
        let _ = writeln!(out, "    {line}");
    }
    let _ = writeln!(out, "    fallthrough");
    let _ = writeln!(out, "  }}");

    for fragment in &zone_policies {
        for line in fragment.lines() {
            let _ = writeln!(out, "  {line}");
        }
    }

    let _ = writeln!(out, "  forward . /etc/resolv.conf");
    let _ = writeln!(out, "  cache 30");
    let _ = write!(out, "}}");

    out
}

/// Render the inner lines of the `hosts { ... }` block.
///
/// Groups hostnames by `lan_ip` so that entries sharing an IP appear on a
/// single line. Both IPs and hostnames within each group are sorted for
/// deterministic output.
fn render_hosts_block(entries: &[DnsEntry]) -> String {
    // BTreeMap gives us sorted IPs automatically.
    let mut by_ip: BTreeMap<String, Vec<&str>> = BTreeMap::new();

    for entry in entries {
        by_ip
            .entry(entry.lan_ip.to_string())
            .or_default()
            .push(&entry.hostname);
    }

    // Sort hostnames within each IP group.
    for hostnames in by_ip.values_mut() {
        hostnames.sort();
    }

    let mut out = String::new();
    for (ip, hostnames) in &by_ip {
        let _ = write!(out, "{ip}");
        for hostname in hostnames {
            let _ = write!(out, " {hostname}");
        }
        let _ = writeln!(out);
    }
    out
}

/// Apply the rendered ConfigMap to the cluster via server-side apply.
///
/// When `dry_run` is true, the rendered data is logged but not sent to the
/// API server.
pub async fn apply_configmap(
    client: Client,
    data: BTreeMap<String, String>,
    dry_run: bool,
) -> Result<(), Error> {
    if dry_run {
        info!("dry-run: would apply coredns-custom ConfigMap");
        for (key, value) in &data {
            debug!(key, value, "dry-run: ConfigMap data entry");
        }
        return Ok(());
    }

    let cm = ConfigMap {
        metadata: ObjectMeta {
            name: Some(CONFIGMAP_NAME.to_owned()),
            namespace: Some(CONFIGMAP_NAMESPACE.to_owned()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    let api: Api<ConfigMap> = Api::namespaced(client, CONFIGMAP_NAMESPACE);
    let params = PatchParams::apply("fleet-dns").force();
    api.patch(CONFIGMAP_NAME, &params, &Patch::Apply(&cm))
        .await?;

    info!("applied coredns-custom ConfigMap");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CoreDnsPolicySpec;
    use crate::state::{CloudflareMode, WanExpose};
    use kube::api::ObjectMeta;
    use std::net::IpAddr;
    use std::time::Duration;

    fn entry(hostname: &str, lan_ip: &str) -> DnsEntry {
        DnsEntry {
            hostname: hostname.to_owned(),
            lan_ip: lan_ip.parse::<IpAddr>().unwrap(),
            macvlan_ip: None,
            cloudflare_mode: CloudflareMode::Proxied,
            wan_expose: WanExpose::Skip,
            dns_ttl: Duration::from_secs(300),
            reconcile_interval: Duration::from_secs(60),
            managed: true,
            source: "test/test".to_owned(),
            unbound_alias_target: None,
            org: "hr-home".to_owned(),
        }
    }

    fn policy(key: &str, content: &str, zone: Option<&str>) -> Arc<CoreDnsPolicy> {
        let meta = ObjectMeta {
            name: Some(key.to_owned()),
            namespace: Some("kube-system".to_owned()),
            ..Default::default()
        };
        Arc::new(CoreDnsPolicy {
            metadata: meta,
            spec: CoreDnsPolicySpec {
                policy_type: "template".to_owned(),
                zone: zone.map(str::to_owned),
                org: None,
                key: key.to_owned(),
                content: content.to_owned(),
            },
        })
    }

    /// Single-organization registry mirroring the historical defaults.
    fn test_orgs() -> Orgs {
        Orgs::single(Org::test())
    }

    /// The ConfigMap key the single-organization deployment has always used.
    const SERVER_KEY: &str = "hr-home-xyz.server";

    fn render_server(entries: &[DnsEntry], policies: &[Arc<CoreDnsPolicy>]) -> String {
        let data = render_configmap_data(entries, policies, &test_orgs());
        data.get(SERVER_KEY).unwrap().clone()
    }

    #[test]
    fn basic_render_with_entries_and_policies() {
        let entries = vec![
            entry("zitadel.hr-home.xyz", "10.43.0.100"),
            entry("oidc.hr-home.xyz", "10.43.0.100"),
            entry("plex.hr-home.xyz", "192.168.2.51"),
        ];

        let aaaa_content = "template IN AAAA {\n  rcode NXDOMAIN\n}";
        let search_content = "template IN A search.hr-home.xyz {\n  answer \"search.hr-home.xyz 60 IN CNAME searxng.hr-home.xyz\"\n}";
        let policies = vec![
            policy("no-aaaa.override", aaaa_content, None),
            policy("search-fix.override", search_content, Some("hr-home.xyz")),
        ];

        let data = render_configmap_data(&entries, &policies, &test_orgs());

        // Non-zone policy gets its own key.
        assert_eq!(data.get("no-aaaa.override").unwrap(), aaaa_content);

        // Server block exists.
        let server = data.get(SERVER_KEY).unwrap();
        assert!(server.starts_with("hr-home.xyz:53 {"));
        assert!(server.contains("errors"));

        // Hosts grouped by IP: two hostnames on 10.43.0.100, one on 192.168.2.51.
        assert!(server.contains("10.43.0.100 oidc.hr-home.xyz zitadel.hr-home.xyz"));
        assert!(server.contains("192.168.2.51 plex.hr-home.xyz"));
        assert!(server.contains("fallthrough"));

        // Zone-scoped policy embedded between hosts and forward.
        let hosts_end = server.find("fallthrough").unwrap();
        let forward_pos = server.find("forward . /etc/resolv.conf").unwrap();
        let search_pos = server.find("template IN A search.hr-home.xyz").unwrap();
        assert!(
            search_pos > hosts_end,
            "zone policy must come after hosts block"
        );
        assert!(
            search_pos < forward_pos,
            "zone policy must come before forward"
        );

        // Forward and cache present.
        assert!(server.contains("forward . /etc/resolv.conf"));
        assert!(server.contains("cache 30"));
    }

    #[test]
    fn grouping_multiple_hostnames_same_ip() {
        let entries = vec![
            entry("charlie.hr-home.xyz", "10.43.0.100"),
            entry("alpha.hr-home.xyz", "10.43.0.100"),
            entry("bravo.hr-home.xyz", "10.43.0.100"),
        ];

        let server = render_server(&entries, &[]);

        // All three on one line, sorted alphabetically.
        assert!(
            server.contains("10.43.0.100 alpha.hr-home.xyz bravo.hr-home.xyz charlie.hr-home.xyz")
        );
    }

    #[test]
    fn zone_scoped_policy_positioned_correctly() {
        let entries = vec![entry("app.hr-home.xyz", "10.43.0.100")];
        let template = "template IN CNAME search.hr-home.xyz {\n  answer \"...\"\n}";
        let policies = vec![policy("search.override", template, Some("hr-home.xyz"))];

        let server = render_server(&entries, &policies);

        let hosts_close = server.find("  }").unwrap();
        let template_pos = server.find("template IN CNAME").unwrap();
        let forward_pos = server.find("forward").unwrap();

        assert!(template_pos > hosts_close);
        assert!(template_pos < forward_pos);
    }

    #[test]
    fn empty_entries_produces_hosts_with_only_fallthrough() {
        let template = "template IN AAAA {\n  rcode NXDOMAIN\n}";
        let policies = vec![policy("no-aaaa.override", template, None)];

        let server = render_server(&[], &policies);

        // Hosts block should contain only fallthrough (no IP lines).
        assert!(server.contains("hosts {"));
        assert!(server.contains("fallthrough"));

        // No IP lines between "hosts {" and "fallthrough".
        let hosts_start = server.find("hosts {").unwrap();
        let fallthrough = server.find("fallthrough").unwrap();
        let between = &server[hosts_start + "hosts {".len()..fallthrough];
        assert!(
            between.trim().is_empty(),
            "expected no IP lines between hosts and fallthrough, got: {between:?}"
        );
    }

    #[test]
    fn output_is_deterministic_and_sorted() {
        let entries = vec![
            entry("zebra.hr-home.xyz", "192.168.2.99"),
            entry("alpha.hr-home.xyz", "10.43.0.100"),
            entry("beta.hr-home.xyz", "10.43.0.100"),
            entry("middle.hr-home.xyz", "172.16.0.5"),
        ];

        let data_a = render_configmap_data(&entries, &[], &test_orgs());
        let data_b = render_configmap_data(&entries, &[], &test_orgs());

        assert_eq!(data_a, data_b, "output must be deterministic");

        let server = data_a.get(SERVER_KEY).unwrap();

        // IPs must appear in sorted order: 10.43.0.100, 172.16.0.5, 192.168.2.99.
        let pos_10 = server.find("10.43.0.100").unwrap();
        let pos_172 = server.find("172.16.0.5").unwrap();
        let pos_192 = server.find("192.168.2.99").unwrap();
        assert!(pos_10 < pos_172);
        assert!(pos_172 < pos_192);

        // Within the 10.43.0.100 group, alpha before beta.
        let pos_alpha = server.find("alpha.hr-home.xyz").unwrap();
        let pos_beta = server.find("beta.hr-home.xyz").unwrap();
        assert!(pos_alpha < pos_beta);
    }
    // -----------------------------------------------------------------------
    // Golden snapshot — the exact ConfigMap that lands in kube-system.
    //
    // No org is set anywhere in this fixture. Org support must leave this
    // output byte-identical, including the `hr-home-xyz.server` key name.
    // -----------------------------------------------------------------------
    #[test]
    fn golden_configmap_without_orgs() {
        let entries = vec![
            entry("ha.hr-home.xyz", "10.43.0.100"),
            entry("plex.hr-home.xyz", "10.43.0.100"),
            entry("plex-direct.hr-home.xyz", "192.168.2.40"),
            entry("kitchen-sensor.hr-home.xyz", "192.168.2.100"),
        ];
        let policies = vec![
            policy(
                "no-aaaa.override",
                "template IN AAAA {\n  rcode NXDOMAIN\n}",
                None,
            ),
            policy(
                "search-fix.override",
                "template IN A search.hr-home.xyz {\n  answer \"search 60 IN CNAME searxng\"\n}",
                Some("hr-home.xyz"),
            ),
        ];

        let data = render_configmap_data(&entries, &policies, &test_orgs());

        let keys: Vec<&str> = data.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["hr-home-xyz.server", "no-aaaa.override"]);

        assert_eq!(
            data.get("hr-home-xyz.server").unwrap(),
            "\
hr-home.xyz:53 {
  errors
  hosts {
    10.43.0.100 ha.hr-home.xyz plex.hr-home.xyz
    192.168.2.100 kitchen-sensor.hr-home.xyz
    192.168.2.40 plex-direct.hr-home.xyz
    fallthrough
  }
  template IN A search.hr-home.xyz {
    answer \"search 60 IN CNAME searxng\"
  }
  forward . /etc/resolv.conf
  cache 30
}"
        );
    }
    // -----------------------------------------------------------------------
    // Multi-organization rendering
    // -----------------------------------------------------------------------

    /// hr-home (default) plus quota-fitness.
    fn two_orgs() -> Orgs {
        let mut orgs = Orgs::single(Org::test());
        orgs.extend([Org::new("quota-fitness", "quota.fitness")]);
        orgs
    }

    /// Render the two-organization ConfigMap from a single CoreDnsPolicy that
    /// carries `spec.org`, and optionally an explicit `spec.zone` that should
    /// take precedence over it.
    fn render_with_org_policy(
        key: &str,
        content: &str,
        zone: Option<&str>,
        org: &str,
    ) -> BTreeMap<String, String> {
        let mut p = policy(key, content, zone);
        Arc::get_mut(&mut p)
            .expect("freshly built Arc is unique")
            .spec
            .org = Some(org.to_owned());
        render_configmap_data(&[], &[p], &two_orgs())
    }

    /// A DNS entry owned by a named organization.
    fn org_entry(hostname: &str, ip: &str, org: &str) -> DnsEntry {
        let mut e = entry(hostname, ip);
        e.org = org.to_owned();
        e
    }

    #[test]
    fn server_key_matches_the_historical_name() {
        assert_eq!(server_key("hr-home.xyz"), "hr-home-xyz.server");
        assert_eq!(server_key("quota.fitness"), "quota-fitness.server");
    }

    #[test]
    fn registering_a_second_organization_leaves_the_first_untouched() {
        let entries = vec![org_entry("plex.hr-home.xyz", "10.43.0.100", "hr-home")];

        // Same entries, rendered against a one-org and a two-org registry.
        let one = render_configmap_data(&entries, &[], &test_orgs());
        let two = render_configmap_data(&entries, &[], &two_orgs());

        // An organization with nothing in it contributes no key at all, so the
        // ConfigMap is identical.
        assert_eq!(one, two);
        assert_eq!(
            two.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["hr-home-xyz.server"]
        );
    }

    #[test]
    fn each_organization_renders_its_own_server_block() {
        let entries = vec![
            org_entry("plex.hr-home.xyz", "10.43.0.100", "hr-home"),
            org_entry("lists.quota.fitness", "10.43.0.100", "quota-fitness"),
        ];

        let data = render_configmap_data(&entries, &[], &two_orgs());

        assert_eq!(
            data.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["hr-home-xyz.server", "quota-fitness.server"]
        );

        // Each block carries only its own organization's hostnames.
        let hr = &data["hr-home-xyz.server"];
        assert!(hr.starts_with("hr-home.xyz:53 {"));
        assert!(hr.contains("plex.hr-home.xyz"));
        assert!(!hr.contains("lists.quota.fitness"));

        let quota = &data["quota-fitness.server"];
        assert!(quota.starts_with("quota.fitness:53 {"));
        assert!(quota.contains("lists.quota.fitness"));
        assert!(!quota.contains("plex.hr-home.xyz"));
    }

    #[test]
    fn policy_org_selects_the_zone_block() {
        let data = render_with_org_policy(
            "quota-fix.override",
            "template IN A x {\n  answer \"y\"\n}",
            None,
            "quota-fitness",
        );

        // The policy pulled the quota block into existence and landed inside
        // it, rather than becoming a standalone key.
        assert!(data.contains_key("quota-fitness.server"));
        assert!(data["quota-fitness.server"].contains("template IN A x"));
        assert!(!data.contains_key("quota-fix.override"));
    }

    #[test]
    fn explicit_zone_wins_over_org_on_a_policy() {
        let data = render_with_org_policy(
            "pinned.override",
            "template IN A z {\n  answer \"w\"\n}",
            Some("hr-home.xyz"),
            "quota-fitness",
        );

        assert!(data["hr-home-xyz.server"].contains("template IN A z"));
        assert!(!data.contains_key("quota-fitness.server"));
    }

    #[test]
    fn policy_naming_an_unknown_organization_becomes_a_standalone_key() {
        let content = "template IN AAAA {\n  rcode NXDOMAIN\n}";
        let data = render_with_org_policy("orphan.override", content, None, "gone");

        assert_eq!(
            data.get("orphan.override").map(String::as_str),
            Some(content)
        );
    }
}
