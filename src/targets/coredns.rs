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

/// DNS zone managed by fleet-dns.
const ZONE: &str = "hr-home.xyz";

/// ConfigMap key for the zone server block.
const SERVER_KEY: &str = "hr-home-xyz.server";

/// ConfigMap name in kube-system that CoreDNS reads custom overrides from.
const CONFIGMAP_NAME: &str = "coredns-custom";

/// Namespace where CoreDNS runs.
const CONFIGMAP_NAMESPACE: &str = "kube-system";

/// Render the ConfigMap `data` keys from DNS entries and CoreDNS policies.
///
/// Non-zone policies (where `spec.zone` is `None`) each become their own
/// ConfigMap key. Zone-scoped entries and policies are merged into a single
/// `hr-home-xyz.server` key containing a CoreDNS server block.
pub fn render_configmap_data(
    entries: &[DnsEntry],
    policies: &[Arc<CoreDnsPolicy>],
) -> BTreeMap<String, String> {
    let mut data = BTreeMap::new();

    // --- Non-zone policies: each gets its own key ---
    for policy in policies {
        if policy.spec.zone.is_none() {
            data.insert(policy.spec.key.clone(), policy.spec.content.clone());
        }
    }

    // --- Zone server block ---
    let server_block = render_server_block(entries, policies);
    data.insert(SERVER_KEY.to_owned(), server_block);

    data
}

/// Build the `hr-home.xyz:53 { ... }` server block.
fn render_server_block(entries: &[DnsEntry], policies: &[Arc<CoreDnsPolicy>]) -> String {
    // Group hostnames by lan_ip, sorted for determinism.
    let hosts_block = render_hosts_block(entries);

    // Collect zone-scoped policy content fragments.
    let mut zone_policies: Vec<&str> = policies
        .iter()
        .filter(|p| p.spec.zone.as_deref() == Some(ZONE))
        .map(|p| p.spec.content.as_str())
        .collect();
    zone_policies.sort();

    let mut out = String::new();
    let _ = writeln!(out, "{ZONE}:53 {{");
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
    let params = PatchParams::apply("fleet-dns");
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
            reconcile_interval: Duration::from_secs(300),
            managed: true,
            source: "test/test".to_owned(),
        }
    }

    fn policy(key: &str, content: &str, zone: Option<&str>) -> Arc<CoreDnsPolicy> {
        Arc::new(CoreDnsPolicy {
            metadata: ObjectMeta {
                name: Some(key.to_owned()),
                namespace: Some("kube-system".to_owned()),
                ..Default::default()
            },
            spec: CoreDnsPolicySpec {
                policy_type: "template".to_owned(),
                zone: zone.map(str::to_owned),
                key: key.to_owned(),
                content: content.to_owned(),
            },
        })
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
            policy(
                "search-fix.override",
                search_content,
                Some("hr-home.xyz"),
            ),
        ];

        let data = render_configmap_data(&entries, &policies);

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
        assert!(search_pos > hosts_end, "zone policy must come after hosts block");
        assert!(search_pos < forward_pos, "zone policy must come before forward");

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

        let data = render_configmap_data(&entries, &[]);
        let server = data.get(SERVER_KEY).unwrap();

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

        let data = render_configmap_data(&entries, &policies);
        let server = data.get(SERVER_KEY).unwrap();

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

        let data = render_configmap_data(&[], &policies);
        let server = data.get(SERVER_KEY).unwrap();

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

        let data_a = render_configmap_data(&entries, &[]);
        let data_b = render_configmap_data(&entries, &[]);

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
}
