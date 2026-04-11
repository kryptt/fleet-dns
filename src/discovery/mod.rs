pub mod dhcp;
pub mod ingress;
pub mod oidc;
pub mod pods;
pub mod policies;
pub mod services;

use std::net::IpAddr;

use serde::Deserialize;
use tracing::warn;

/// A single entry from the Multus `k8s.v1.cni.cncf.io/network-status` JSON annotation.
#[derive(Debug, Clone, Deserialize)]
pub struct MultusNetwork {
    pub name: String,
    #[serde(default)]
    pub ips: Vec<String>,
}

/// Parse the Multus network-status annotation and extract the IP for a named network.
///
/// The annotation is a JSON array of objects like:
/// ```json
/// [{"name":"default/lan-macvlan","ips":["192.168.2.51/24"]}]
/// ```
///
/// Returns `None` (with a log warning) on any parse error, missing network, or
/// missing/unparseable IP. Never panics.
#[must_use]
pub fn parse_multus_ip(annotation: &str, network_name: &str) -> Option<IpAddr> {
    let networks: Vec<MultusNetwork> = match serde_json::from_str(annotation) {
        Ok(v) => v,
        Err(e) => {
            warn!(%e, "failed to parse Multus network-status annotation");
            return None;
        }
    };

    let entry = networks.iter().find(|n| {
        // Multus prefixes the network name with the namespace, e.g. "default/lan-macvlan".
        // Match on either the full name or the suffix after '/'.
        n.name == network_name
            || n.name
                .rsplit_once('/')
                .is_some_and(|(_, suffix)| suffix == network_name)
    })?;

    let ip_str = entry.ips.first()?;

    // Strip optional CIDR prefix length (e.g. "/24").
    let bare = ip_str.split('/').next().unwrap_or(ip_str);

    match bare.parse::<IpAddr>() {
        Ok(addr) => Some(addr),
        Err(e) => {
            warn!(%e, ip = %ip_str, "failed to parse Multus IP address");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn valid_annotation_with_cidr() {
        let annotation = r#"[{"name":"lan-macvlan","ips":["192.168.2.51/24"]}]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 51))));
    }

    #[test]
    fn multiple_networks_picks_correct_one() {
        let annotation = r#"[
            {"name":"default/cbr0","ips":["10.244.1.5/24"]},
            {"name":"default/lan-macvlan","ips":["192.168.2.51/24"]}
        ]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 51))));
    }

    #[test]
    fn malformed_json_returns_none() {
        let ip = parse_multus_ip("not json at all", "lan-macvlan");
        assert_eq!(ip, None);
    }

    #[test]
    fn missing_ips_field_returns_none() {
        let annotation = r#"[{"name":"lan-macvlan"}]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, None);
    }

    #[test]
    fn network_not_found_returns_none() {
        let annotation = r#"[{"name":"other-net","ips":["10.0.0.1/16"]}]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, None);
    }

    #[test]
    fn ip_without_cidr_prefix() {
        let annotation = r#"[{"name":"lan-macvlan","ips":["192.168.2.51"]}]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 51))));
    }

    #[test]
    fn namespaced_network_name_matches() {
        let annotation = r#"[{"name":"kube-system/lan-macvlan","ips":["192.168.2.99/24"]}]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 99))));
    }

    #[test]
    fn empty_ips_array_returns_none() {
        let annotation = r#"[{"name":"lan-macvlan","ips":[]}]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, None);
    }

    #[test]
    fn unparseable_ip_returns_none() {
        let annotation = r#"[{"name":"lan-macvlan","ips":["not-an-ip"]}]"#;
        let ip = parse_multus_ip(annotation, "lan-macvlan");
        assert_eq!(ip, None);
    }
}
