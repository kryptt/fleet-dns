use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::{Pod, Service};
use tracing::{info, warn};

use crate::crd::DhcpReservation;
use crate::discovery::parse_multus_ip;
use crate::traefik::{IngressRoute, extract_hostnames};
use crate::{MANAGED_ZONE, UNBOUND_ANCHOR, ZONE};

/// The Multus network attachment name used for LAN macvlan interfaces.
const MACVLAN_NETWORK: &str = "lan-macvlan";

/// The annotation key for Multus network status.
const MULTUS_STATUS_ANNOTATION: &str = "k8s.v1.cni.cncf.io/network-status";

/// Label prefix for fleet-dns annotations on IngressRoutes.
const LABEL_PREFIX: &str = "hr-home.xyz/";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareMode {
    Proxied,
    DnsOnly,
    /// Create an A record pointing directly to the WAN IP instead of a CNAME.
    Address,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WanExpose {
    Expose { ports: Vec<PortForward> },
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForward {
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnsEntry {
    pub hostname: String,
    pub lan_ip: IpAddr,
    pub macvlan_ip: Option<IpAddr>,
    pub cloudflare_mode: CloudflareMode,
    pub wan_expose: WanExpose,
    pub dns_ttl: Duration,
    pub reconcile_interval: Duration,
    pub managed: bool,
    pub source: String,
    /// When set, this entry becomes an Unbound host alias pointing to the given
    /// anchor hostname (e.g., "ha.hr-home.xyz") instead of a direct A record.
    pub unbound_alias_target: Option<String>,
}

/// Per-target change sets produced by [`diff`].
#[derive(Debug, Default)]
pub struct DnsChanges {
    pub add: Vec<DnsEntry>,
    pub update: Vec<DnsEntry>,
    pub remove: Vec<String>,
}

pub type DnsState = HashMap<String, DnsEntry>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a label value from a `BTreeMap`, stripping the common prefix.
fn get_label<'a>(labels: &'a BTreeMap<String, String>, suffix: &str) -> Option<&'a str> {
    let key = format!("{LABEL_PREFIX}{suffix}");
    labels.get(&key).map(String::as_str)
}

/// Parse a human-friendly duration string.
///
/// Accepted formats: `"5m"`, `"1h"`, `"30s"`, or bare seconds `"300"`.
/// Returns `None` on invalid input.
#[must_use]
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (digits, suffix) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(pos) => (&s[..pos], &s[pos..]),
        None => (s, ""),
    };

    let value: u64 = digits.parse().ok()?;

    let multiplier = match suffix {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return None,
    };

    Some(Duration::from_secs(value * multiplier))
}

/// Parse a port-forward specification like `"32400/tcp,32469/udp"`.
#[must_use]
pub fn parse_wan_ports(s: &str) -> Vec<PortForward> {
    s.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            let (port_str, proto_str) = entry.split_once('/')?;
            let port: u16 = port_str.trim().parse().ok()?;
            let protocol = match proto_str.trim().to_lowercase().as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                other => {
                    warn!(protocol = other, "unknown protocol in wan-ports, skipping");
                    return None;
                }
            };
            Some(PortForward { port, protocol })
        })
        .collect()
}

/// Format `namespace/name` from K8s metadata, falling back to `"unknown"`.
fn source_key(meta: &kube::api::ObjectMeta) -> String {
    let ns = meta.namespace.as_deref().unwrap_or("unknown");
    let name = meta.name.as_deref().unwrap_or("unknown");
    format!("{ns}/{name}")
}

// ---------------------------------------------------------------------------
// Service / Pod lookup helpers
// ---------------------------------------------------------------------------

/// Find the K8s Service referenced by an IngressRoute's first route's first service entry.
fn find_backing_service<'a>(
    ir: &IngressRoute,
    service_store: &'a [Arc<Service>],
) -> Option<&'a Service> {
    let ir_ns = ir.metadata.namespace.as_deref().unwrap_or("default");

    ir.spec.routes.iter().find_map(|route| {
        route.services.as_ref()?.iter().find_map(|svc_ref| {
            let svc_ns = svc_ref.namespace.as_deref().unwrap_or(ir_ns);
            let svc_name = &svc_ref.name;
            service_store
                .iter()
                .find(|s| {
                    let meta = &s.metadata;
                    meta.namespace.as_deref().unwrap_or("default") == svc_ns
                        && meta.name.as_deref() == Some(svc_name.as_str())
                })
                .map(|s| s.as_ref())
        })
    })
}

/// Find Pods matching a Service's selector in the given namespace.
fn find_matching_pods<'a>(svc: &Service, pod_store: &'a [Arc<Pod>]) -> Vec<&'a Pod> {
    let svc_ns = svc.metadata.namespace.as_deref().unwrap_or("default");

    let selector = match svc.spec.as_ref().and_then(|s| s.selector.as_ref()) {
        Some(sel) => sel,
        None => return Vec::new(),
    };

    pod_store
        .iter()
        .filter(|pod| {
            let pod_ns = pod.metadata.namespace.as_deref().unwrap_or("default");
            if pod_ns != svc_ns {
                return false;
            }
            let pod_labels = match pod.metadata.labels.as_ref() {
                Some(l) => l,
                None => return false,
            };
            // All selector labels must be present and matching in the pod.
            selector.iter().all(|(k, v)| pod_labels.get(k) == Some(v))
        })
        .map(|p| p.as_ref())
        .collect()
}

/// Check if any of the given pods has a Multus macvlan IP.
fn find_macvlan_ip(pods: &[&Pod]) -> Option<IpAddr> {
    pods.iter().find_map(|pod| {
        let annotations = pod.metadata.annotations.as_ref()?;
        let status = annotations.get(MULTUS_STATUS_ANNOTATION)?;
        parse_multus_ip(status, MACVLAN_NETWORK)
    })
}

/// Infer port forwards from a K8s Service, excluding ports 80 and 443.
fn infer_ports_from_service(svc: &Service) -> Vec<PortForward> {
    let ports = match svc.spec.as_ref().and_then(|s| s.ports.as_ref()) {
        Some(p) => p,
        None => return Vec::new(),
    };

    ports
        .iter()
        .filter_map(|sp| {
            let port = sp.port.try_into().ok()?;
            if port == 80 || port == 443 {
                return None;
            }
            let protocol = match sp.protocol.as_deref() {
                Some("UDP") => Protocol::Udp,
                _ => Protocol::Tcp,
            };
            Some(PortForward { port, protocol })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// build_desired_state
// ---------------------------------------------------------------------------

/// Build the desired DNS state from live K8s stores.
///
/// Iterates all IngressRoutes, extracts `*.hr-home.xyz` hostnames, and
/// enriches each with macvlan IP, labels, and port information.
#[must_use]
pub fn build_desired_state(
    ingress_store: &[Arc<IngressRoute>],
    pod_store: &[Arc<Pod>],
    service_store: &[Arc<Service>],
    traefik_ip: IpAddr,
) -> DnsState {
    // Collect all (hostname, source_key, IngressRoute) tuples, then deduplicate.
    let mut candidates: HashMap<String, (String, &IngressRoute)> = HashMap::new();

    for ir in ingress_store {
        let source = source_key(&ir.metadata);

        for route in &ir.spec.routes {
            for hostname in extract_hostnames(&route.match_rule) {
                if !hostname.ends_with(MANAGED_ZONE) && hostname != ZONE {
                    continue;
                }

                match candidates.get(&hostname) {
                    Some((existing_source, _)) if existing_source <= &source => {
                        warn!(
                            hostname,
                            existing = %existing_source,
                            duplicate = %source,
                            "duplicate hostname across IngressRoutes, keeping lower source"
                        );
                    }
                    Some((existing_source, _)) => {
                        warn!(
                            hostname,
                            existing = %existing_source,
                            duplicate = %source,
                            "duplicate hostname across IngressRoutes, replacing with lower source"
                        );
                        candidates.insert(hostname, (source.clone(), ir.as_ref()));
                    }
                    None => {
                        candidates.insert(hostname, (source.clone(), ir.as_ref()));
                    }
                }
            }
        }
    }

    // Build DnsEntry for each candidate.
    let mut state = DnsState::with_capacity(candidates.len());

    for (hostname, (source, ir)) in candidates {
        let labels = ir.metadata.labels.as_ref().cloned().unwrap_or_default();
        let annotations = ir
            .metadata
            .annotations
            .as_ref()
            .cloned()
            .unwrap_or_default();

        let managed = get_label(&labels, "dns") == Some("true");

        let cloudflare_mode = match get_label(&labels, "cloudflare") {
            Some("dns-only") => CloudflareMode::DnsOnly,
            Some("address") => CloudflareMode::Address,
            Some("skip") => CloudflareMode::Skip,
            _ => CloudflareMode::Proxied,
        };

        let dns_ttl = get_label(&labels, "dns-ttl")
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(300));

        let reconcile_interval = get_label(&labels, "reconcile-interval")
            .and_then(parse_duration)
            .unwrap_or(Duration::from_secs(300));

        // Look up backing service and pods for macvlan + port inference.
        let backing_svc = find_backing_service(ir, service_store);
        let matching_pods: Vec<&Pod> = backing_svc
            .map(|svc| find_matching_pods(svc, pod_store))
            .unwrap_or_default();

        let macvlan_ip = find_macvlan_ip(&matching_pods);

        let wan_expose = match get_label(&labels, "wan-expose") {
            Some("true") => {
                // Explicit opt-in: expose WAN if there is a macvlan IP.
                match macvlan_ip {
                    Some(_) => {
                        let ports = match get_label(&annotations, "wan-ports")
                            .or_else(|| get_label(&labels, "wan-ports"))
                        {
                            Some(p) => parse_wan_ports(p),
                            None => backing_svc
                                .map(infer_ports_from_service)
                                .unwrap_or_default(),
                        };
                        if ports.is_empty() {
                            WanExpose::Skip
                        } else {
                            WanExpose::Expose { ports }
                        }
                    }
                    None => {
                        warn!(
                            hostname = %hostname,
                            "wan-expose=true but no macvlan IP; skipping"
                        );
                        WanExpose::Skip
                    }
                }
            }
            _ => WanExpose::Skip,
        };

        state.insert(
            hostname.clone(),
            DnsEntry {
                hostname,
                lan_ip: traefik_ip,
                macvlan_ip,
                cloudflare_mode,
                wan_expose,
                dns_ttl,
                reconcile_interval,
                managed,
                source,
                unbound_alias_target: None,
            },
        );
    }

    // Post-process: make all IngressRoute entries into Unbound aliases
    // pointing to the anchor, except the anchor itself. For entries with
    // macvlan IPs, emit additional `{name}-direct` A records.
    if state.is_empty() {
        return state;
    }

    let anchor = UNBOUND_ANCHOR.to_owned();

    // Ensure the anchor entry exists as an A record.
    if !state.contains_key(&anchor) {
        state.insert(
            anchor.clone(),
            DnsEntry {
                hostname: anchor.clone(),
                lan_ip: traefik_ip,
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Skip,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "synthetic/unbound-anchor".to_owned(),
                unbound_alias_target: None,
            },
        );
    }

    // Collect direct entries to add (can't mutate state while iterating).
    let mut direct_entries: Vec<DnsEntry> = Vec::new();

    for entry in state.values_mut() {
        if entry.hostname == anchor {
            // The anchor stays as an A record pointing to traefik_ip.
            // Drop the macvlan_ip — the anchor's purpose is to hold
            // traefik_ip; no -direct needed since both resolve the same way.
            entry.macvlan_ip = None;
            continue;
        }

        // All other IngressRoute entries become aliases.
        entry.unbound_alias_target = Some(anchor.clone());

        // Only emit -direct when the macvlan IP differs from lan_ip
        // (traefik_ip). If they're the same there's no conflict.
        if let Some(mvip) = entry.macvlan_ip.filter(|&ip| ip != entry.lan_ip) {
            let direct_host = format!(
                "{}-direct.{ZONE}",
                entry
                    .hostname
                    .strip_suffix(&format!(".{ZONE}"))
                    .unwrap_or(&entry.hostname)
            );
            direct_entries.push(DnsEntry {
                hostname: direct_host,
                lan_ip: mvip,
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Skip,
                wan_expose: WanExpose::Skip,
                dns_ttl: entry.dns_ttl,
                reconcile_interval: entry.reconcile_interval,
                managed: true,
                source: format!("{}/direct", entry.source),
                unbound_alias_target: None,
            });
        }
    }

    for de in direct_entries {
        state.insert(de.hostname.clone(), de);
    }

    state
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

/// Compute the change set between desired and current DNS states.
#[must_use]
pub fn diff(desired: &DnsState, current: &DnsState) -> DnsChanges {
    let mut changes = DnsChanges::default();

    for (hostname, desired_entry) in desired {
        match current.get(hostname) {
            None => changes.add.push(desired_entry.clone()),
            Some(current_entry) if current_entry != desired_entry => {
                changes.update.push(desired_entry.clone());
            }
            Some(_) => {} // unchanged
        }
    }

    for hostname in current.keys() {
        if !desired.contains_key(hostname) {
            changes.remove.push(hostname.clone());
        }
    }

    // Sort for deterministic output.
    changes.add.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    changes.update.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    changes.remove.sort();

    changes
}

// ---------------------------------------------------------------------------
// merge_dhcp_reservations
// ---------------------------------------------------------------------------

/// Merge DHCP reservations into the DNS state.
///
/// For each reservation whose hostname does NOT already exist in `state`
/// (i.e. no IngressRoute claims it), a new [`DnsEntry`] is inserted pointing
/// directly at the device's IP. Reservations whose hostname collides with an
/// existing IngressRoute entry are skipped for DNS purposes — Traefik wins —
/// but are still included in the returned `Vec` so Dnsmasq can process all
/// static leases.
pub fn merge_dhcp_reservations(
    state: &mut DnsState,
    reservations: &[Arc<DhcpReservation>],
) -> Vec<Arc<DhcpReservation>> {
    let mut result: Vec<Arc<DhcpReservation>> = Vec::with_capacity(reservations.len());

    for reservation in reservations {
        let hostname = format!("{}.hr-home.xyz", reservation.spec.hostname);

        if let Some(existing) = state.get(&hostname) {
            // IngressRoute already owns this hostname — skip DNS, keep for Dnsmasq.
            info!(
                hostname = %hostname,
                winning_ip = %existing.lan_ip,
                dhcp_ip = %reservation.spec.ip,
                winner = %existing.source,
                "DHCP reservation hostname already managed by IngressRoute; DNS points to Traefik, DHCP lease still created"
            );
            result.push(Arc::clone(reservation));
            continue;
        }

        let lan_ip = match reservation.spec.ip.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(err) => {
                warn!(
                    hostname = %hostname,
                    ip = %reservation.spec.ip,
                    error = %err,
                    "DHCP reservation has invalid IP, skipping"
                );
                continue;
            }
        };

        state.insert(
            hostname.clone(),
            DnsEntry {
                hostname: hostname.clone(),
                lan_ip,
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Skip,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: format!("dhcp/{}", reservation.spec.hostname),
                unbound_alias_target: None,
            },
        );

        result.push(Arc::clone(reservation));
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{PodSpec, PodStatus, ServicePort, ServiceSpec};
    use kube::api::ObjectMeta;

    // ---- Test fixture builders ----

    fn make_ingress_route(
        namespace: &str,
        name: &str,
        match_rule: &str,
        svc_name: &str,
        labels: BTreeMap<String, String>,
    ) -> Arc<IngressRoute> {
        make_ingress_route_with_annotations(
            namespace,
            name,
            match_rule,
            svc_name,
            labels,
            BTreeMap::new(),
        )
    }

    fn make_ingress_route_with_annotations(
        namespace: &str,
        name: &str,
        match_rule: &str,
        svc_name: &str,
        labels: BTreeMap<String, String>,
        annotations: BTreeMap<String, String>,
    ) -> Arc<IngressRoute> {
        let annotations_opt = if annotations.is_empty() {
            None
        } else {
            Some(annotations)
        };
        Arc::new(IngressRoute {
            metadata: ObjectMeta {
                namespace: Some(namespace.to_owned()),
                name: Some(name.to_owned()),
                labels: Some(labels),
                annotations: annotations_opt,
                ..Default::default()
            },
            spec: crate::traefik::IngressRouteSpec {
                entry_points: None,
                routes: vec![crate::traefik::IngressRouteRoute {
                    match_rule: match_rule.to_owned(),
                    services: Some(vec![crate::traefik::IngressRouteService {
                        name: svc_name.to_owned(),
                        namespace: Some(namespace.to_owned()),
                    }]),
                    middlewares: None,
                }],
            },
        })
    }

    fn make_service(
        namespace: &str,
        name: &str,
        selector: BTreeMap<String, String>,
        ports: Vec<(i32, &str)>,
    ) -> Arc<Service> {
        Arc::new(Service {
            metadata: ObjectMeta {
                namespace: Some(namespace.to_owned()),
                name: Some(name.to_owned()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector: Some(selector),
                ports: Some(
                    ports
                        .into_iter()
                        .map(|(port, proto)| ServicePort {
                            port,
                            protocol: Some(proto.to_owned()),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    fn make_pod(
        namespace: &str,
        name: &str,
        labels: BTreeMap<String, String>,
        multus_annotation: Option<&str>,
    ) -> Arc<Pod> {
        let annotations = multus_annotation.map(|a| {
            let mut m = BTreeMap::new();
            m.insert(MULTUS_STATUS_ANNOTATION.to_owned(), a.to_owned());
            m
        });

        Arc::new(Pod {
            metadata: ObjectMeta {
                namespace: Some(namespace.to_owned()),
                name: Some(name.to_owned()),
                labels: Some(labels),
                annotations,
                ..Default::default()
            },
            spec: Some(PodSpec::default()),
            status: Some(PodStatus::default()),
        })
    }

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn make_dhcp_reservation(hostname: &str, mac: &str, ip: &str) -> Arc<DhcpReservation> {
        Arc::new(DhcpReservation {
            metadata: ObjectMeta {
                namespace: Some("system".to_owned()),
                name: Some(hostname.to_owned()),
                ..Default::default()
            },
            spec: crate::crd::DhcpReservationSpec {
                hostname: hostname.to_owned(),
                mac: mac.to_owned(),
                ip: ip.to_owned(),
                description: None,
            },
        })
    }

    fn traefik_ip() -> IpAddr {
        "10.43.0.100".parse().unwrap()
    }

    // ---- Tests ----

    #[test]
    fn macvlan_pod_gets_alias_and_direct_entry() {
        let ir = make_ingress_route(
            "home",
            "hass",
            "Host(`hass.hr-home.xyz`)",
            "hass-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );
        let svc = make_service(
            "home",
            "hass-svc",
            labels(&[("app", "hass")]),
            vec![(8123, "TCP")],
        );
        let pod = make_pod(
            "home",
            "hass-pod",
            labels(&[("app", "hass")]),
            Some(r#"[{"name":"default/lan-macvlan","ips":["192.168.2.51/24"]}]"#),
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        // Main entry becomes an alias to the anchor.
        let entry = state.get("hass.hr-home.xyz").expect("entry must exist");
        assert_eq!(entry.lan_ip, traefik_ip());
        assert_eq!(entry.macvlan_ip, Some("192.168.2.51".parse().unwrap()));
        assert!(entry.managed);
        assert_eq!(
            entry.unbound_alias_target,
            Some(crate::UNBOUND_ANCHOR.to_owned())
        );

        // Direct entry is emitted for the macvlan IP.
        let direct = state
            .get("hass-direct.hr-home.xyz")
            .expect("direct entry must exist");
        assert_eq!(direct.lan_ip, "192.168.2.51".parse::<IpAddr>().unwrap());
        assert_eq!(direct.macvlan_ip, None);
        assert!(direct.managed);
        assert_eq!(direct.unbound_alias_target, None);

        // Anchor entry is synthesized.
        let anchor = state.get(crate::UNBOUND_ANCHOR).expect("anchor must exist");
        assert_eq!(anchor.lan_ip, traefik_ip());
        assert_eq!(anchor.unbound_alias_target, None);
        assert!(anchor.managed);
    }

    #[test]
    fn no_macvlan_pod_gets_alias_no_direct() {
        let ir = make_ingress_route(
            "media",
            "plex",
            "Host(`plex.hr-home.xyz`)",
            "plex-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );
        let svc = make_service(
            "media",
            "plex-svc",
            labels(&[("app", "plex")]),
            vec![(32400, "TCP")],
        );
        let pod = make_pod("media", "plex-pod", labels(&[("app", "plex")]), None);

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        let entry = state.get("plex.hr-home.xyz").unwrap();
        assert_eq!(entry.lan_ip, traefik_ip());
        assert_eq!(entry.macvlan_ip, None);
        assert_eq!(
            entry.unbound_alias_target,
            Some(crate::UNBOUND_ANCHOR.to_owned())
        );
        // No -direct entry since no macvlan IP.
        assert!(!state.contains_key("plex-direct.hr-home.xyz"));
    }

    #[test]
    fn no_dns_label_sets_managed_false() {
        let ir = make_ingress_route(
            "system",
            "registry",
            "Host(`registry.hr-home.xyz`)",
            "registry-svc",
            BTreeMap::new(), // no labels
        );
        let svc = make_service(
            "system",
            "registry-svc",
            labels(&[("app", "registry")]),
            vec![(5000, "TCP")],
        );

        let state = build_desired_state(&[ir], &[], &[svc], traefik_ip());

        let entry = state.get("registry.hr-home.xyz").unwrap();
        assert!(!entry.managed);
    }

    #[test]
    fn dns_true_label_sets_managed_true() {
        let ir = make_ingress_route(
            "home",
            "hass",
            "Host(`hass.hr-home.xyz`)",
            "hass-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );

        let state = build_desired_state(&[ir], &[], &[], traefik_ip());

        let entry = state.get("hass.hr-home.xyz").unwrap();
        assert!(entry.managed);
    }

    #[test]
    fn cloudflare_dns_only_label() {
        let ir = make_ingress_route(
            "home",
            "hass",
            "Host(`hass.hr-home.xyz`)",
            "hass-svc",
            labels(&[("hr-home.xyz/cloudflare", "dns-only")]),
        );

        let state = build_desired_state(&[ir], &[], &[], traefik_ip());

        let entry = state.get("hass.hr-home.xyz").unwrap();
        assert_eq!(entry.cloudflare_mode, CloudflareMode::DnsOnly);
    }

    #[test]
    fn cloudflare_address_label() {
        let ir = make_ingress_route(
            "system",
            "stalwart",
            "Host(`mail.hr-home.xyz`)",
            "stalwart-svc",
            labels(&[("hr-home.xyz/cloudflare", "address")]),
        );

        let state = build_desired_state(&[ir], &[], &[], traefik_ip());

        let entry = state.get("mail.hr-home.xyz").unwrap();
        assert_eq!(entry.cloudflare_mode, CloudflareMode::Address);
    }

    #[test]
    fn service_ports_exclude_80_443() {
        let ir = make_ingress_route(
            "media",
            "plex",
            "Host(`plex.hr-home.xyz`)",
            "plex-svc",
            labels(&[
                ("hr-home.xyz/dns", "true"),
                ("hr-home.xyz/wan-expose", "true"),
            ]),
        );
        let svc = make_service(
            "media",
            "plex-svc",
            labels(&[("app", "plex")]),
            vec![(80, "TCP"), (443, "TCP"), (32400, "TCP")],
        );
        let pod = make_pod(
            "media",
            "plex-pod",
            labels(&[("app", "plex")]),
            Some(r#"[{"name":"default/lan-macvlan","ips":["192.168.2.52/24"]}]"#),
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        let entry = state.get("plex.hr-home.xyz").unwrap();
        match &entry.wan_expose {
            WanExpose::Expose { ports } => {
                assert_eq!(ports.len(), 1);
                assert_eq!(ports[0].port, 32400);
                assert_eq!(ports[0].protocol, Protocol::Tcp);
            }
            WanExpose::Skip => panic!("expected Expose, got Skip"),
        }
    }

    #[test]
    fn wan_ports_label_overrides_service_ports() {
        let ir = make_ingress_route(
            "media",
            "plex",
            "Host(`plex.hr-home.xyz`)",
            "plex-svc",
            labels(&[
                ("hr-home.xyz/dns", "true"),
                ("hr-home.xyz/wan-expose", "true"),
                ("hr-home.xyz/wan-ports", "32400/tcp,32469/tcp"),
            ]),
        );
        let svc = make_service(
            "media",
            "plex-svc",
            labels(&[("app", "plex")]),
            vec![(80, "TCP"), (9090, "TCP")],
        );
        let pod = make_pod(
            "media",
            "plex-pod",
            labels(&[("app", "plex")]),
            Some(r#"[{"name":"default/lan-macvlan","ips":["192.168.2.52/24"]}]"#),
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        let entry = state.get("plex.hr-home.xyz").unwrap();
        match &entry.wan_expose {
            WanExpose::Expose { ports } => {
                assert_eq!(ports.len(), 2);
                assert_eq!(ports[0].port, 32400);
                assert_eq!(ports[1].port, 32469);
            }
            WanExpose::Skip => panic!("expected Expose, got Skip"),
        }
    }

    #[test]
    fn wan_ports_annotation_overrides_service_ports() {
        let ir = make_ingress_route_with_annotations(
            "system",
            "stalwart",
            "Host(`mail.hr-home.xyz`)",
            "stalwart-svc",
            labels(&[
                ("hr-home.xyz/dns", "true"),
                ("hr-home.xyz/wan-expose", "true"),
            ]),
            labels(&[("hr-home.xyz/wan-ports", "25/tcp,587/tcp,993/tcp")]),
        );
        let svc = make_service(
            "system",
            "stalwart-svc",
            labels(&[("app", "stalwart")]),
            vec![(8080, "TCP")],
        );
        let pod = make_pod(
            "system",
            "stalwart-pod",
            labels(&[("app", "stalwart")]),
            Some(r#"[{"name":"default/lan-macvlan","ips":["192.168.2.3/24"]}]"#),
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        let entry = state.get("mail.hr-home.xyz").unwrap();
        match &entry.wan_expose {
            WanExpose::Expose { ports } => {
                assert_eq!(ports.len(), 3);
                assert_eq!(ports[0].port, 25);
                assert_eq!(ports[1].port, 587);
                assert_eq!(ports[2].port, 993);
            }
            WanExpose::Skip => panic!("expected Expose, got Skip"),
        }
    }

    #[test]
    fn wan_expose_skip_label() {
        let ir = make_ingress_route(
            "media",
            "plex",
            "Host(`plex.hr-home.xyz`)",
            "plex-svc",
            labels(&[("hr-home.xyz/wan-expose", "skip")]),
        );
        let svc = make_service(
            "media",
            "plex-svc",
            labels(&[("app", "plex")]),
            vec![(32400, "TCP")],
        );
        let pod = make_pod(
            "media",
            "plex-pod",
            labels(&[("app", "plex")]),
            Some(r#"[{"name":"default/lan-macvlan","ips":["192.168.2.52/24"]}]"#),
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        let entry = state.get("plex.hr-home.xyz").unwrap();
        assert_eq!(entry.wan_expose, WanExpose::Skip);
    }

    #[test]
    fn diff_detects_add_update_remove() {
        let mut current = DnsState::new();
        current.insert(
            "old.hr-home.xyz".to_owned(),
            DnsEntry {
                hostname: "old.hr-home.xyz".to_owned(),
                lan_ip: traefik_ip(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "system/old".to_owned(),
                unbound_alias_target: None,
            },
        );
        current.insert(
            "same.hr-home.xyz".to_owned(),
            DnsEntry {
                hostname: "same.hr-home.xyz".to_owned(),
                lan_ip: traefik_ip(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "system/same".to_owned(),
                unbound_alias_target: None,
            },
        );
        current.insert(
            "changed.hr-home.xyz".to_owned(),
            DnsEntry {
                hostname: "changed.hr-home.xyz".to_owned(),
                lan_ip: traefik_ip(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: false, // was false
                source: "system/changed".to_owned(),
                unbound_alias_target: None,
            },
        );

        let mut desired = DnsState::new();
        // "old" is gone -> remove
        // "same" is identical -> no change
        desired.insert(
            "same.hr-home.xyz".to_owned(),
            DnsEntry {
                hostname: "same.hr-home.xyz".to_owned(),
                lan_ip: traefik_ip(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "system/same".to_owned(),
                unbound_alias_target: None,
            },
        );
        // "changed" has managed flipped -> update
        desired.insert(
            "changed.hr-home.xyz".to_owned(),
            DnsEntry {
                hostname: "changed.hr-home.xyz".to_owned(),
                lan_ip: traefik_ip(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true, // changed to true
                source: "system/changed".to_owned(),
                unbound_alias_target: None,
            },
        );
        // "new" is added
        desired.insert(
            "new.hr-home.xyz".to_owned(),
            DnsEntry {
                hostname: "new.hr-home.xyz".to_owned(),
                lan_ip: traefik_ip(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "system/new".to_owned(),
                unbound_alias_target: None,
            },
        );

        let changes = diff(&desired, &current);

        assert_eq!(changes.add.len(), 1);
        assert_eq!(changes.add[0].hostname, "new.hr-home.xyz");

        assert_eq!(changes.update.len(), 1);
        assert_eq!(changes.update[0].hostname, "changed.hr-home.xyz");

        assert_eq!(changes.remove.len(), 1);
        assert_eq!(changes.remove[0], "old.hr-home.xyz");
    }

    #[test]
    fn fida_services_hostname_skipped() {
        let ir = make_ingress_route(
            "fida",
            "rfc",
            "Host(`rfc.fida.services`)",
            "rfc-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );

        let state = build_desired_state(&[ir], &[], &[], traefik_ip());

        assert!(state.is_empty());
    }

    #[test]
    fn sablier_zero_pod_still_creates_entry() {
        let ir = make_ingress_route(
            "media",
            "calibre",
            "Host(`calibre.hr-home.xyz`)",
            "calibre-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );
        let svc = make_service(
            "media",
            "calibre-svc",
            labels(&[("app", "calibre")]),
            vec![(8083, "TCP")],
        );
        // No pods at all (Sablier scaled to zero).

        let state = build_desired_state(&[ir], &[], &[svc], traefik_ip());

        let entry = state.get("calibre.hr-home.xyz").unwrap();
        assert_eq!(entry.lan_ip, traefik_ip());
        assert_eq!(entry.macvlan_ip, None);
        assert!(entry.managed);
    }

    #[test]
    fn duplicate_hostname_lower_source_wins() {
        let ir_a = make_ingress_route(
            "home",
            "hass",
            "Host(`hass.hr-home.xyz`)",
            "hass-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );
        let ir_b = make_ingress_route(
            "ingress",
            "hass-redirect",
            "Host(`hass.hr-home.xyz`)",
            "hass-redirect-svc",
            BTreeMap::new(),
        );

        let state = build_desired_state(&[ir_a, ir_b], &[], &[], traefik_ip());

        let entry = state.get("hass.hr-home.xyz").unwrap();
        // "home/hass" < "ingress/hass-redirect" lexicographically
        assert_eq!(entry.source, "home/hass");
        assert!(entry.managed);
    }

    #[test]
    fn parse_duration_variants() {
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("300"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("5x"), None);
    }

    #[test]
    fn invalid_reconcile_interval_uses_default() {
        let ir = make_ingress_route(
            "home",
            "hass",
            "Host(`hass.hr-home.xyz`)",
            "hass-svc",
            labels(&[("hr-home.xyz/reconcile-interval", "bogus")]),
        );

        let state = build_desired_state(&[ir], &[], &[], traefik_ip());

        let entry = state.get("hass.hr-home.xyz").unwrap();
        assert_eq!(entry.reconcile_interval, Duration::from_secs(300));
    }

    #[test]
    fn parse_wan_ports_valid() {
        let ports = parse_wan_ports("32400/tcp,32469/tcp");
        assert_eq!(ports.len(), 2);
        assert_eq!(
            ports[0],
            PortForward {
                port: 32400,
                protocol: Protocol::Tcp
            }
        );
        assert_eq!(
            ports[1],
            PortForward {
                port: 32469,
                protocol: Protocol::Tcp
            }
        );
    }

    #[test]
    fn parse_wan_ports_mixed_protocols() {
        let ports = parse_wan_ports("8080/tcp,9090/udp");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].protocol, Protocol::Tcp);
        assert_eq!(ports[1].protocol, Protocol::Udp);
    }

    #[test]
    fn bare_zone_hostname_is_included() {
        let ir = make_ingress_route(
            "ingress",
            "root",
            "Host(`hr-home.xyz`)",
            "root-svc",
            BTreeMap::new(),
        );

        let state = build_desired_state(&[ir], &[], &[], traefik_ip());

        assert!(state.contains_key("hr-home.xyz"));
    }

    #[test]
    fn no_macvlan_means_wan_expose_skip_even_without_label() {
        let ir = make_ingress_route(
            "system",
            "registry",
            "Host(`registry.hr-home.xyz`)",
            "registry-svc",
            BTreeMap::new(),
        );
        let svc = make_service(
            "system",
            "registry-svc",
            labels(&[("app", "registry")]),
            vec![(5000, "TCP")],
        );
        let pod = make_pod(
            "system",
            "registry-pod",
            labels(&[("app", "registry")]),
            None, // no macvlan
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        let entry = state.get("registry.hr-home.xyz").unwrap();
        assert_eq!(entry.wan_expose, WanExpose::Skip);
    }

    #[test]
    fn anchor_ingressroute_stays_as_a_record_no_direct() {
        // When the anchor hostname (ha.hr-home.xyz) is a real IngressRoute
        // with a macvlan IP, it stays as an A record pointing to traefik_ip.
        // No -direct entry needed — the anchor IS the traefik_ip record.
        let ir = make_ingress_route(
            "home",
            "ha",
            &format!("Host(`{}`)", crate::UNBOUND_ANCHOR),
            "ha-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );
        let svc = make_service(
            "home",
            "ha-svc",
            labels(&[("app", "ha")]),
            vec![(8123, "TCP")],
        );
        let pod = make_pod(
            "home",
            "ha-pod",
            labels(&[("app", "ha")]),
            Some(r#"[{"name":"default/lan-macvlan","ips":["192.168.2.50/24"]}]"#),
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        // Anchor is an A record (no alias target), pointing to traefik_ip.
        let anchor = state.get(crate::UNBOUND_ANCHOR).expect("anchor must exist");
        assert_eq!(anchor.lan_ip, traefik_ip());
        assert_eq!(anchor.macvlan_ip, None);
        assert_eq!(anchor.unbound_alias_target, None);
        assert!(anchor.managed);

        // No -direct entry for the anchor itself.
        assert!(!state.contains_key("ha-direct.hr-home.xyz"));
    }

    #[test]
    fn synthetic_anchor_created_when_no_ha_ingressroute() {
        let ir = make_ingress_route(
            "media",
            "plex",
            "Host(`plex.hr-home.xyz`)",
            "plex-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );

        let state = build_desired_state(&[ir], &[], &[], traefik_ip());

        // Anchor is injected synthetically.
        let anchor = state.get(crate::UNBOUND_ANCHOR).expect("anchor must exist");
        assert_eq!(anchor.lan_ip, traefik_ip());
        assert_eq!(anchor.unbound_alias_target, None);
        assert!(anchor.managed);
        assert_eq!(anchor.source, "synthetic/unbound-anchor");

        // Plex entry is an alias.
        let entry = state.get("plex.hr-home.xyz").unwrap();
        assert_eq!(
            entry.unbound_alias_target,
            Some(crate::UNBOUND_ANCHOR.to_owned())
        );
    }

    // ---- DHCP reservation merge tests ----

    #[test]
    fn dhcp_reservation_merged_into_empty_state() {
        let mut state = DnsState::new();
        let reservation = make_dhcp_reservation("printer", "aa:bb:cc:dd:ee:ff", "192.168.2.100");

        let returned = merge_dhcp_reservations(&mut state, &[reservation]);

        assert_eq!(returned.len(), 1);
        let entry = state.get("printer.hr-home.xyz").expect("entry must exist");
        assert_eq!(entry.hostname, "printer.hr-home.xyz");
        assert_eq!(entry.lan_ip, "192.168.2.100".parse::<IpAddr>().unwrap());
        assert_eq!(entry.macvlan_ip, None);
        assert_eq!(entry.cloudflare_mode, CloudflareMode::Skip);
        assert_eq!(entry.wan_expose, WanExpose::Skip);
        assert_eq!(entry.dns_ttl, Duration::from_secs(300));
        assert_eq!(entry.reconcile_interval, Duration::from_secs(300));
        assert!(entry.managed);
        assert_eq!(entry.source, "dhcp/printer");
    }

    #[test]
    fn dhcp_reservation_conflict_preserves_ingress_entry() {
        let ir = make_ingress_route(
            "home",
            "hass",
            "Host(`hass.hr-home.xyz`)",
            "hass-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );
        let mut state = build_desired_state(&[ir], &[], &[], traefik_ip());

        let reservation = make_dhcp_reservation("hass", "aa:bb:cc:dd:ee:ff", "192.168.2.50");
        merge_dhcp_reservations(&mut state, &[reservation]);

        // IngressRoute entry must be preserved, not overwritten.
        let entry = state.get("hass.hr-home.xyz").unwrap();
        assert_eq!(entry.lan_ip, traefik_ip());
        assert_eq!(entry.source, "home/hass");
    }

    #[test]
    fn conflicting_reservation_still_returned() {
        let ir = make_ingress_route(
            "home",
            "hass",
            "Host(`hass.hr-home.xyz`)",
            "hass-svc",
            labels(&[("hr-home.xyz/dns", "true")]),
        );
        let mut state = build_desired_state(&[ir], &[], &[], traefik_ip());

        let reservation = make_dhcp_reservation("hass", "aa:bb:cc:dd:ee:ff", "192.168.2.50");
        let returned = merge_dhcp_reservations(&mut state, std::slice::from_ref(&reservation));

        // Conflicting reservation must still appear in the returned Vec for Dnsmasq.
        assert_eq!(returned.len(), 1);
        assert_eq!(returned[0].spec.hostname, "hass");
    }

    #[test]
    fn multiple_non_conflicting_reservations_all_merged() {
        let mut state = DnsState::new();
        let reservations = vec![
            make_dhcp_reservation("printer", "aa:bb:cc:00:00:01", "192.168.2.100"),
            make_dhcp_reservation("camera", "aa:bb:cc:00:00:02", "192.168.2.101"),
            make_dhcp_reservation("thermostat", "aa:bb:cc:00:00:03", "192.168.2.102"),
        ];

        let returned = merge_dhcp_reservations(&mut state, &reservations);

        assert_eq!(returned.len(), 3);
        assert_eq!(state.len(), 3);
        assert!(state.contains_key("printer.hr-home.xyz"));
        assert!(state.contains_key("camera.hr-home.xyz"));
        assert!(state.contains_key("thermostat.hr-home.xyz"));

        assert_eq!(
            state["camera.hr-home.xyz"].lan_ip,
            "192.168.2.101".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn dhcp_reservation_invalid_ip_skipped() {
        let mut state = DnsState::new();
        let reservation = make_dhcp_reservation("broken", "aa:bb:cc:dd:ee:ff", "not-an-ip");

        let returned = merge_dhcp_reservations(&mut state, &[reservation]);

        // Invalid IP reservation is not added to state or returned Vec.
        assert!(state.is_empty());
        assert!(returned.is_empty());
    }
}
