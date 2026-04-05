use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::{Pod, Service};
use tracing::warn;

use crate::discovery::parse_multus_ip;
use crate::traefik::{extract_hostnames, IngressRoute};

/// The Multus network attachment name used for LAN macvlan interfaces.
const MACVLAN_NETWORK: &str = "lan-macvlan";

/// The annotation key for Multus network status.
const MULTUS_STATUS_ANNOTATION: &str = "k8s.v1.cni.cncf.io/network-status";

/// DNS zone suffix that fleet-dns manages. Hostnames outside this zone are skipped.
const MANAGED_ZONE: &str = ".hr-home.xyz";

/// Label prefix for fleet-dns annotations on IngressRoutes.
const LABEL_PREFIX: &str = "hr-home.xyz/";

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareMode {
    Proxied,
    DnsOnly,
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
            service_store.iter().find(|s| {
                let meta = &s.metadata;
                meta.namespace.as_deref().unwrap_or("default") == svc_ns
                    && meta.name.as_deref() == Some(svc_name.as_str())
            }).map(|s| s.as_ref())
        })
    })
}

/// Find Pods matching a Service's selector in the given namespace.
fn find_matching_pods<'a>(
    svc: &Service,
    pod_store: &'a [Arc<Pod>],
) -> Vec<&'a Pod> {
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
                if !hostname.ends_with(MANAGED_ZONE) && hostname != "hr-home.xyz" {
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

        let managed = get_label(&labels, "dns") == Some("true");

        let cloudflare_mode = match get_label(&labels, "cloudflare") {
            Some("dns-only") => CloudflareMode::DnsOnly,
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
                        let ports = match get_label(&labels, "wan-ports") {
                            Some(p) => parse_wan_ports(p),
                            None => backing_svc
                                .map(|s| infer_ports_from_service(s))
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

        state.insert(hostname.clone(), DnsEntry {
            hostname,
            lan_ip: traefik_ip,
            macvlan_ip,
            cloudflare_mode,
            wan_expose,
            dns_ttl,
            reconcile_interval,
            managed,
            source,
        });
    }

    state
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

/// Compute the change set between desired and current DNS states.
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        PodSpec, PodStatus, ServicePort, ServiceSpec,
    };
    use kube::api::ObjectMeta;

    // ---- Test fixture builders ----

    fn make_ingress_route(
        namespace: &str,
        name: &str,
        match_rule: &str,
        svc_name: &str,
        labels: BTreeMap<String, String>,
    ) -> Arc<IngressRoute> {
        Arc::new(IngressRoute {
            metadata: ObjectMeta {
                namespace: Some(namespace.to_owned()),
                name: Some(name.to_owned()),
                labels: Some(labels),
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

    fn traefik_ip() -> IpAddr {
        "10.43.0.100".parse().unwrap()
    }

    // ---- Tests ----

    #[test]
    fn macvlan_pod_gets_macvlan_ip_and_traefik_lan_ip() {
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

        let state = build_desired_state(
            &[ir],
            &[pod],
            &[svc],
            traefik_ip(),
        );

        let entry = state.get("hass.hr-home.xyz").expect("entry must exist");
        assert_eq!(entry.lan_ip, traefik_ip());
        assert_eq!(
            entry.macvlan_ip,
            Some("192.168.2.51".parse().unwrap())
        );
        assert!(entry.managed);
    }

    #[test]
    fn no_macvlan_pod_gets_none_macvlan_ip() {
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
        let pod = make_pod(
            "media",
            "plex-pod",
            labels(&[("app", "plex")]),
            None,
        );

        let state = build_desired_state(&[ir], &[pod], &[svc], traefik_ip());

        let entry = state.get("plex.hr-home.xyz").unwrap();
        assert_eq!(entry.lan_ip, traefik_ip());
        assert_eq!(entry.macvlan_ip, None);
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
    fn service_ports_exclude_80_443() {
        let ir = make_ingress_route(
            "media",
            "plex",
            "Host(`plex.hr-home.xyz`)",
            "plex-svc",
            labels(&[("hr-home.xyz/dns", "true"), ("hr-home.xyz/wan-expose", "true")]),
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
        current.insert("old.hr-home.xyz".to_owned(), DnsEntry {
            hostname: "old.hr-home.xyz".to_owned(),
            lan_ip: traefik_ip(),
            macvlan_ip: None,
            cloudflare_mode: CloudflareMode::Proxied,
            wan_expose: WanExpose::Skip,
            dns_ttl: Duration::from_secs(300),
            reconcile_interval: Duration::from_secs(300),
            managed: true,
            source: "system/old".to_owned(),
        });
        current.insert("same.hr-home.xyz".to_owned(), DnsEntry {
            hostname: "same.hr-home.xyz".to_owned(),
            lan_ip: traefik_ip(),
            macvlan_ip: None,
            cloudflare_mode: CloudflareMode::Proxied,
            wan_expose: WanExpose::Skip,
            dns_ttl: Duration::from_secs(300),
            reconcile_interval: Duration::from_secs(300),
            managed: true,
            source: "system/same".to_owned(),
        });
        current.insert("changed.hr-home.xyz".to_owned(), DnsEntry {
            hostname: "changed.hr-home.xyz".to_owned(),
            lan_ip: traefik_ip(),
            macvlan_ip: None,
            cloudflare_mode: CloudflareMode::Proxied,
            wan_expose: WanExpose::Skip,
            dns_ttl: Duration::from_secs(300),
            reconcile_interval: Duration::from_secs(300),
            managed: false, // was false
            source: "system/changed".to_owned(),
        });

        let mut desired = DnsState::new();
        // "old" is gone -> remove
        // "same" is identical -> no change
        desired.insert("same.hr-home.xyz".to_owned(), DnsEntry {
            hostname: "same.hr-home.xyz".to_owned(),
            lan_ip: traefik_ip(),
            macvlan_ip: None,
            cloudflare_mode: CloudflareMode::Proxied,
            wan_expose: WanExpose::Skip,
            dns_ttl: Duration::from_secs(300),
            reconcile_interval: Duration::from_secs(300),
            managed: true,
            source: "system/same".to_owned(),
        });
        // "changed" has managed flipped -> update
        desired.insert("changed.hr-home.xyz".to_owned(), DnsEntry {
            hostname: "changed.hr-home.xyz".to_owned(),
            lan_ip: traefik_ip(),
            macvlan_ip: None,
            cloudflare_mode: CloudflareMode::Proxied,
            wan_expose: WanExpose::Skip,
            dns_ttl: Duration::from_secs(300),
            reconcile_interval: Duration::from_secs(300),
            managed: true, // changed to true
            source: "system/changed".to_owned(),
        });
        // "new" is added
        desired.insert("new.hr-home.xyz".to_owned(), DnsEntry {
            hostname: "new.hr-home.xyz".to_owned(),
            lan_ip: traefik_ip(),
            macvlan_ip: None,
            cloudflare_mode: CloudflareMode::Proxied,
            wan_expose: WanExpose::Skip,
            dns_ttl: Duration::from_secs(300),
            reconcile_interval: Duration::from_secs(300),
            managed: true,
            source: "system/new".to_owned(),
        });

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
        assert_eq!(ports[0], PortForward { port: 32400, protocol: Protocol::Tcp });
        assert_eq!(ports[1], PortForward { port: 32469, protocol: Protocol::Tcp });
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
}
