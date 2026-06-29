use std::future::Future;
use std::net::IpAddr;

use futures::{Stream, StreamExt};
use kube::runtime::WatchStreamExt;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher;
use kube::{Api, Client};
use serde::Deserialize;
use tracing::{error, warn};

/// Start a reflector that watches all resources of type `T` cluster-wide.
///
/// Returns the readable store and a future that drives the watch stream.
/// The caller is responsible for spawning the future (typically via `tokio::spawn`).
pub fn start_watcher<T>(
    client: Client,
    resource_name: &'static str,
) -> (Store<T>, impl Future<Output = ()>)
where
    T: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + Send
        + Sync
        + 'static
        + serde::de::DeserializeOwned,
{
    let api: Api<T> = Api::all(client);
    let (reader, writer) = reflector::store();
    let config = watcher::Config::default();
    let stream = watcher(api, config).default_backoff().reflect(writer);
    let handle = drive_watch(resource_name, stream);
    (reader, handle)
}

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

/// Drive a reflector-backed watch stream forever, logging transient errors
/// instead of terminating on them.
///
/// `try_for_each` short-circuits on the first error `default_backoff` surfaces
/// (e.g. a routine apiserver connection reset over a long-lived watch). That
/// completed the driver future and silently froze the reflector Store with
/// stale data — a dead watch that never again sees new or changed objects,
/// while reconciles kept running against the frozen snapshot. Logging each
/// error and continuing keeps the watch (and its Store) live. Returns only if
/// the stream ends, which callers treat as fatal.
pub async fn drive_watch<S, T, E>(resource: &str, stream: S)
where
    S: Stream<Item = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut stream = std::pin::pin!(stream);
    while let Some(event) = stream.next().await {
        if let Err(e) = event {
            warn!(resource, error = %e, "watch error; backing off and retrying");
        }
    }
    error!(resource, "watch stream ended unexpectedly");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Parse a Multus annotation for the default "lan-macvlan" network.
    fn multus_lan(annotation: &str) -> Option<IpAddr> {
        parse_multus_ip(annotation, "lan-macvlan")
    }

    /// Shorthand to build `Some(IpAddr::V4(...))` for test assertions.
    fn some_v4(a: u8, b: u8, c: u8, d: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    #[test]
    fn valid_annotation_with_cidr() {
        assert_eq!(
            multus_lan(r#"[{"name":"lan-macvlan","ips":["192.168.2.51/24"]}]"#),
            some_v4(192, 168, 2, 51),
        );
    }

    #[test]
    fn multiple_networks_picks_correct_one() {
        let annotation = r#"[
            {"name":"default/cbr0","ips":["10.244.1.5/24"]},
            {"name":"default/lan-macvlan","ips":["192.168.2.51/24"]}
        ]"#;
        assert_eq!(multus_lan(annotation), some_v4(192, 168, 2, 51));
    }

    #[test]
    fn malformed_json_returns_none() {
        assert_eq!(multus_lan("not json at all"), None);
    }

    #[test]
    fn missing_ips_field_returns_none() {
        assert_eq!(multus_lan(r#"[{"name":"lan-macvlan"}]"#), None);
    }

    #[test]
    fn network_not_found_returns_none() {
        assert_eq!(
            multus_lan(r#"[{"name":"other-net","ips":["10.0.0.1/16"]}]"#),
            None
        );
    }

    #[test]
    fn ip_without_cidr_prefix() {
        // Bare IP (no /prefix) should parse identically to one with CIDR.
        let result = multus_lan(r#"[{"name":"lan-macvlan","ips":["10.0.1.42"]}]"#);
        assert_eq!(result, some_v4(10, 0, 1, 42));
    }

    #[test]
    fn namespaced_network_name_matches() {
        // Network names prefixed with a namespace ("kube-system/lan-macvlan")
        // should match the bare suffix "lan-macvlan".
        let namespaced = r#"[{"name":"kube-system/lan-macvlan","ips":["192.168.2.99/24"]}]"#;
        assert_eq!(multus_lan(namespaced), some_v4(192, 168, 2, 99));
    }

    #[test]
    fn empty_ips_array_returns_none() {
        assert_eq!(multus_lan(r#"[{"name":"lan-macvlan","ips":[]}]"#), None);
    }

    #[test]
    fn unparseable_ip_returns_none() {
        assert_eq!(
            multus_lan(r#"[{"name":"lan-macvlan","ips":["not-an-ip"]}]"#),
            None
        );
    }

    #[tokio::test]
    async fn drive_watch_consumes_every_item_past_errors() {
        use futures::StreamExt;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Regression guard for the swallowed-watch-death bug: a stream that
        // interleaves Ok and Err must be drained to completion. The old
        // `try_for_each` would stop at the first Err, leaving later items
        // (here Ok(2), Err, Ok(3)) unpolled.
        let polled = Arc::new(AtomicUsize::new(0));
        let counter = polled.clone();
        let items: Vec<Result<i32, String>> = vec![
            Ok(1),
            Err("transient watch error".to_owned()),
            Ok(2),
            Err("another transient error".to_owned()),
            Ok(3),
        ];
        let stream = futures::stream::iter(items).inspect(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        drive_watch("test-resource", stream).await;

        assert_eq!(
            polled.load(Ordering::SeqCst),
            5,
            "drive_watch must consume every item, not short-circuit on the first Err"
        );
    }
}
