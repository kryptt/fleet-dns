use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

/// Label set for per-target metrics: `vec![("target", "cloudflare")]`.
type Labels = Vec<(String, String)>;

/// Prometheus metrics for the fleet-dns reconciler.
#[derive(Clone)]
pub struct Metrics {
    pub reconciliations_total: Counter,
    pub reconcile_duration_seconds: Histogram,
    pub errors_total: Family<Labels, Counter>,
    pub records_managed: Family<Labels, Gauge>,
    pub wan_ip_changes_total: Counter,
}

impl Metrics {
    /// Create and register all metrics under the `fleet_dns_` prefix.
    pub fn new(registry: &mut Registry) -> Self {
        let sub = registry.sub_registry_with_prefix("fleet_dns");

        let reconciliations_total = Counter::default();
        sub.register(
            "reconciliations_total",
            "Total number of reconciliation passes",
            reconciliations_total.clone(),
        );

        let reconcile_duration_seconds = Histogram::new(
            [0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0].into_iter(),
        );
        sub.register(
            "reconcile_duration_seconds",
            "Duration of each reconciliation pass in seconds",
            reconcile_duration_seconds.clone(),
        );

        let errors_total = Family::<Labels, Counter>::default();
        sub.register(
            "errors_total",
            "Total number of errors by source",
            errors_total.clone(),
        );

        let records_managed = Family::<Labels, Gauge>::default();
        sub.register(
            "records_managed",
            "Number of DNS records managed per target",
            records_managed.clone(),
        );

        let wan_ip_changes_total = Counter::default();
        sub.register(
            "wan_ip_changes_total",
            "Total number of WAN IP address changes detected",
            wan_ip_changes_total.clone(),
        );

        Self {
            reconciliations_total,
            reconcile_duration_seconds,
            errors_total,
            records_managed,
            wan_ip_changes_total,
        }
    }
}

/// Build a label set with a single `target` key.
pub fn target_label(target: &str) -> Labels {
    vec![("target".to_owned(), target.to_owned())]
}

/// Build a label set with a single `source` key (for error categorisation).
pub fn error_label(source: &str) -> Labels {
    vec![("source".to_owned(), source.to_owned())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_registration_does_not_panic() {
        let mut registry = Registry::default();
        let _metrics = Metrics::new(&mut registry);
    }

    #[test]
    fn metrics_can_be_cloned_and_incremented() {
        let mut registry = Registry::default();
        let metrics = Metrics::new(&mut registry);
        let m2 = metrics.clone();

        metrics.reconciliations_total.inc();
        // Clone shares the same underlying counter.
        assert_eq!(m2.reconciliations_total.get(), 1);
    }

    #[test]
    fn target_label_format() {
        let labels = target_label("cloudflare");
        assert_eq!(labels, vec![("target".to_owned(), "cloudflare".to_owned())]);
    }

    #[test]
    fn error_label_format() {
        let labels = error_label("opnsense");
        assert_eq!(labels, vec![("source".to_owned(), "opnsense".to_owned())]);
    }

    #[test]
    fn encode_produces_text() {
        let mut registry = Registry::default();
        let metrics = Metrics::new(&mut registry);
        metrics.reconciliations_total.inc();

        let mut buf = String::new();
        prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();

        assert!(buf.contains("fleet_dns_reconciliations_total"));
    }
}
