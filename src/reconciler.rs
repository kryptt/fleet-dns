use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use k8s_openapi::api::core::v1::{Pod, Service};
use kube::runtime::reflector::Store;
use kube::Client;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::crd::{CoreDnsPolicy, DhcpConfig, DhcpReservation};
use crate::error::Error;
use crate::metrics::{error_label, target_label, Metrics};
use crate::state::{build_desired_state, diff, merge_dhcp_reservations, DnsState};
use crate::targets::cloudflare::CloudflareClient;
use crate::targets::coredns;
use crate::targets::opnsense::{validate_ip_allocation, DhcpHostEntry, OpnSenseClient};
use crate::traefik::IngressRoute;

/// The main reconciliation orchestrator.
///
/// Holds references to all stores and target clients. The reconcile loop
/// calls [`Reconciler::run_once`] on each trigger.
pub struct Reconciler {
    config: Config,
    kube_client: Client,
    cloudflare: CloudflareClient,
    opnsense: OpnSenseClient,
    metrics: Metrics,
    ingress_store: Store<IngressRoute>,
    pod_store: Store<Pod>,
    service_store: Store<Service>,
    policy_store: Store<CoreDnsPolicy>,
    reservation_store: Store<DhcpReservation>,
    dhcp_config_store: Store<DhcpConfig>,
    current_state: Mutex<DnsState>,
    wan_ip: Mutex<Option<IpAddr>>,
}

impl Reconciler {
    /// Create a new reconciler from pre-constructed stores and clients.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        kube_client: Client,
        cloudflare: CloudflareClient,
        opnsense: OpnSenseClient,
        metrics: Metrics,
        ingress_store: Store<IngressRoute>,
        pod_store: Store<Pod>,
        service_store: Store<Service>,
        policy_store: Store<CoreDnsPolicy>,
        reservation_store: Store<DhcpReservation>,
        dhcp_config_store: Store<DhcpConfig>,
    ) -> Self {
        Self {
            config,
            kube_client,
            cloudflare,
            opnsense,
            metrics,
            ingress_store,
            pod_store,
            service_store,
            policy_store,
            reservation_store,
            dhcp_config_store,
            current_state: Mutex::new(DnsState::new()),
            wan_ip: Mutex::new(None),
        }
    }

    /// Execute a single reconciliation pass.
    ///
    /// Ordering: NAT -> Unbound -> CoreDNS -> Cloudflare -> Dnsmasq.
    /// - CoreDNS and Unbound always run (internal targets).
    /// - If NAT fails, Cloudflare is skipped (prevents exposing records
    ///   without matching port forwards).
    /// - Dnsmasq always runs (DHCP is independent of DNS/NAT success).
    pub async fn run_once(&self) -> Result<(), Error> {
        let start = Instant::now();
        self.metrics.reconciliations_total.inc();

        let result = self.reconcile_inner().await;

        let elapsed = start.elapsed().as_secs_f64();
        self.metrics.reconcile_duration_seconds.observe(elapsed);

        if let Err(ref e) = result {
            self.metrics
                .errors_total
                .get_or_create(&error_label(e.metric_label()))
                .inc();
            error!(error = %e, elapsed_s = elapsed, "reconciliation failed");
        } else {
            info!(elapsed_s = elapsed, "reconciliation complete");
        }

        result
    }

    async fn reconcile_inner(&self) -> Result<(), Error> {
        // 1. Snapshot stores.
        let ingresses = self.ingress_store.state();
        let pods = self.pod_store.state();
        let services = self.service_store.state();
        let policies = self.policy_store.state();

        // 2. Find Traefik pod IP.
        let traefik_ip = find_traefik_ip(&pods)?;

        // 3. Build desired state.
        let mut desired = build_desired_state(&ingresses, &pods, &services, traefik_ip);

        // 3b. Merge DHCP reservations into DNS state.
        let reservations: Vec<_> = self.reservation_store.state();
        let all_reservations = merge_dhcp_reservations(&mut desired, &reservations);
        let dhcp_configs: Vec<_> = self.dhcp_config_store.state();

        // 4. Get current WAN IP from OPNsense.
        let wan_ip = self
            .opnsense
            .get_wan_ip(&self.config.wan_interface)
            .await?;

        // Detect WAN IP changes.
        {
            let mut prev = self.wan_ip.lock().expect("wan_ip mutex poisoned");
            if prev.is_some_and(|old| old != wan_ip) {
                info!(old = %prev.unwrap(), new = %wan_ip, "WAN IP changed");
                self.metrics.wan_ip_changes_total.inc();
            }
            *prev = Some(wan_ip);
        }

        // 5. Diff against cached current state.
        let current = self.current_state.lock().expect("state mutex poisoned").clone();
        let changes = diff(&desired, &current);

        let has_changes = !changes.add.is_empty()
            || !changes.update.is_empty()
            || !changes.remove.is_empty();

        if !has_changes {
            return Ok(());
        }

        info!(
            add = changes.add.len(),
            update = changes.update.len(),
            remove = changes.remove.len(),
            "state diff computed"
        );

        // Collect all desired entries as a flat vec for target reconcilers.
        let all_entries: Vec<_> = desired.values().cloned().collect();

        // 6. Reconcile targets.
        //    NAT failure prevents Cloudflare, but Unbound and CoreDNS always run.
        let mut nat_ok = true;

        // -- NAT (external, managed-only entries with WAN expose) --
        match self
            .opnsense
            .reconcile_nat(&all_entries, self.config.dry_run)
            .await
        {
            Ok(stats) => {
                let total = stats.created + stats.updated + stats.deleted;
                self.metrics
                    .records_managed
                    .get_or_create(&target_label("nat"))
                    .set(total.into());
            }
            Err(e) => {
                warn!(error = %e, "NAT reconciliation failed; skipping Cloudflare");
                self.metrics
                    .errors_total
                    .get_or_create(&error_label("opnsense_nat"))
                    .inc();
                nat_ok = false;
            }
        }

        // -- Unbound (internal, managed-only entries) --
        match self
            .opnsense
            .reconcile_unbound(&all_entries, self.config.dry_run)
            .await
        {
            Ok(stats) => {
                let total = stats.created + stats.updated;
                self.metrics
                    .records_managed
                    .get_or_create(&target_label("unbound"))
                    .set(total.into());
            }
            Err(e) => {
                warn!(error = %e, "Unbound reconciliation failed");
                self.metrics
                    .errors_total
                    .get_or_create(&error_label("opnsense_unbound"))
                    .inc();
            }
        }

        // -- CoreDNS (internal, ALL entries unconditionally) --
        let configmap_data = coredns::render_configmap_data(&all_entries, &policies);
        if let Err(e) =
            coredns::apply_configmap(self.kube_client.clone(), configmap_data, self.config.dry_run)
                .await
        {
            warn!(error = %e, "CoreDNS reconciliation failed");
            self.metrics
                .errors_total
                .get_or_create(&error_label("coredns"))
                .inc();
        } else {
            self.metrics
                .records_managed
                .get_or_create(&target_label("coredns"))
                .set(all_entries.len() as i64);
        }

        // -- Cloudflare (external, managed-only entries; skip if NAT failed) --
        if nat_ok {
            match self
                .cloudflare
                .reconcile(&all_entries, wan_ip, self.config.dry_run)
                .await
            {
                Ok(stats) => {
                    let total = stats.created + stats.updated;
                    self.metrics
                        .records_managed
                        .get_or_create(&target_label("cloudflare"))
                        .set(total.into());
                }
                Err(e) => {
                    warn!(error = %e, "Cloudflare reconciliation failed");
                    self.metrics
                        .errors_total
                        .get_or_create(&error_label("cloudflare"))
                        .inc();
                }
            }
        }

        // -- Dnsmasq (DHCP host reservations + range) --
        let host_entries: Vec<DhcpHostEntry> = all_reservations
            .iter()
            .map(|r| DhcpHostEntry {
                hostname: r.spec.hostname.clone(),
                ip: r.spec.ip.clone(),
                mac: r.spec.mac.clone(),
            })
            .collect();

        match self
            .opnsense
            .reconcile_dnsmasq_hosts(&host_entries, self.config.dry_run)
            .await
        {
            Ok(stats) => {
                let total = stats.created + stats.updated + stats.deleted;
                self.metrics
                    .records_managed
                    .get_or_create(&target_label("dnsmasq"))
                    .set(total.into());
            }
            Err(e) => {
                warn!(error = %e, "Dnsmasq host reconciliation failed");
                self.metrics
                    .errors_total
                    .get_or_create(&error_label("dnsmasq_hosts"))
                    .inc();
            }
        }

        if let Some(dhcp_config) = dhcp_configs.first() {
            let reservation_ips: Vec<String> =
                reservations.iter().map(|r| r.spec.ip.clone()).collect();
            let conflicts = validate_ip_allocation(
                &dhcp_config.spec.reserved_ranges,
                &reservation_ips,
                &dhcp_config.spec.range_start,
                &dhcp_config.spec.range_end,
            );

            if !conflicts.is_empty() {
                for conflict in &conflicts {
                    error!(conflict = %conflict, "IP allocation conflict detected");
                }
                self.metrics.ip_conflicts_total.inc_by(conflicts.len() as u64);
            } else {
                match self
                    .opnsense
                    .reconcile_dnsmasq_range(&dhcp_config.spec, self.config.dry_run)
                    .await
                {
                    Ok(_stats) => {}
                    Err(e) => {
                        warn!(error = %e, "Dnsmasq range reconciliation failed");
                        self.metrics
                            .errors_total
                            .get_or_create(&error_label("dnsmasq_range"))
                            .inc();
                    }
                }
            }

            // Update pool size metric (range_end - range_start + 1).
            if let (Some(start), Some(end)) = (
                crate::targets::opnsense::parse_ipv4_octets(&dhcp_config.spec.range_start),
                crate::targets::opnsense::parse_ipv4_octets(&dhcp_config.spec.range_end),
            ) {
                let s = crate::targets::opnsense::octets_to_u32(start);
                let e = crate::targets::opnsense::octets_to_u32(end);
                if e >= s {
                    self.metrics.dhcp_pool_size.set((e - s + 1) as i64);
                }
            }
        }

        // Update DHCP reservations gauge.
        self.metrics
            .dhcp_reservations_total
            .set(all_reservations.len() as i64);

        // 7. Update cached current state.
        *self.current_state.lock().expect("state mutex poisoned") = desired;

        Ok(())
    }
}

/// Find the Traefik pod's macvlan IP from the pod store.
///
/// Looks for a running pod with the label `app=traefik` (or
/// `app.kubernetes.io/name=traefik`) and reads its Multus macvlan IP.
/// Falls back to podIP if no macvlan annotation is found.
fn find_traefik_ip(pods: &[std::sync::Arc<Pod>]) -> Result<IpAddr, Error> {
    use crate::discovery::parse_multus_ip;

    for pod in pods {
        let labels = match pod.metadata.labels.as_ref() {
            Some(l) => l,
            None => continue,
        };

        let is_traefik = labels.get("app").is_some_and(|v| v == "traefik")
            || labels
                .get("app.kubernetes.io/name")
                .is_some_and(|v| v == "traefik");

        if !is_traefik {
            continue;
        }

        // Prefer macvlan IP from Multus annotation (this is the LAN IP
        // that all CoreDNS entries should resolve to).
        // Try network-status first (runtime), then networks (request).
        let annotations = pod.metadata.annotations.as_ref();
        for key in [
            "k8s.v1.cni.cncf.io/network-status",
            "k8s.v1.cni.cncf.io/networks",
        ] {
            if let Some(annotation) = annotations.and_then(|a| a.get(key)) {
                if let Some(ip) = parse_multus_ip(annotation, "lan-macvlan") {
                    return Ok(ip);
                }
            }
        }

        // Fall back to podIP if no macvlan annotation.
        let ip_str = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ips.as_ref())
            .and_then(|ips| ips.first())
            .map(|pip| pip.ip.as_str())
            .or_else(|| {
                pod.status.as_ref().and_then(|s| s.pod_ip.as_deref())
            });

        if let Some(ip) = ip_str {
            match ip.parse::<IpAddr>() {
                Ok(addr) => return Ok(addr),
                Err(e) => {
                    warn!(ip, error = %e, "failed to parse Traefik pod IP");
                    continue;
                }
            }
        }
    }

    Err(Error::Config(
        "no running Traefik pod found with label app=traefik".to_owned(),
    ))
}
