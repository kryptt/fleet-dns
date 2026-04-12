use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use k8s_openapi::api::core::v1::{Pod, Service};
use kube::api::{DeleteParams, ListParams, Patch, PatchParams};
use kube::runtime::reflector::Store;
use kube::{Api, Client};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::crd::{CoreDnsPolicy, DhcpConfig, DhcpReservation, OidcApplication};
use crate::error::Error;
use crate::metrics::{error_label, target_label, Metrics};
use crate::oidc_state::{build_oidc_desired, OidcAppDesired};
use crate::state::{build_desired_state, diff, merge_dhcp_reservations, DnsState};
use crate::targets::cloudflare::CloudflareClient;
use crate::targets::coredns;
use crate::targets::opnsense::{validate_ip_allocation, DhcpHostEntry, OpnSenseClient};
use crate::targets::zitadel::ZitadelClient;
use crate::traefik::IngressRoute;
use crate::ReconcileStats;

/// The main reconciliation orchestrator.
///
/// Holds references to all stores and target clients. The reconcile loop
/// calls [`Reconciler::run_once`] on each trigger.
pub struct Reconciler {
    config: Config,
    kube_client: Client,
    cloudflare: CloudflareClient,
    opnsense: OpnSenseClient,
    zitadel: Option<ZitadelClient>,
    metrics: Metrics,
    ingress_store: Store<IngressRoute>,
    pod_store: Store<Pod>,
    service_store: Store<Service>,
    policy_store: Store<CoreDnsPolicy>,
    reservation_store: Store<DhcpReservation>,
    dhcp_config_store: Store<DhcpConfig>,
    oidc_store: Option<Store<OidcApplication>>,
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
        zitadel: Option<ZitadelClient>,
        metrics: Metrics,
        ingress_store: Store<IngressRoute>,
        pod_store: Store<Pod>,
        service_store: Store<Service>,
        policy_store: Store<CoreDnsPolicy>,
        reservation_store: Store<DhcpReservation>,
        dhcp_config_store: Store<DhcpConfig>,
        oidc_store: Option<Store<OidcApplication>>,
    ) -> Self {
        Self {
            config,
            kube_client,
            cloudflare,
            opnsense,
            zitadel,
            metrics,
            ingress_store,
            pod_store,
            service_store,
            policy_store,
            reservation_store,
            dhcp_config_store,
            oidc_store,
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

        // -- OIDC (Zitadel apps + Traefik Middleware) --
        if let (Some(zitadel), Some(oidc_store)) = (&self.zitadel, &self.oidc_store) {
            let oidc_apps: Vec<_> = oidc_store.state();
            let oidc_desired = build_oidc_desired(&oidc_apps, &ingresses);

            match reconcile_oidc(
                zitadel,
                self.kube_client.clone(),
                &oidc_desired,
                self.config.dry_run,
            )
            .await
            {
                Ok(stats) => {
                    let total = stats.created + stats.updated + stats.deleted;
                    self.metrics
                        .records_managed
                        .get_or_create(&target_label("oidc"))
                        .set(total.into());
                }
                Err(e) => {
                    warn!(error = %e, "OIDC reconciliation failed");
                    self.metrics
                        .errors_total
                        .get_or_create(&error_label("zitadel"))
                        .inc();
                }
            }
        }

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
            if let Some(annotation) = annotations.and_then(|a| a.get(key))
                && let Some(ip) = parse_multus_ip(annotation, "lan-macvlan")
            {
                return Ok(ip);
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

// ---------------------------------------------------------------------------
// OIDC reconciliation
// ---------------------------------------------------------------------------

/// Zitadel URL used in generated Middlewares.
const ZITADEL_URL: &str = "https://zitadel.hr-home.xyz";

/// Reconcile OIDC applications: ensure each `OidcAppDesired` has a
/// corresponding Zitadel app and Traefik Middleware, with up-to-date
/// redirect URIs.
async fn reconcile_oidc(
    zitadel: &ZitadelClient,
    kube: Client,
    desired: &BTreeMap<String, OidcAppDesired>,
    dry_run: bool,
) -> Result<ReconcileStats, Error> {
    let mut stats = ReconcileStats::default();

    for (name, app) in desired {
        // Resolve project ID from name.
        let project_id = match zitadel.find_project_by_name(&app.spec.project_name).await? {
            Some(id) => id,
            None => {
                warn!(
                    crd = name,
                    project = app.spec.project_name,
                    "Zitadel project not found, skipping OIDC app"
                );
                stats.skipped += 1;
                continue;
            }
        };

        let redirect_uris: Vec<String> = app.redirect_uris.iter().cloned().collect();

        // Check if the app already exists in Zitadel.
        let existing = zitadel.list_apps(&project_id).await?;
        let found = existing
            .iter()
            .find(|a| a.name == app.spec.app_name);

        match found {
            Some(existing_app) => {
                // App exists — check if redirect URIs need updating.
                let current_uris: BTreeSet<String> =
                    existing_app.redirect_uris().iter().cloned().collect();
                if current_uris != app.redirect_uris {
                    if dry_run {
                        info!(
                            app = app.spec.app_name,
                            added = ?(app.redirect_uris.difference(&current_uris).collect::<Vec<_>>()),
                            "OIDC [dry-run] would update redirect URIs"
                        );
                    } else {
                        zitadel
                            .update_oidc_config(
                                &project_id,
                                &existing_app.id,
                                &redirect_uris,
                            )
                            .await?;
                        info!(
                            app = app.spec.app_name,
                            uris = redirect_uris.len(),
                            "updated OIDC redirect URIs"
                        );
                    }
                    stats.updated += 1;
                } else {
                    stats.skipped += 1;
                }

                // Ensure Middleware exists (requires a valid client_id).
                if let Some(client_id) = existing_app.client_id() {
                    ensure_middleware(&kube, &app.spec, client_id, &project_id, dry_run)
                        .await?;
                } else {
                    warn!(
                        app = app.spec.app_name,
                        "Zitadel app has no OIDC config; skipping Middleware"
                    );
                }
            }
            None => {
                // App doesn't exist — create it.
                if dry_run {
                    info!(
                        app = app.spec.app_name,
                        project = app.spec.project_name,
                        "OIDC [dry-run] would create app"
                    );
                } else {
                    let (app_id, client_id) = zitadel
                        .create_oidc_app(&project_id, &app.spec.app_name, &redirect_uris)
                        .await?;
                    info!(
                        app = app.spec.app_name,
                        app_id, client_id,
                        uris = redirect_uris.len(),
                        "created OIDC app in Zitadel"
                    );

                    ensure_middleware(&kube, &app.spec, &client_id, &project_id, dry_run)
                        .await?;
                }
                stats.created += 1;
            }
        }
    }

    // -- Cleanup: delete orphaned managed Middlewares --
    //
    // List all Middlewares with the `fleet-dns.hr-home.xyz/managed` label.
    // Any that don't match a desired OidcApplication are orphaned: clear their
    // Zitadel redirect URIs and delete the Middleware resource.
    let mw_api: Api<kube::core::DynamicObject> = Api::all_with(
        kube.clone(),
        &middleware_api_resource(),
    );
    let managed_list = mw_api
        .list(&ListParams::default().labels("fleet-dns.hr-home.xyz/managed=true"))
        .await?;

    // Build a set of desired middleware keys (namespace/name).
    let desired_mw_keys: BTreeSet<String> = desired
        .values()
        .map(|app| format!("{}/{}", app.spec.middleware.namespace, app.spec.middleware.name))
        .collect();

    for mw_obj in &managed_list {
        let mw_name = mw_obj.metadata.name.as_deref().unwrap_or_default();
        let mw_ns = mw_obj.metadata.namespace.as_deref().unwrap_or_default();
        let key = format!("{mw_ns}/{mw_name}");

        if desired_mw_keys.contains(&key) {
            continue;
        }

        let labels = mw_obj.metadata.labels.as_ref();
        let app_name = labels
            .and_then(|l| l.get("fleet-dns.hr-home.xyz/oidc-app"))
            .map(String::as_str)
            .unwrap_or_default();
        let project_id = labels
            .and_then(|l| l.get("fleet-dns.hr-home.xyz/project-id"))
            .map(String::as_str)
            .unwrap_or_default();

        if dry_run {
            info!(
                middleware = %key,
                app = app_name,
                "OIDC [dry-run] would delete orphaned Middleware and clear redirect URIs"
            );
        } else {
            // Clear redirect URIs in Zitadel (keep the app itself).
            if !project_id.is_empty() && !app_name.is_empty() {
                if let Ok(apps) = zitadel.list_apps(project_id).await {
                    if let Some(found) = apps.iter().find(|a| a.name == app_name) {
                        if !found.redirect_uris().is_empty() {
                            if let Err(e) = zitadel
                                .update_oidc_config(project_id, &found.id, &[])
                                .await
                            {
                                warn!(
                                    app = app_name,
                                    error = %e,
                                    "failed to clear Zitadel redirect URIs for orphaned app"
                                );
                            } else {
                                info!(
                                    app = app_name,
                                    "cleared Zitadel redirect URIs for orphaned OIDC app"
                                );
                            }
                        }
                    }
                }
            }

            // Delete the orphaned Middleware.
            let ns_api: Api<kube::core::DynamicObject> = Api::namespaced_with(
                kube.clone(),
                mw_ns,
                &middleware_api_resource(),
            );
            ns_api
                .delete(mw_name, &DeleteParams::default())
                .await?;
            info!(middleware = %key, "deleted orphaned Traefik Middleware");
        }
        stats.deleted += 1;
    }

    Ok(stats)
}

/// Create or update a Traefik Middleware resource for an OIDC application.
///
/// Uses server-side apply so that fleet-dns owns the resource without
/// conflicting with other controllers.
async fn ensure_middleware(
    kube: &Client,
    spec: &crate::crd::OidcApplicationSpec,
    client_id: &str,
    project_id: &str,
    dry_run: bool,
) -> Result<(), Error> {
    let mw = &spec.middleware;
    let mw_name = &mw.name;
    let mw_ns = &mw.namespace;

    if dry_run {
        info!(
            middleware = %format!("{mw_ns}/{mw_name}"),
            "OIDC [dry-run] would ensure Middleware"
        );
        return Ok(());
    }

    // Generate a deterministic session secret from the middleware name.
    // This is NOT a security credential — it's used for cookie encryption
    // by the Traefik OIDC plugin. Deterministic so restarts don't invalidate
    // sessions.
    let secret = format!(
        "{:x}",
        fnv1a_128(format!("fleet-dns-oidc-{mw_name}-{client_id}").as_bytes())
    );

    let mut oidc_auth = serde_json::json!({
        "Secret": secret,
        "Provider": {
            "Url": ZITADEL_URL,
            "ClientId": client_id,
            "UsePkce": true,
            "ValidAudience": project_id,
        },
        "Scopes": &mw.scopes,
        "AuthorizationHeader": {
            "Name": "Authorization"
        }
    });

    if !mw.headers.is_empty() {
        oidc_auth.as_object_mut().unwrap().insert(
            "Headers".to_owned(),
            serde_json::json!(
                mw.headers.iter().map(|h| serde_json::json!({
                    "Name": &h.name,
                    "Value": &h.value,
                })).collect::<Vec<_>>()
            ),
        );
    }

    let middleware_json = serde_json::json!({
        "apiVersion": "traefik.io/v1alpha1",
        "kind": "Middleware",
        "metadata": {
            "name": mw_name,
            "namespace": mw_ns,
            "labels": {
                "fleet-dns.hr-home.xyz/managed": "true",
                "fleet-dns.hr-home.xyz/oidc-app": spec.app_name,
                "fleet-dns.hr-home.xyz/project-id": project_id,
            }
        },
        "spec": {
            "plugin": {
                "oidc-auth": oidc_auth
            }
        }
    });

    let api: Api<kube::core::DynamicObject> = Api::namespaced_with(
        kube.clone(),
        mw_ns,
        &middleware_api_resource(),
    );

    let patch_params = PatchParams::apply("fleet-dns").force();
    api.patch(mw_name, &patch_params, &Patch::Apply(middleware_json))
        .await?;

    info!(middleware = %format!("{mw_ns}/{mw_name}"), "ensured Traefik Middleware");
    Ok(())
}

/// [`ApiResource`](kube::discovery::ApiResource) for Traefik Middleware CRDs.
fn middleware_api_resource() -> kube::discovery::ApiResource {
    kube::discovery::ApiResource {
        group: "traefik.io".into(),
        version: "v1alpha1".into(),
        kind: "Middleware".into(),
        api_version: "traefik.io/v1alpha1".into(),
        plural: "middlewares".into(),
    }
}

/// Deterministic FNV-1a 128-bit hash for generating session secrets.
///
/// This is NOT a cryptographic hash. It provides uniqueness and determinism
/// for Traefik OIDC plugin cookie encryption keys, where the only requirement
/// is that different inputs produce different outputs and the result is stable
/// across restarts.
fn fnv1a_128(data: &[u8]) -> u128 {
    // FNV-1a 128-bit offset basis and prime.
    // See: <https://www.isthe.com/chongo/tech/comp/fnv/>
    let mut h: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    for &b in data {
        h ^= b as u128;
        h = h.wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013B);
    }
    h
}
