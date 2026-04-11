use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use tokio::sync::Notify;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use fleet_dns::config::Config;
use fleet_dns::discovery;
use fleet_dns::metrics::Metrics;
use fleet_dns::reconciler::Reconciler;
use fleet_dns::targets::cloudflare::CloudflareClient;
use fleet_dns::targets::opnsense::OpnSenseClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Init tracing.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    info!("fleet-dns starting");

    // 2. Load config.
    let config = Config::from_env()?;

    // 3. Check for "cleanup" subcommand.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).is_some_and(|a| a == "cleanup") {
        return run_cleanup(&config).await;
    }

    // 4. Create kube client.
    let kube_client = kube::Client::try_default().await?;

    // 5. Verify coredns-custom ConfigMap exists.
    verify_coredns_configmap(kube_client.clone()).await?;

    // 6. Create metrics registry.
    let mut registry = Registry::default();
    let metrics = Metrics::new(&mut registry);
    let registry = Arc::new(registry);

    // 7. Start watchers.
    let (ingress_store, ingress_handle) =
        discovery::ingress::start_watcher(kube_client.clone());
    let (pod_store, pod_handle) =
        discovery::pods::start_watcher(kube_client.clone());
    let (service_store, service_handle) =
        discovery::services::start_watcher(kube_client.clone());
    let (policy_store, policy_handle) =
        discovery::policies::start_watcher(kube_client.clone());
    let (reservation_store, reservation_handle) =
        discovery::dhcp::start_reservation_watcher(kube_client.clone());
    let (dhcp_config_store, dhcp_config_handle) =
        discovery::dhcp::start_config_watcher(kube_client.clone());

    tokio::spawn(ingress_handle);
    tokio::spawn(pod_handle);
    tokio::spawn(service_handle);
    tokio::spawn(policy_handle);
    tokio::spawn(reservation_handle);
    tokio::spawn(dhcp_config_handle);

    // 8. Build target clients.
    let cloudflare = CloudflareClient::new(
        &config.cloudflare_api_token,
        &config.cloudflare_zone_id,
        &config.cloudflare_cname_target,
    );
    let opnsense = OpnSenseClient::new(
        &config.opnsense_url,
        &config.opnsense_api_key,
        &config.opnsense_api_secret,
    )?;

    let reconcile_interval = config.default_reconcile_interval;
    let dry_run = config.dry_run;

    // 9. Build reconciler.
    // TODO(fleet-dns-oidc): add Zitadel client and OidcApplication store
    // when ZITADEL_URL is configured.
    let zitadel: Option<fleet_dns::targets::zitadel::ZitadelClient> = None;
    let oidc_store: Option<kube::runtime::reflector::Store<fleet_dns::crd::OidcApplication>> = None;

    let reconciler = Arc::new(Reconciler::new(
        config,
        kube_client,
        cloudflare,
        opnsense,
        zitadel,
        metrics.clone(),
        ingress_store.clone(),
        pod_store.clone(),
        service_store.clone(),
        policy_store.clone(),
        reservation_store.clone(),
        dhcp_config_store.clone(),
        oidc_store,
    ));

    // 10. Start HTTP server.
    let ready = Arc::new(AtomicBool::new(false));
    let app = build_router(registry, ready.clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9090").await?;
    info!("HTTP server listening on :9090");
    let http_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // 11. Wait for initial store sync (simple heuristic: poll until stores are non-empty).
    wait_for_sync(&ingress_store, &pod_store, &service_store).await;
    ready.store(true, Ordering::Release);
    info!("all reflector stores synced; ready");

    // 12. Reconcile loop with Notify-based signaling.
    let notify = Arc::new(Notify::new());

    // Periodic timer.
    let notify_timer = notify.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(reconcile_interval).await;
            notify_timer.notify_one();
        }
    });

    // Trigger first reconcile immediately.
    notify.notify_one();

    // 13. Graceful shutdown on SIGTERM.
    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        info!("received shutdown signal");
    };

    if dry_run {
        info!("running in DRY-RUN mode");
    }

    tokio::select! {
        _ = run_reconcile_loop(reconciler, notify) => {}
        _ = shutdown => {
            info!("shutting down");
        }
    }

    http_handle.abort();
    Ok(())
}

/// Run the reconcile loop, waking on each `Notify` signal.
///
/// At most one reconciliation is in flight at a time -- if a notification
/// arrives while a pass is running, it is coalesced into the next pass.
async fn run_reconcile_loop(reconciler: Arc<Reconciler>, notify: Arc<Notify>) {
    loop {
        notify.notified().await;

        if let Err(e) = reconciler.run_once().await {
            error!(error = %e, "reconciliation pass failed");
        }
    }
}

/// Wait until at least the ingress and pod stores have received their initial
/// listing. Services and policies may legitimately be empty.
async fn wait_for_sync(
    ingress_store: &kube::runtime::reflector::Store<fleet_dns::traefik::IngressRoute>,
    pod_store: &kube::runtime::reflector::Store<k8s_openapi::api::core::v1::Pod>,
    _service_store: &kube::runtime::reflector::Store<k8s_openapi::api::core::v1::Service>,
) {
    // The reflector populates the store after the initial LIST completes.
    // We poll until the pod store has at least one entry (there is always at
    // least one pod in a running cluster).
    let mut attempts = 0;
    loop {
        let pods_populated = !pod_store.state().is_empty();
        // IngressRoutes might legitimately be zero if none are deployed yet,
        // but we wait for pods as a proxy for "the API server is reachable
        // and the reflector has completed its initial list".
        if pods_populated {
            break;
        }
        attempts += 1;
        if attempts % 20 == 0 {
            warn!(
                attempts,
                ingress_count = ingress_store.state().len(),
                pod_count = pod_store.state().len(),
                "still waiting for reflector stores to sync"
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Verify that the `coredns-custom` ConfigMap exists in `kube-system`.
async fn verify_coredns_configmap(client: kube::Client) -> Result<(), Box<dyn std::error::Error>> {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::Api;

    let api: Api<ConfigMap> = Api::namespaced(client, "kube-system");
    match api.get("coredns-custom").await {
        Ok(_) => {
            info!("coredns-custom ConfigMap exists");
            Ok(())
        }
        Err(kube::Error::Api(resp)) if resp.code == 404 => {
            error!("coredns-custom ConfigMap not found in kube-system; create it first");
            Err("coredns-custom ConfigMap not found".into())
        }
        Err(e) => Err(e.into()),
    }
}

/// Build the axum router with health and metrics endpoints.
fn build_router(
    registry: Arc<Registry>,
    ready: Arc<AtomicBool>,
) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route(
            "/readyz",
            get(move || {
                let ready = ready.clone();
                async move {
                    if ready.load(Ordering::Acquire) {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }
            }),
        )
        .route(
            "/metrics",
            get(move || {
                let registry = registry.clone();
                async move { metrics_handler(registry).await }
            }),
        )
}

async fn metrics_handler(registry: Arc<Registry>) -> impl IntoResponse {
    let mut buf = String::new();
    match encode(&mut buf, &registry) {
        Ok(()) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            buf,
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, "failed to encode metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Run cleanup: delete all fleet-dns-managed entries from OPNsense and Cloudflare, then exit.
async fn run_cleanup(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("running cleanup");

    let opnsense = OpnSenseClient::new(
        &config.opnsense_url,
        &config.opnsense_api_key,
        &config.opnsense_api_secret,
    )?;

    let cloudflare = CloudflareClient::new(
        &config.cloudflare_api_token,
        &config.cloudflare_zone_id,
        &config.cloudflare_cname_target,
    );

    // Clean up OPNsense Unbound host overrides.
    let overrides = opnsense.search_host_overrides().await?;
    let managed_overrides: Vec<_> = overrides
        .iter()
        .filter(|o| fleet_dns::targets::opnsense::is_fleet_dns_managed(&o.description))
        .collect();

    info!(count = managed_overrides.len(), "found fleet-dns Unbound overrides");
    for o in &managed_overrides {
        if config.dry_run {
            info!(uuid = %o.uuid, desc = %o.description, "[dry-run] would delete Unbound override");
        } else {
            opnsense.del_host_override(&o.uuid).await?;
            info!(uuid = %o.uuid, desc = %o.description, "deleted Unbound override");
        }
    }

    if !managed_overrides.is_empty() && !config.dry_run {
        opnsense.unbound_reconfigure().await?;
    }

    // Clean up OPNsense DNAT rules.
    let dnat_rules = opnsense.search_dnat_rules().await?;
    let managed_dnat: Vec<_> = dnat_rules
        .iter()
        .filter(|r| fleet_dns::targets::opnsense::is_fleet_dns_managed(&r.descr))
        .collect();

    info!(count = managed_dnat.len(), "found fleet-dns DNAT rules");
    for r in &managed_dnat {
        if config.dry_run {
            info!(uuid = %r.uuid, desc = %r.descr, "[dry-run] would delete DNAT rule");
        } else {
            opnsense.del_dnat_rule(&r.uuid).await?;
            info!(uuid = %r.uuid, desc = %r.descr, "deleted DNAT rule");
        }
    }

    // Clean up OPNsense filter rules.
    let filter_rules = opnsense.search_filter_rules().await?;
    let managed_filter: Vec<_> = filter_rules
        .iter()
        .filter(|r| fleet_dns::targets::opnsense::is_fleet_dns_managed(&r.description))
        .collect();

    info!(count = managed_filter.len(), "found fleet-dns filter rules");
    for r in &managed_filter {
        if config.dry_run {
            info!(uuid = %r.uuid, desc = %r.description, "[dry-run] would delete filter rule");
        } else {
            opnsense.del_filter_rule(&r.uuid).await?;
            info!(uuid = %r.uuid, desc = %r.description, "deleted filter rule");
        }
    }

    let firewall_mutated = !managed_dnat.is_empty() || !managed_filter.is_empty();
    if firewall_mutated && !config.dry_run {
        opnsense.firewall_apply().await?;
    }

    // Clean up Cloudflare: reconcile with empty desired state removes all managed records.
    info!("cleaning up Cloudflare records");
    cloudflare.reconcile(&[], "0.0.0.0".parse().unwrap(), config.dry_run).await?;

    info!("cleanup complete");
    Ok(())
}
