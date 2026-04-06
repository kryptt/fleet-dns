use std::future::Future;

use futures::TryStreamExt;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher;
use kube::runtime::WatchStreamExt;
use kube::{Api, Client};

use crate::crd::{DhcpConfig, DhcpReservation};

/// Start a reflector that watches all `DhcpReservation` resources cluster-wide.
///
/// Returns the readable store and a future that drives the watch stream.
/// The caller is responsible for spawning the future (typically via `tokio::spawn`).
pub fn start_reservation_watcher(
    client: Client,
) -> (Store<DhcpReservation>, impl Future<Output = ()>) {
    let api: Api<DhcpReservation> = Api::all(client);
    let (reader, writer) = reflector::store();
    let config = watcher::Config::default();

    let stream = watcher(api, config).default_backoff().reflect(writer);

    let handle = async move {
        stream.try_for_each(|_| futures::future::ok(())).await.ok();
    };

    (reader, handle)
}

/// Start a reflector that watches all `DhcpConfig` resources cluster-wide.
///
/// Returns the readable store and a future that drives the watch stream.
/// The caller is responsible for spawning the future (typically via `tokio::spawn`).
pub fn start_config_watcher(client: Client) -> (Store<DhcpConfig>, impl Future<Output = ()>) {
    let api: Api<DhcpConfig> = Api::all(client);
    let (reader, writer) = reflector::store();
    let config = watcher::Config::default();

    let stream = watcher(api, config).default_backoff().reflect(writer);

    let handle = async move {
        stream.try_for_each(|_| futures::future::ok(())).await.ok();
    };

    (reader, handle)
}
