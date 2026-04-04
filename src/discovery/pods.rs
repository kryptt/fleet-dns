use std::future::Future;

use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher;
use kube::runtime::WatchStreamExt;
use kube::{Api, Client};

/// Start a reflector that watches all `Pod` resources cluster-wide.
///
/// We watch all pods because the Multus network-status annotation cannot be
/// filtered server-side. Client-side filtering happens in the state builder.
///
/// Returns the readable store and a future that drives the watch stream.
/// The caller is responsible for spawning the future (typically via `tokio::spawn`).
pub fn start_watcher(client: Client) -> (Store<Pod>, impl Future<Output = ()>) {
    let api: Api<Pod> = Api::all(client);
    let (reader, writer) = reflector::store();
    let config = watcher::Config::default();

    let stream = watcher(api, config).default_backoff().reflect(writer);

    let handle = async move {
        stream.try_for_each(|_| futures::future::ok(())).await.ok();
    };

    (reader, handle)
}
