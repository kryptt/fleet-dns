use std::future::Future;

use futures::TryStreamExt;
use kube::runtime::WatchStreamExt;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher;
use kube::{Api, Client};

use crate::crd::OidcApplication;

/// Start a reflector that watches all `OidcApplication` resources cluster-wide.
///
/// Returns the readable store and a future that drives the watch stream.
/// The caller is responsible for spawning the future (typically via `tokio::spawn`).
pub fn start_watcher(client: Client) -> (Store<OidcApplication>, impl Future<Output = ()>) {
    let api: Api<OidcApplication> = Api::all(client);
    let (reader, writer) = reflector::store();
    let config = watcher::Config::default();

    let stream = watcher(api, config).default_backoff().reflect(writer);

    let handle = async move {
        stream.try_for_each(|_| futures::future::ok(())).await.ok();
    };

    (reader, handle)
}
