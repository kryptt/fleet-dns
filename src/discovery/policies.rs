use std::future::Future;

use kube::runtime::WatchStreamExt;
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher;
use kube::{Api, Client};

use crate::crd::CoreDnsPolicy;

/// Start a reflector that watches all `CoreDnsPolicy` resources cluster-wide.
///
/// Returns the readable store and a future that drives the watch stream.
/// The caller is responsible for spawning the future (typically via `tokio::spawn`).
pub fn start_watcher(client: Client) -> (Store<CoreDnsPolicy>, impl Future<Output = ()>) {
    let api: Api<CoreDnsPolicy> = Api::all(client);
    let (reader, writer) = reflector::store();
    let config = watcher::Config::default();

    let stream = watcher(api, config).default_backoff().reflect(writer);
    let handle = super::drive_watch("corednspolicy", stream);

    (reader, handle)
}
