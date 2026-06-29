#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod crd;
pub mod crd_prelude;
pub mod discovery;
pub mod error;
pub mod metrics;
pub mod oidc_state;
pub mod reconciler;
pub mod state;
pub mod targets;
pub mod traefik;

pub use config::Zones;

/// Statistics from a single reconciliation pass against any target.
#[derive(Debug, Default)]
pub struct ReconcileStats {
    pub created: u32,
    pub updated: u32,
    pub deleted: u32,
    pub skipped: u32,
}
