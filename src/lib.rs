pub mod config;
pub mod crd;
pub mod discovery;
pub mod error;
pub mod metrics;
pub mod reconciler;
pub mod state;
pub mod targets;
pub mod traefik;

/// DNS zone suffix that fleet-dns manages. Hostnames outside this zone are skipped.
pub const MANAGED_ZONE: &str = ".hr-home.xyz";

/// The bare zone name (without leading dot).
pub const ZONE: &str = "hr-home.xyz";

/// Statistics from a single reconciliation pass against any target.
#[derive(Debug, Default)]
pub struct ReconcileStats {
    pub created: u32,
    pub updated: u32,
    pub deleted: u32,
    pub skipped: u32,
}
