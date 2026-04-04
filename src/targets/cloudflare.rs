use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::Error;
use crate::state::{CloudflareMode, DnsEntry};

/// DNS zone suffix used to identify managed records for cleanup.
const MANAGED_ZONE: &str = ".hr-home.xyz";

/// Minimum TTL Cloudflare accepts for non-proxied records.
const MIN_TTL: u32 = 60;

/// Cloudflare uses TTL = 1 to mean "automatic" for proxied records.
const AUTO_TTL: u32 = 1;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Statistics from a single reconciliation pass.
#[derive(Debug, Default)]
pub struct ReconcileStats {
    pub created: u32,
    pub updated: u32,
    pub deleted: u32,
    pub skipped: u32,
}

/// Async client wrapping Cloudflare API v4 for DNS record CRUD.
pub struct CloudflareClient {
    client: Client,
    zone_id: String,
    base_url: String,
}

// ---------------------------------------------------------------------------
// Wire types (serde)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CreateDnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    result: Option<T>,
    errors: Vec<CloudflareError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
    #[serde(rename = "type")]
    #[allow(dead_code)] // Deserialized for completeness; not read in application logic.
    record_type: String,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Compute the TTL to send to Cloudflare.
///
/// Proxied records always use TTL = 1 ("Auto"). Non-proxied records use the
/// configured TTL, clamped to a minimum of 60 seconds.
pub fn compute_ttl(mode: &CloudflareMode, ttl: Duration) -> u32 {
    match mode {
        CloudflareMode::Proxied => AUTO_TTL,
        CloudflareMode::DnsOnly => {
            let secs = ttl.as_secs() as u32;
            secs.max(MIN_TTL)
        }
        CloudflareMode::Skip => 0, // caller should never send Skip entries
    }
}

/// Format Cloudflare API errors into a single string.
fn format_errors(errors: &[CloudflareError]) -> String {
    errors
        .iter()
        .map(|e| format!("[{}] {}", e.code, e.message))
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// CloudflareClient
// ---------------------------------------------------------------------------

impl CloudflareClient {
    /// Create a new client authenticated with a Cloudflare API token.
    pub fn new(token: &str, zone_id: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .expect("API token must be valid ASCII"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            zone_id: zone_id.to_owned(),
            base_url: "https://api.cloudflare.com/client/v4".to_owned(),
        }
    }

    /// List all A records in the zone.
    async fn list_records(&self) -> Result<Vec<DnsRecord>, Error> {
        let url = format!(
            "{}/zones/{}/dns_records?type=A&per_page=500",
            self.base_url, self.zone_id
        );

        let resp: CloudflareResponse<Vec<DnsRecord>> =
            self.client.get(&url).send().await?.json().await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "list_records failed: {}",
                format_errors(&resp.errors)
            )));
        }

        Ok(resp.result.unwrap_or_default())
    }

    /// Create an A record for the given entry.
    pub async fn create_record(
        &self,
        entry: &DnsEntry,
        wan_ip: IpAddr,
    ) -> Result<(), Error> {
        let url = format!(
            "{}/zones/{}/dns_records",
            self.base_url, self.zone_id
        );

        let proxied = entry.cloudflare_mode == CloudflareMode::Proxied;
        let body = CreateDnsRecord {
            record_type: "A".to_owned(),
            name: entry.hostname.clone(),
            content: wan_ip.to_string(),
            ttl: compute_ttl(&entry.cloudflare_mode, entry.dns_ttl),
            proxied,
        };

        let resp: CloudflareResponse<DnsRecord> = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "create_record({}) failed: {}",
                entry.hostname,
                format_errors(&resp.errors)
            )));
        }

        info!(hostname = %entry.hostname, ip = %wan_ip, "created Cloudflare A record");
        Ok(())
    }

    /// Update an existing A record by ID.
    pub async fn update_record(
        &self,
        record_id: &str,
        entry: &DnsEntry,
        wan_ip: IpAddr,
    ) -> Result<(), Error> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.base_url, self.zone_id, record_id
        );

        let proxied = entry.cloudflare_mode == CloudflareMode::Proxied;
        let body = CreateDnsRecord {
            record_type: "A".to_owned(),
            name: entry.hostname.clone(),
            content: wan_ip.to_string(),
            ttl: compute_ttl(&entry.cloudflare_mode, entry.dns_ttl),
            proxied,
        };

        let resp: CloudflareResponse<DnsRecord> = self
            .client
            .put(&url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "update_record({}) failed: {}",
                entry.hostname,
                format_errors(&resp.errors)
            )));
        }

        info!(
            hostname = %entry.hostname,
            ip = %wan_ip,
            record_id,
            "updated Cloudflare A record"
        );
        Ok(())
    }

    /// Delete an A record by ID.
    pub async fn delete_record(
        &self,
        record_id: &str,
        hostname: &str,
    ) -> Result<(), Error> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.base_url, self.zone_id, record_id
        );

        let resp: CloudflareResponse<serde_json::Value> =
            self.client.delete(&url).send().await?.json().await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "delete_record({}) failed: {}",
                hostname,
                format_errors(&resp.errors)
            )));
        }

        info!(hostname, record_id, "deleted Cloudflare A record");
        Ok(())
    }

    /// Reconcile desired DNS entries against Cloudflare's live state.
    ///
    /// 1. List existing A records in the zone.
    /// 2. For each desired entry where `managed == true` and mode is not `Skip`:
    ///    - Create if no matching record exists.
    ///    - Update if the record differs in IP, TTL, or proxied state.
    /// 3. Delete existing `*.hr-home.xyz` records not present in desired state.
    /// 4. If `dry_run`, log intended actions without executing mutations.
    pub async fn reconcile(
        &self,
        entries: &[DnsEntry],
        wan_ip: IpAddr,
        dry_run: bool,
    ) -> Result<ReconcileStats, Error> {
        let existing = self.list_records().await?;
        let mut stats = ReconcileStats::default();

        // Index existing records by hostname for O(1) lookup.
        let existing_by_name: std::collections::HashMap<&str, &DnsRecord> = existing
            .iter()
            .map(|r| (r.name.as_str(), r))
            .collect();

        // Track hostnames that the desired state accounts for, so we know
        // which existing records are orphaned.
        let mut accounted: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(entries.len());

        for entry in entries {
            if !entry.managed {
                stats.skipped += 1;
                continue;
            }

            if entry.cloudflare_mode == CloudflareMode::Skip {
                stats.skipped += 1;
                continue;
            }

            accounted.insert(&entry.hostname);

            let desired_ttl = compute_ttl(&entry.cloudflare_mode, entry.dns_ttl);
            let desired_proxied = entry.cloudflare_mode == CloudflareMode::Proxied;
            let desired_ip = wan_ip.to_string();

            match existing_by_name.get(entry.hostname.as_str()) {
                None => {
                    if dry_run {
                        info!(
                            hostname = %entry.hostname,
                            ip = %wan_ip,
                            "[dry-run] would create A record"
                        );
                    } else {
                        self.create_record(entry, wan_ip).await?;
                    }
                    stats.created += 1;
                }
                Some(record)
                    if record.content != desired_ip
                        || record.ttl != desired_ttl
                        || record.proxied != desired_proxied =>
                {
                    if dry_run {
                        info!(
                            hostname = %entry.hostname,
                            old_ip = %record.content,
                            new_ip = %wan_ip,
                            old_ttl = record.ttl,
                            new_ttl = desired_ttl,
                            "[dry-run] would update A record"
                        );
                    } else {
                        self.update_record(&record.id, entry, wan_ip).await?;
                    }
                    stats.updated += 1;
                }
                Some(_) => {
                    // Record matches desired state exactly.
                }
            }
        }

        // Delete orphaned records within the managed zone.
        for record in &existing {
            let in_zone = record.name.ends_with(MANAGED_ZONE)
                || record.name == "hr-home.xyz";

            if in_zone && !accounted.contains(record.name.as_str()) {
                if dry_run {
                    info!(
                        hostname = %record.name,
                        record_id = %record.id,
                        "[dry-run] would delete orphaned A record"
                    );
                } else {
                    self.delete_record(&record.id, &record.name).await?;
                }
                stats.deleted += 1;
            }
        }

        if stats.created > 0 || stats.updated > 0 || stats.deleted > 0 {
            info!(
                created = stats.created,
                updated = stats.updated,
                deleted = stats.deleted,
                skipped = stats.skipped,
                dry_run,
                "Cloudflare reconciliation complete"
            );
        }

        Ok(stats)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_stats_default_is_all_zeros() {
        let stats = ReconcileStats::default();
        assert_eq!(stats.created, 0);
        assert_eq!(stats.updated, 0);
        assert_eq!(stats.deleted, 0);
        assert_eq!(stats.skipped, 0);
    }

    #[test]
    fn compute_ttl_proxied_returns_auto() {
        assert_eq!(compute_ttl(&CloudflareMode::Proxied, Duration::from_secs(300)), 1);
        assert_eq!(compute_ttl(&CloudflareMode::Proxied, Duration::from_secs(0)), 1);
    }

    #[test]
    fn compute_ttl_dns_only_uses_configured_value() {
        assert_eq!(compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(300)), 300);
        assert_eq!(compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(3600)), 3600);
    }

    #[test]
    fn compute_ttl_dns_only_clamps_below_minimum() {
        assert_eq!(compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(30)), 60);
        assert_eq!(compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(0)), 60);
        assert_eq!(compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(59)), 60);
    }

    #[test]
    fn compute_ttl_dns_only_at_boundary() {
        assert_eq!(compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(60)), 60);
        assert_eq!(compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(61)), 61);
    }

    #[test]
    fn compute_ttl_skip_returns_zero() {
        assert_eq!(compute_ttl(&CloudflareMode::Skip, Duration::from_secs(300)), 0);
    }

    #[test]
    fn dns_record_deserializes_from_sample_json() {
        let json = r#"{
            "id": "abc123",
            "name": "app.hr-home.xyz",
            "content": "1.2.3.4",
            "ttl": 300,
            "proxied": true,
            "type": "A"
        }"#;

        let record: DnsRecord = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(record.id, "abc123");
        assert_eq!(record.name, "app.hr-home.xyz");
        assert_eq!(record.content, "1.2.3.4");
        assert_eq!(record.ttl, 300);
        assert!(record.proxied);
        assert_eq!(record.record_type, "A");
    }

    #[test]
    fn dns_record_deserializes_non_proxied() {
        let json = r#"{
            "id": "def456",
            "name": "hass.hr-home.xyz",
            "content": "5.6.7.8",
            "ttl": 120,
            "proxied": false,
            "type": "A"
        }"#;

        let record: DnsRecord = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(record.id, "def456");
        assert!(!record.proxied);
        assert_eq!(record.ttl, 120);
    }

    #[test]
    fn cloudflare_response_deserializes_success() {
        let json = r#"{
            "success": true,
            "result": [
                {
                    "id": "rec1",
                    "name": "test.hr-home.xyz",
                    "content": "1.1.1.1",
                    "ttl": 1,
                    "proxied": true,
                    "type": "A"
                }
            ],
            "errors": []
        }"#;

        let resp: CloudflareResponse<Vec<DnsRecord>> =
            serde_json::from_str(json).expect("should deserialize");
        assert!(resp.success);
        assert_eq!(resp.result.unwrap().len(), 1);
        assert!(resp.errors.is_empty());
    }

    #[test]
    fn cloudflare_response_deserializes_error() {
        let json = r#"{
            "success": false,
            "result": null,
            "errors": [
                { "code": 1003, "message": "Invalid or missing zone id." }
            ]
        }"#;

        let resp: CloudflareResponse<Vec<DnsRecord>> =
            serde_json::from_str(json).expect("should deserialize");
        assert!(!resp.success);
        assert!(resp.result.is_none());
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].code, 1003);
    }

    #[test]
    fn format_errors_produces_readable_string() {
        let errors = vec![
            CloudflareError { code: 1003, message: "Invalid zone".to_owned() },
            CloudflareError { code: 9999, message: "Unknown".to_owned() },
        ];
        let formatted = format_errors(&errors);
        assert_eq!(formatted, "[1003] Invalid zone; [9999] Unknown");
    }

    /// Verify that entries with `CloudflareMode::Skip` are excluded from
    /// the desired set during reconciliation filtering.
    #[test]
    fn skip_entries_are_filtered() {
        use crate::state::WanExpose;

        let entries = vec![
            DnsEntry {
                hostname: "proxied.hr-home.xyz".to_owned(),
                lan_ip: "10.0.0.1".parse().unwrap(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "test/proxied".to_owned(),
            },
            DnsEntry {
                hostname: "skipped.hr-home.xyz".to_owned(),
                lan_ip: "10.0.0.2".parse().unwrap(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Skip,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "test/skipped".to_owned(),
            },
            DnsEntry {
                hostname: "unmanaged.hr-home.xyz".to_owned(),
                lan_ip: "10.0.0.3".parse().unwrap(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: false,
                source: "test/unmanaged".to_owned(),
            },
        ];

        // Simulate the filtering logic from reconcile without HTTP calls.
        let actionable: Vec<&DnsEntry> = entries
            .iter()
            .filter(|e| e.managed && e.cloudflare_mode != CloudflareMode::Skip)
            .collect();

        assert_eq!(actionable.len(), 1);
        assert_eq!(actionable[0].hostname, "proxied.hr-home.xyz");
    }
}
