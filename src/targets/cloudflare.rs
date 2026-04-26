use std::net::IpAddr;
use std::time::Duration;

use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::Error;
use crate::state::{CloudflareMode, DnsEntry};
use crate::{MANAGED_ZONE, ReconcileStats, ZONE};

/// Minimum TTL Cloudflare accepts for non-proxied records.
const MIN_TTL: u32 = 60;

/// Cloudflare uses TTL = 1 to mean "automatic" for proxied records.
const AUTO_TTL: u32 = 1;

/// Async client wrapping Cloudflare API v4 for DNS record CRUD.
///
/// Uses a CNAME model: one A record for `cname_target` holds the WAN IP,
/// all service hostnames are CNAMEs pointing to it.
pub struct CloudflareClient {
    client: Client,
    zone_id: String,
    base_url: String,
    cname_target: String,
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
    /// Wire type field; deserialized for tests but not read in production logic.
    #[allow(dead_code)]
    #[serde(rename = "type")]
    record_type: String,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Compute the TTL to send to Cloudflare.
///
/// Proxied records always use TTL = 1 ("Auto"). Non-proxied records use the
/// configured TTL, clamped to a minimum of 60 seconds.
#[must_use]
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
    ///
    /// `cname_target` is the hostname that holds the A record (e.g.,
    /// `hr-main.hr-home.xyz`). All service hostnames become CNAMEs
    /// pointing to it.
    pub fn new(token: &str, zone_id: &str, cname_target: &str) -> Self {
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
            cname_target: cname_target.to_owned(),
        }
    }

    /// List all records of a given type in the zone.
    async fn list_records_by_type(&self, record_type: &str) -> Result<Vec<DnsRecord>, Error> {
        let url = format!(
            "{}/zones/{}/dns_records?type={}&per_page=500",
            self.base_url, self.zone_id, record_type
        );

        let resp: CloudflareResponse<Vec<DnsRecord>> =
            self.client.get(&url).send().await?.json().await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "list_records(type={record_type}) failed: {}",
                format_errors(&resp.errors)
            )));
        }

        Ok(resp.result.unwrap_or_default())
    }

    /// Create a DNS record (A or CNAME).
    async fn create_record(&self, body: &CreateDnsRecord) -> Result<(), Error> {
        let url = format!("{}/zones/{}/dns_records", self.base_url, self.zone_id);

        let resp: CloudflareResponse<DnsRecord> = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "create_record({}) failed: {}",
                body.name,
                format_errors(&resp.errors)
            )));
        }

        Ok(())
    }

    /// Update an existing record by ID.
    async fn update_record(&self, record_id: &str, body: &CreateDnsRecord) -> Result<(), Error> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.base_url, self.zone_id, record_id
        );

        let resp: CloudflareResponse<DnsRecord> = self
            .client
            .put(&url)
            .json(body)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "update_record({}) failed: {}",
                body.name,
                format_errors(&resp.errors)
            )));
        }

        Ok(())
    }

    /// Delete a record by ID.
    async fn delete_record(&self, record_id: &str, hostname: &str) -> Result<(), Error> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.base_url, self.zone_id, record_id
        );

        let resp: CloudflareResponse<serde_json::Value> =
            self.client.delete(&url).send().await?.json().await?;

        if !resp.success {
            return Err(Error::Cloudflare(format!(
                "delete_record({hostname}) failed: {}",
                format_errors(&resp.errors)
            )));
        }

        Ok(())
    }

    /// Reconcile desired DNS entries against Cloudflare's live state.
    ///
    /// CNAME model:
    /// 1. Ensure A records for `cname_target` and `extra_a_records` with the WAN IP.
    /// 2. For each managed service hostname, ensure a CNAME -> `cname_target`.
    /// 3. Delete orphaned `*.hr-home.xyz` records not in desired state.
    pub async fn reconcile(
        &self,
        entries: &[DnsEntry],
        wan_ip: IpAddr,
        extra_a_records: &[String],
        dry_run: bool,
    ) -> Result<ReconcileStats, Error> {
        let a_records = self.list_records_by_type("A").await?;
        let cname_records = self.list_records_by_type("CNAME").await?;
        let mut stats = ReconcileStats::default();

        // --- Step 1: Ensure A record for cname_target ---
        let existing_a = a_records.iter().find(|r| r.name == self.cname_target);

        let wan_str = wan_ip.to_string();

        match existing_a {
            None => {
                let body = CreateDnsRecord {
                    record_type: "A".to_owned(),
                    name: self.cname_target.clone(),
                    content: wan_str.clone(),
                    ttl: 300,
                    proxied: false,
                };
                if dry_run {
                    info!(
                        hostname = %self.cname_target,
                        ip = %wan_ip,
                        "[dry-run] would create A record for CNAME target"
                    );
                } else {
                    self.create_record(&body).await?;
                    info!(
                        hostname = %self.cname_target,
                        ip = %wan_ip,
                        "created A record for CNAME target"
                    );
                }
                stats.created += 1;
            }
            Some(record) if record.content != wan_str => {
                let body = CreateDnsRecord {
                    record_type: "A".to_owned(),
                    name: self.cname_target.clone(),
                    content: wan_str.clone(),
                    ttl: 300,
                    proxied: false,
                };
                if dry_run {
                    info!(
                        hostname = %self.cname_target,
                        old_ip = %record.content,
                        new_ip = %wan_ip,
                        "[dry-run] would update A record for CNAME target"
                    );
                } else {
                    self.update_record(&record.id, &body).await?;
                    info!(
                        hostname = %self.cname_target,
                        old_ip = %record.content,
                        new_ip = %wan_ip,
                        "updated A record for CNAME target (WAN IP changed)"
                    );
                }
                stats.updated += 1;
            }
            Some(_) => {
                // A record exists with correct IP.
            }
        }

        // --- Step 1b: Ensure A records for extra hostnames (e.g. MX targets) ---
        let a_by_name: std::collections::HashMap<&str, &DnsRecord> =
            a_records.iter().map(|r| (r.name.as_str(), r)).collect();

        for extra in extra_a_records {
            match a_by_name.get(extra.as_str()) {
                None => {
                    let body = CreateDnsRecord {
                        record_type: "A".to_owned(),
                        name: extra.clone(),
                        content: wan_str.clone(),
                        ttl: 300,
                        proxied: false,
                    };
                    if dry_run {
                        info!(hostname = %extra, ip = %wan_ip, "[dry-run] would create extra A record");
                    } else {
                        self.create_record(&body).await?;
                        info!(hostname = %extra, ip = %wan_ip, "created extra A record");
                    }
                    stats.created += 1;
                }
                Some(record) if record.content != wan_str => {
                    let body = CreateDnsRecord {
                        record_type: "A".to_owned(),
                        name: extra.clone(),
                        content: wan_str.clone(),
                        ttl: 300,
                        proxied: false,
                    };
                    if dry_run {
                        info!(hostname = %extra, old_ip = %record.content, new_ip = %wan_ip, "[dry-run] would update extra A record");
                    } else {
                        self.update_record(&record.id, &body).await?;
                        info!(hostname = %extra, old_ip = %record.content, new_ip = %wan_ip, "updated extra A record (WAN IP changed)");
                    }
                    stats.updated += 1;
                }
                Some(_) => {}
            }
        }

        // --- Step 2: Ensure CNAME records for managed services ---
        let existing_by_name: std::collections::HashMap<&str, &DnsRecord> =
            cname_records.iter().map(|r| (r.name.as_str(), r)).collect();

        let mut accounted: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(entries.len());

        // The cname_target itself is managed as an A record, never a CNAME.
        accounted.insert(&self.cname_target);

        // Extra A records are also managed — prevent orphan deletion.
        for extra in extra_a_records {
            accounted.insert(extra);
        }

        for entry in entries {
            if !entry.managed {
                stats.skipped += 1;
                continue;
            }
            if entry.cloudflare_mode == CloudflareMode::Skip {
                stats.skipped += 1;
                continue;
            }
            // Don't create a CNAME for the cname_target itself.
            if entry.hostname == self.cname_target {
                continue;
            }

            accounted.insert(&entry.hostname);

            let desired_ttl = compute_ttl(&entry.cloudflare_mode, entry.dns_ttl);
            let desired_proxied = entry.cloudflare_mode == CloudflareMode::Proxied;

            match existing_by_name.get(entry.hostname.as_str()) {
                None => {
                    let body = CreateDnsRecord {
                        record_type: "CNAME".to_owned(),
                        name: entry.hostname.clone(),
                        content: self.cname_target.clone(),
                        ttl: desired_ttl,
                        proxied: desired_proxied,
                    };
                    if dry_run {
                        info!(
                            hostname = %entry.hostname,
                            target = %self.cname_target,
                            "[dry-run] would create CNAME record"
                        );
                    } else {
                        self.create_record(&body).await?;
                        info!(
                            hostname = %entry.hostname,
                            target = %self.cname_target,
                            "created Cloudflare CNAME record"
                        );
                    }
                    stats.created += 1;
                }
                Some(record)
                    if record.content != self.cname_target
                        || record.ttl != desired_ttl
                        || record.proxied != desired_proxied =>
                {
                    let body = CreateDnsRecord {
                        record_type: "CNAME".to_owned(),
                        name: entry.hostname.clone(),
                        content: self.cname_target.clone(),
                        ttl: desired_ttl,
                        proxied: desired_proxied,
                    };
                    if dry_run {
                        info!(
                            hostname = %entry.hostname,
                            old_target = %record.content,
                            "[dry-run] would update CNAME record"
                        );
                    } else {
                        self.update_record(&record.id, &body).await?;
                        info!(
                            hostname = %entry.hostname,
                            target = %self.cname_target,
                            "updated Cloudflare CNAME record"
                        );
                    }
                    stats.updated += 1;
                }
                Some(_) => {
                    // Record matches desired state.
                }
            }
        }

        // --- Step 3: Delete orphaned records ---
        // Delete orphaned CNAMEs in *.hr-home.xyz
        for record in &cname_records {
            let in_zone = record.name.ends_with(MANAGED_ZONE) || record.name == ZONE;
            if in_zone && !accounted.contains(record.name.as_str()) {
                if dry_run {
                    info!(
                        hostname = %record.name,
                        "[dry-run] would delete orphaned CNAME record"
                    );
                } else {
                    self.delete_record(&record.id, &record.name).await?;
                    info!(hostname = %record.name, "deleted orphaned Cloudflare CNAME record");
                }
                stats.deleted += 1;
            }
        }

        // Delete orphaned A records in *.hr-home.xyz (except cname_target)
        for record in &a_records {
            let in_zone = record.name.ends_with(MANAGED_ZONE) || record.name == ZONE;
            if in_zone
                && record.name != self.cname_target
                && !accounted.contains(record.name.as_str())
            {
                if dry_run {
                    info!(
                        hostname = %record.name,
                        "[dry-run] would delete orphaned A record"
                    );
                } else {
                    self.delete_record(&record.id, &record.name).await?;
                    info!(hostname = %record.name, "deleted orphaned Cloudflare A record");
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
        assert_eq!(
            compute_ttl(&CloudflareMode::Proxied, Duration::from_secs(300)),
            1
        );
        assert_eq!(
            compute_ttl(&CloudflareMode::Proxied, Duration::from_secs(0)),
            1
        );
    }

    #[test]
    fn compute_ttl_dns_only_uses_configured_value() {
        assert_eq!(
            compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(300)),
            300
        );
    }

    #[test]
    fn compute_ttl_dns_only_clamps_below_minimum() {
        assert_eq!(
            compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(30)),
            60
        );
        assert_eq!(
            compute_ttl(&CloudflareMode::DnsOnly, Duration::from_secs(0)),
            60
        );
    }

    #[test]
    fn compute_ttl_skip_returns_zero() {
        assert_eq!(
            compute_ttl(&CloudflareMode::Skip, Duration::from_secs(300)),
            0
        );
    }

    #[test]
    fn dns_record_deserializes_a_record() {
        let json = r#"{
            "id": "abc123", "name": "hr-main.hr-home.xyz",
            "content": "1.2.3.4", "ttl": 300, "proxied": false, "type": "A"
        }"#;
        let record: DnsRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.record_type, "A");
        assert_eq!(record.content, "1.2.3.4");
    }

    #[test]
    fn dns_record_deserializes_cname_record() {
        let json = r#"{
            "id": "def456", "name": "plex.hr-home.xyz",
            "content": "hr-main.hr-home.xyz", "ttl": 1, "proxied": true, "type": "CNAME"
        }"#;
        let record: DnsRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.record_type, "CNAME");
        assert_eq!(record.content, "hr-main.hr-home.xyz");
        assert!(record.proxied);
    }

    #[test]
    fn format_errors_produces_readable_string() {
        let errors = vec![
            CloudflareError {
                code: 1003,
                message: "Invalid zone".to_owned(),
            },
            CloudflareError {
                code: 9999,
                message: "Unknown".to_owned(),
            },
        ];
        assert_eq!(
            format_errors(&errors),
            "[1003] Invalid zone; [9999] Unknown"
        );
    }

    #[test]
    fn skip_and_unmanaged_entries_are_filtered() {
        use crate::state::WanExpose;

        let entries = [
            DnsEntry {
                hostname: "managed.hr-home.xyz".to_owned(),
                lan_ip: "10.0.0.1".parse().unwrap(),
                macvlan_ip: None,
                cloudflare_mode: CloudflareMode::Proxied,
                wan_expose: WanExpose::Skip,
                dns_ttl: Duration::from_secs(300),
                reconcile_interval: Duration::from_secs(300),
                managed: true,
                source: "test/managed".to_owned(),
                unbound_alias_target: None,
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
                unbound_alias_target: None,
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
                unbound_alias_target: None,
            },
        ];

        let actionable: Vec<&DnsEntry> = entries
            .iter()
            .filter(|e| e.managed && e.cloudflare_mode != CloudflareMode::Skip)
            .collect();

        assert_eq!(actionable.len(), 1);
        assert_eq!(actionable[0].hostname, "managed.hr-home.xyz");
    }
}
