use std::{net::IpAddr, time::Duration};

use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::Error;
use crate::state::{CloudflareMode, DnsEntry};
use crate::{ReconcileStats, Zones};

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
    zones: Zones,
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
    proxied: bool,
    ttl: u32,
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
        CloudflareMode::Address | CloudflareMode::DnsOnly => {
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
    pub fn new(
        token: &str,
        zone_id: &str,
        cname_target: &str,
        zones: &Zones,
    ) -> Result<Self, Error> {
        let mut headers = HeaderMap::new();
        let mut auth_value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|e| {
            Error::Cloudflare(format!("API token is not a valid header value: {e}"))
        })?;
        auth_value.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth_value);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = Client::builder().default_headers(headers).build()?;

        Ok(Self {
            client,
            zone_id: zone_id.to_owned(),
            base_url: "https://api.cloudflare.com/client/v4".to_owned(),
            cname_target: cname_target.to_owned(),
            zones: zones.clone(),
        })
    }

    /// Send a Cloudflare API request, deserialize the envelope, and check for errors.
    ///
    /// Returns `Ok(result)` on success (defaulting to `T::default()` if `result` is `null`).
    async fn send_cf<T: serde::de::DeserializeOwned + Default>(
        &self,
        req: reqwest::RequestBuilder,
        context: &str,
    ) -> Result<T, Error> {
        let resp: CloudflareResponse<T> = req.send().await?.json().await?;
        if resp.success {
            Ok(resp.result.unwrap_or_default())
        } else {
            Err(Error::Cloudflare(format!(
                "{context} failed: {}",
                format_errors(&resp.errors)
            )))
        }
    }

    /// List all records of a given type in the zone.
    async fn list_records_by_type(&self, record_type: &str) -> Result<Vec<DnsRecord>, Error> {
        let url = format!(
            "{}/zones/{}/dns_records?type={}&per_page=500",
            self.base_url, self.zone_id, record_type
        );
        self.send_cf(
            self.client.get(&url),
            &format!("list_records(type={record_type})"),
        )
        .await
    }

    /// Build the URL for a specific DNS record (update / delete).
    fn record_url(&self, record_id: &str) -> String {
        format!(
            "{}/zones/{}/dns_records/{record_id}",
            self.base_url, self.zone_id
        )
    }

    /// Create or update a DNS record. When `record_id` is `Some`, issues a PUT
    /// (update); otherwise issues a POST (create).
    async fn write_record(
        &self,
        record_id: Option<&str>,
        body: &CreateDnsRecord,
    ) -> Result<(), Error> {
        let (req, verb) = match record_id {
            Some(id) => (
                self.client.put(self.record_url(id)).json(body),
                "update_record",
            ),
            None => {
                let url = format!("{}/zones/{}/dns_records", self.base_url, self.zone_id);
                (self.client.post(&url).json(body), "create_record")
            }
        };
        self.send_cf::<serde_json::Value>(req, &format!("{verb}({})", body.name))
            .await
            .map(|_| ())
    }

    /// Delete a record by ID.
    async fn delete_record(&self, record_id: &str, hostname: &str) -> Result<(), Error> {
        let _: serde_json::Value = self
            .send_cf(
                self.client.delete(self.record_url(record_id)),
                &format!("delete_record({hostname})"),
            )
            .await?;
        Ok(())
    }

    /// Compare an existing record against the desired body, and create or update
    /// it if the record is absent or differs. Respects `dry_run` mode and bumps
    /// `stats` accordingly.
    async fn ensure_record(
        &self,
        existing: Option<&DnsRecord>,
        body: &CreateDnsRecord,
        dry_run: bool,
        record_label: &str,
        stats: &mut ReconcileStats,
    ) -> Result<(), Error> {
        match existing {
            Some(r)
                if r.content == body.content && r.ttl == body.ttl && r.proxied == body.proxied =>
            {
                // Record is already up to date.
                return Ok(());
            }
            Some(r) => {
                if dry_run {
                    info!(hostname = %body.name, "[dry-run] would update {record_label}");
                } else {
                    self.write_record(Some(&r.id), body).await?;
                    info!(hostname = %body.name, "updated {record_label}");
                }
                stats.updated += 1;
            }
            None => {
                if dry_run {
                    info!(hostname = %body.name, "[dry-run] would create {record_label}");
                } else {
                    self.write_record(None, body).await?;
                    info!(hostname = %body.name, "created {record_label}");
                }
                stats.created += 1;
            }
        }
        Ok(())
    }

    /// Delete orphaned records of a given type from the zone.
    async fn delete_orphans(
        &self,
        records: &[DnsRecord],
        accounted: &std::collections::HashSet<&str>,
        record_type: &str,
        dry_run: bool,
        extra_skip: Option<&str>,
    ) -> Result<u32, Error> {
        let mut deleted = 0;
        for record in records {
            let in_zone = record.name.ends_with(self.zones.managed_zone.as_str())
                || record.name == self.zones.zone;
            if !in_zone || accounted.contains(record.name.as_str()) {
                continue;
            }
            if let Some(skip) = extra_skip
                && record.name == skip
            {
                continue;
            }
            if dry_run {
                info!(
                    hostname = %record.name,
                    "[dry-run] would delete orphaned {record_type} record"
                );
            } else {
                self.delete_record(&record.id, &record.name).await?;
                info!(hostname = %record.name, "deleted orphaned Cloudflare {record_type} record");
            }
            deleted += 1;
        }
        Ok(deleted)
    }

    /// Reconcile desired DNS entries against Cloudflare's live state.
    ///
    /// CNAME model:
    /// 1. Ensure A record for `cname_target` with the WAN IP.
    /// 2. For each managed entry, ensure a CNAME (Proxied/DnsOnly) or A record (Address).
    /// 3. Delete orphaned `*.hr-home.xyz` records not in desired state.
    pub async fn reconcile(
        &self,
        entries: &[DnsEntry],
        wan_ip: IpAddr,
        dry_run: bool,
    ) -> Result<ReconcileStats, Error> {
        let a_records = self.list_records_by_type("A").await?;
        let cname_records = self.list_records_by_type("CNAME").await?;
        let mut stats = ReconcileStats::default();

        // --- Step 1: Ensure A record for cname_target ---
        let existing_a = a_records.iter().find(|r| r.name == self.cname_target);

        let wan_str = wan_ip.to_string();

        let body = CreateDnsRecord {
            record_type: "A".to_owned(),
            name: self.cname_target.clone(),
            content: wan_str.clone(),
            ttl: 300,
            proxied: false,
        };
        self.ensure_record(
            existing_a,
            &body,
            dry_run,
            "A record for CNAME target",
            &mut stats,
        )
        .await?;

        // --- Step 2: Ensure DNS records for managed services ---
        let a_by_name: std::collections::HashMap<&str, &DnsRecord> =
            a_records.iter().map(|r| (r.name.as_str(), r)).collect();
        let existing_by_name: std::collections::HashMap<&str, &DnsRecord> =
            cname_records.iter().map(|r| (r.name.as_str(), r)).collect();

        let mut accounted: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(entries.len());

        // The cname_target itself is managed as an A record, never a CNAME.
        accounted.insert(&self.cname_target);

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

            // Build the desired record body and look up the existing one.
            let (body, existing) = if entry.cloudflare_mode == CloudflareMode::Address {
                let b = CreateDnsRecord {
                    record_type: "A".to_owned(),
                    name: entry.hostname.clone(),
                    content: wan_str.clone(),
                    ttl: desired_ttl,
                    proxied: false,
                };
                (b, a_by_name.get(entry.hostname.as_str()).copied())
            } else {
                let desired_proxied = entry.cloudflare_mode == CloudflareMode::Proxied;
                let b = CreateDnsRecord {
                    record_type: "CNAME".to_owned(),
                    name: entry.hostname.clone(),
                    content: self.cname_target.clone(),
                    ttl: desired_ttl,
                    proxied: desired_proxied,
                };
                (b, existing_by_name.get(entry.hostname.as_str()).copied())
            };

            let label = if body.record_type == "A" {
                "A record"
            } else {
                "CNAME record"
            };
            self.ensure_record(existing, &body, dry_run, label, &mut stats)
                .await?;
        }

        // --- Step 3: Delete orphaned records ---
        stats.deleted += self
            .delete_orphans(&cname_records, &accounted, "CNAME", dry_run, None)
            .await?;
        stats.deleted += self
            .delete_orphans(
                &a_records,
                &accounted,
                "A",
                dry_run,
                Some(&self.cname_target),
            )
            .await?;

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

/// Build a [`DnsEntry`] for Cloudflare sync tests with caller-controlled
/// `managed` flag and proxy mode.
#[cfg(test)]
fn test_entry(hostname: &str, managed: bool, mode: CloudflareMode) -> DnsEntry {
    use crate::state::WanExpose;
    DnsEntry {
        hostname: hostname.to_owned(),
        lan_ip: "10.0.0.1".parse().unwrap(),
        macvlan_ip: None,
        managed,
        cloudflare_mode: mode,
        dns_ttl: Duration::from_secs(300),
        wan_expose: WanExpose::Skip,
        reconcile_interval: Duration::from_secs(300),
        source: format!("test/{hostname}"),
        unbound_alias_target: None,
    }
}

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
    fn compute_ttl_non_proxied_uses_configured_value() {
        // Both DnsOnly and Address pass through the configured TTL.
        for mode in [CloudflareMode::DnsOnly, CloudflareMode::Address] {
            assert_eq!(compute_ttl(&mode, Duration::from_secs(300)), 300);
        }
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

    /// Parse a JSON string into a `DnsRecord` and return it.
    fn parse_dns_record(json: &str) -> DnsRecord {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn dns_record_deserializes_a_record() {
        let record = parse_dns_record(
            r#"{"id":"abc123","name":"hr-main.hr-home.xyz","content":"1.2.3.4","ttl":300,"proxied":false,"type":"A"}"#,
        );
        assert_eq!(record.record_type, "A");
        assert_eq!(record.content, "1.2.3.4");
    }

    #[test]
    fn dns_record_deserializes_cname_record() {
        let record = parse_dns_record(
            r#"{"id":"def456","name":"plex.hr-home.xyz","content":"hr-main.hr-home.xyz","ttl":1,"proxied":true,"type":"CNAME"}"#,
        );
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
        let entries = [
            test_entry("managed.hr-home.xyz", true, CloudflareMode::Proxied),
            test_entry("skipped.hr-home.xyz", true, CloudflareMode::Skip),
            test_entry("unmanaged.hr-home.xyz", false, CloudflareMode::Proxied),
        ];

        let actionable: Vec<&DnsEntry> = entries
            .iter()
            .filter(|e| e.managed && e.cloudflare_mode != CloudflareMode::Skip)
            .collect();

        assert_eq!(actionable.len(), 1);
        assert_eq!(actionable[0].hostname, "managed.hr-home.xyz");
    }
}
