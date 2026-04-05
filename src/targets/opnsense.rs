use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::Error;
use crate::state::{DnsEntry, Protocol, WanExpose};

/// Marker prefix embedded in OPNsense descriptions to identify fleet-dns-managed entries.
const MARKER_PREFIX: &str = "[fleet-dns:";

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

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Split an FQDN into `(host, domain)`.
///
/// Examples:
/// - `"plex.hr-home.xyz"` -> `("plex", "hr-home.xyz")`
/// - `"hr-home.xyz"` -> `("", "hr-home.xyz")`
/// - `"deep.sub.hr-home.xyz"` -> `("deep", "sub.hr-home.xyz")`
pub fn split_hostname(fqdn: &str) -> (&str, &str) {
    match fqdn.find('.') {
        Some(pos) => (&fqdn[..pos], &fqdn[pos + 1..]),
        None => ("", fqdn),
    }
}

/// Check whether a description string was created by fleet-dns.
pub fn is_fleet_dns_managed(description: &str) -> bool {
    description.starts_with(MARKER_PREFIX)
}

/// Extract the payload from a fleet-dns marker description.
///
/// `"[fleet-dns:plex.hr-home.xyz]"` -> `Some("plex.hr-home.xyz")`
/// `"[fleet-dns:plex.hr-home.xyz:32400/tcp]"` -> `Some("plex.hr-home.xyz:32400/tcp")`
/// `"manual entry"` -> `None`
pub fn extract_marker_payload(description: &str) -> Option<&str> {
    let rest = description.strip_prefix(MARKER_PREFIX)?;
    let payload = rest.strip_suffix(']')?;
    if payload.is_empty() {
        None
    } else {
        Some(payload)
    }
}

/// Build the Unbound description marker for a hostname.
fn unbound_marker(hostname: &str) -> String {
    format!("{MARKER_PREFIX}{hostname}]")
}

/// Build the NAT/firewall description marker for a port forward rule.
fn nat_marker(hostname: &str, port: u16, protocol: &Protocol) -> String {
    let proto = match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    format!("{MARKER_PREFIX}{hostname}:{port}/{proto}]")
}

// ---------------------------------------------------------------------------
// Unbound wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct UnboundSearchResponse {
    rows: Vec<UnboundHostOverride>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnboundHostOverride {
    pub uuid: String,
    pub hostname: String,
    pub domain: String,
    pub server: String,
    pub description: String,
    #[allow(dead_code)]
    pub enabled: String,
}

#[derive(Debug, Serialize)]
struct UnboundHostPayload {
    host: UnboundHostData,
}

#[derive(Debug, Serialize)]
struct UnboundHostData {
    enabled: String,
    hostname: String,
    domain: String,
    rr: String,
    server: String,
    description: String,
}

// ---------------------------------------------------------------------------
// Firewall / NAT wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct FirewallSearchResponse {
    rows: Vec<FirewallRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirewallRule {
    pub uuid: String,
    /// DNAT rules use `descr`, filter rules use `description`.
    /// Accept either via alias.
    #[serde(alias = "descr")]
    pub description: String,
}

#[derive(Debug, Deserialize)]
struct DnatSearchResponse {
    rows: Vec<DnatRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnatRule {
    pub uuid: String,
    pub descr: String,
}

#[derive(Debug, Serialize)]
struct DnatRulePayload {
    rule: DnatRuleData,
}

#[derive(Debug, Serialize)]
struct DnatRuleData {
    enabled: String,
    interface: String,
    protocol: String,
    src_net: String,
    src_port: String,
    dst_net: String,
    dst_port: String,
    target_ip: String,
    target_port: String,
    descr: String,
}

#[derive(Debug, Serialize)]
struct FilterRulePayload {
    rule: FilterRuleData,
}

#[derive(Debug, Serialize)]
struct FilterRuleData {
    enabled: String,
    action: String,
    interface: String,
    direction: String,
    protocol: String,
    src_net: String,
    dst_net: String,
    dst_port: String,
    description: String,
}

/// Generic OPNsense mutation response: `{"uuid":"..."}`.
#[derive(Debug, Deserialize)]
struct UuidResponse {
    uuid: Option<String>,
}

/// Response from savepoint: `{"revision":"..."}`.
#[derive(Debug, Deserialize)]
struct SavepointResponse {
    revision: Option<String>,
}

/// Response from /api/interfaces/overview/interfaces_info.
/// Paginated response with `rows` array.
#[derive(Debug, Deserialize)]
struct InterfacesInfoResponse {
    rows: Vec<InterfaceOverview>,
}

#[derive(Debug, Deserialize)]
struct InterfaceOverview {
    identifier: String,
    #[serde(default)]
    addr4: Option<String>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async client for the OPNsense API (Unbound + NAT/Firewall).
pub struct OpnSenseClient {
    client: Client,
    base_url: String,
    api_key: String,
    api_secret: String,
}

impl OpnSenseClient {
    /// Create a client with HTTP Basic Auth and TLS verification disabled
    /// (OPNsense typically uses a self-signed certificate).
    pub fn new(base_url: &str, api_key: &str, api_secret: &str) -> Result<Self, Error> {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(Error::Reqwest)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key: api_key.to_owned(),
            api_secret: api_secret.to_owned(),
        })
    }

    // -- Request helpers --

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(format!("{}{path}", self.base_url))
            .basic_auth(&self.api_key, Some(&self.api_secret))
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}{path}", self.base_url))
            .basic_auth(&self.api_key, Some(&self.api_secret))
    }

    // -----------------------------------------------------------------------
    // Unbound host overrides
    // -----------------------------------------------------------------------

    /// Search all host overrides, optionally filtering by description phrase.
    pub async fn search_host_overrides(&self) -> Result<Vec<UnboundHostOverride>, Error> {
        let body = serde_json::json!({"searchPhrase": MARKER_PREFIX});
        let resp = self
            .post("/api/unbound/settings/search_host_override")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "search_host_override returned {status}"
            )));
        }

        let parsed: UnboundSearchResponse = resp.json().await?;
        Ok(parsed.rows)
    }

    /// Create a new host override.
    pub async fn add_host_override(
        &self,
        hostname: &str,
        domain: &str,
        ip: &str,
        description: &str,
    ) -> Result<(), Error> {
        let body = UnboundHostPayload {
            host: UnboundHostData {
                enabled: "1".to_owned(),
                hostname: hostname.to_owned(),
                domain: domain.to_owned(),
                rr: "A".to_owned(),
                server: ip.to_owned(),
                description: description.to_owned(),
            },
        };

        let resp = self
            .post("/api/unbound/settings/add_host_override")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "add_host_override returned {status}"
            )));
        }

        Ok(())
    }

    /// Update an existing host override by UUID.
    pub async fn set_host_override(
        &self,
        uuid: &str,
        hostname: &str,
        domain: &str,
        ip: &str,
        description: &str,
    ) -> Result<(), Error> {
        let body = UnboundHostPayload {
            host: UnboundHostData {
                enabled: "1".to_owned(),
                hostname: hostname.to_owned(),
                domain: domain.to_owned(),
                rr: "A".to_owned(),
                server: ip.to_owned(),
                description: description.to_owned(),
            },
        };

        let resp = self
            .post(&format!("/api/unbound/settings/set_host_override/{uuid}"))
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "set_host_override({uuid}) returned {status}"
            )));
        }

        Ok(())
    }

    /// Delete a host override by UUID.
    pub async fn del_host_override(&self, uuid: &str) -> Result<(), Error> {
        let resp = self
            .post(&format!("/api/unbound/settings/del_host_override/{uuid}"))
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "del_host_override({uuid}) returned {status}"
            )));
        }

        Ok(())
    }

    /// Apply pending Unbound configuration changes.
    pub async fn unbound_reconfigure(&self) -> Result<(), Error> {
        let resp = self
            .post("/api/unbound/service/reconfigure")
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "unbound reconfigure returned {status}"
            )));
        }

        Ok(())
    }

    /// Reconcile Unbound host overrides to match the desired DNS entries.
    ///
    /// Only entries with `managed == true` are considered. The effective IP is
    /// `macvlan_ip` when present, otherwise `lan_ip`.
    pub async fn reconcile_unbound(
        &self,
        entries: &[DnsEntry],
        dry_run: bool,
    ) -> Result<ReconcileStats, Error> {
        let existing = self.search_host_overrides().await?;
        let mut stats = ReconcileStats::default();

        // Index existing fleet-dns overrides by their marker payload (the FQDN).
        let existing_by_marker: HashMap<&str, &UnboundHostOverride> = existing
            .iter()
            .filter_map(|o| {
                extract_marker_payload(&o.description).map(|payload| (payload, o))
            })
            .collect();

        let mut accounted: HashSet<String> = HashSet::with_capacity(entries.len());

        for entry in entries {
            if !entry.managed {
                stats.skipped += 1;
                continue;
            }

            let ip = entry.macvlan_ip.unwrap_or(entry.lan_ip);
            let (host, domain) = split_hostname(&entry.hostname);
            let marker = unbound_marker(&entry.hostname);

            accounted.insert(entry.hostname.clone());

            match existing_by_marker.get(entry.hostname.as_str()) {
                Some(override_entry) => {
                    // Check whether the IP has changed.
                    if override_entry.server != ip.to_string() {
                        if dry_run {
                            info!(
                                hostname = %entry.hostname,
                                old_ip = %override_entry.server,
                                new_ip = %ip,
                                "[dry-run] would update Unbound host override"
                            );
                        } else {
                            self.set_host_override(
                                &override_entry.uuid,
                                host,
                                domain,
                                &ip.to_string(),
                                &marker,
                            )
                            .await?;
                            info!(
                                hostname = %entry.hostname,
                                ip = %ip,
                                uuid = %override_entry.uuid,
                                "updated Unbound host override"
                            );
                        }
                        stats.updated += 1;
                    } else {
                        debug!(hostname = %entry.hostname, "Unbound override unchanged");
                    }
                }
                None => {
                    if dry_run {
                        info!(
                            hostname = %entry.hostname,
                            ip = %ip,
                            "[dry-run] would create Unbound host override"
                        );
                    } else {
                        self.add_host_override(host, domain, &ip.to_string(), &marker)
                            .await?;
                        info!(
                            hostname = %entry.hostname,
                            ip = %ip,
                            "created Unbound host override"
                        );
                    }
                    stats.created += 1;
                }
            }
        }

        // Delete orphaned overrides that fleet-dns manages but no longer desires.
        for override_entry in &existing {
            let payload = match extract_marker_payload(&override_entry.description) {
                Some(p) => p,
                None => continue,
            };

            if !accounted.contains(payload) {
                if dry_run {
                    info!(
                        hostname = payload,
                        uuid = %override_entry.uuid,
                        "[dry-run] would delete orphaned Unbound host override"
                    );
                } else {
                    self.del_host_override(&override_entry.uuid).await?;
                    info!(
                        hostname = payload,
                        uuid = %override_entry.uuid,
                        "deleted orphaned Unbound host override"
                    );
                }
                stats.deleted += 1;
            }
        }

        let mutated = stats.created > 0 || stats.updated > 0 || stats.deleted > 0;

        if mutated && !dry_run {
            self.unbound_reconfigure().await?;
            info!("Unbound reconfigured");
        }

        if mutated {
            info!(
                created = stats.created,
                updated = stats.updated,
                deleted = stats.deleted,
                skipped = stats.skipped,
                dry_run,
                "Unbound reconciliation complete"
            );
        }

        Ok(stats)
    }

    // -----------------------------------------------------------------------
    // NAT / Firewall
    // -----------------------------------------------------------------------

    /// Search all DNAT rules.
    pub async fn search_dnat_rules(&self) -> Result<Vec<FirewallRule>, Error> {
        let body = serde_json::json!({"searchPhrase": MARKER_PREFIX});
        let resp = self
            .post("/api/firewall/d_nat/search_rule")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "search_dnat_rule returned {status}"
            )));
        }

        // DNAT rules use `descr` instead of `description`.
        let parsed: DnatSearchResponse = resp.json().await?;
        Ok(parsed
            .rows
            .into_iter()
            .map(|r| FirewallRule {
                uuid: r.uuid,
                description: r.descr,
            })
            .collect())
    }

    /// Create a DNAT (port forward) rule. Returns the new rule's UUID.
    pub async fn add_dnat_rule(
        &self,
        target_ip: &str,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<String, Error> {
        let body = DnatRulePayload {
            rule: DnatRuleData {
                enabled: "1".to_owned(),
                interface: "wan".to_owned(),
                protocol: protocol.to_owned(),
                src_net: "any".to_owned(),
                src_port: "any".to_owned(),
                dst_net: "wanip".to_owned(),
                dst_port: port.to_string(),
                target_ip: target_ip.to_owned(),
                target_port: port.to_string(),
                descr: description.to_owned(),
            },
        };

        let resp = self
            .post("/api/firewall/d_nat/add_rule")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "add_dnat_rule returned {status}"
            )));
        }

        let parsed: UuidResponse = resp.json().await?;
        parsed.uuid.ok_or_else(|| {
            Error::OpnSense("add_dnat_rule response missing uuid".to_owned())
        })
    }

    /// Delete a DNAT rule by UUID.
    pub async fn del_dnat_rule(&self, uuid: &str) -> Result<(), Error> {
        let resp = self
            .post(&format!("/api/firewall/d_nat/del_rule/{uuid}"))
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "del_dnat_rule({uuid}) returned {status}"
            )));
        }

        Ok(())
    }

    /// Search all firewall filter rules.
    pub async fn search_filter_rules(&self) -> Result<Vec<FirewallRule>, Error> {
        let body = serde_json::json!({"searchPhrase": MARKER_PREFIX});
        let resp = self
            .post("/api/firewall/filter/search_rule")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "search_filter_rule returned {status}"
            )));
        }

        let parsed: FirewallSearchResponse = resp.json().await?;
        Ok(parsed.rows)
    }

    /// Create a firewall filter (allow) rule. Returns the new rule's UUID.
    pub async fn add_filter_rule(
        &self,
        target_ip: &str,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<String, Error> {
        let body = FilterRulePayload {
            rule: FilterRuleData {
                enabled: "1".to_owned(),
                action: "pass".to_owned(),
                interface: "wan".to_owned(),
                direction: "in".to_owned(),
                protocol: protocol.to_owned(),
                src_net: "any".to_owned(),
                dst_net: target_ip.to_owned(),
                dst_port: port.to_string(),
                description: description.to_owned(),
            },
        };

        let resp = self
            .post("/api/firewall/filter/add_rule")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "add_filter_rule returned {status}"
            )));
        }

        let parsed: UuidResponse = resp.json().await?;
        parsed.uuid.ok_or_else(|| {
            Error::OpnSense("add_filter_rule response missing uuid".to_owned())
        })
    }

    /// Delete a firewall filter rule by UUID.
    pub async fn del_filter_rule(&self, uuid: &str) -> Result<(), Error> {
        let resp = self
            .post(&format!("/api/firewall/filter/del_rule/{uuid}"))
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "del_filter_rule({uuid}) returned {status}"
            )));
        }

        Ok(())
    }

    /// Create a firewall savepoint for atomic apply with rollback.
    pub async fn firewall_savepoint(&self) -> Result<String, Error> {
        let resp = self
            .post("/api/firewall/d_nat/savepoint")
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "firewall savepoint returned {status}"
            )));
        }

        let parsed: SavepointResponse = resp.json().await?;
        parsed.revision.ok_or_else(|| {
            Error::OpnSense("savepoint response missing revision".to_owned())
        })
    }

    /// Apply pending firewall changes.
    pub async fn firewall_apply(&self) -> Result<(), Error> {
        let resp = self
            .post("/api/firewall/d_nat/apply")
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "firewall apply returned {status}"
            )));
        }

        Ok(())
    }

    /// Cancel rollback (confirm the savepoint), making changes permanent.
    pub async fn cancel_rollback(&self, savepoint: &str) -> Result<(), Error> {
        let resp = self
            .post(&format!("/api/firewall/d_nat/cancel_rollback/{savepoint}"))
            .json(&serde_json::json!({}))
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "cancel_rollback({savepoint}) returned {status}"
            )));
        }

        Ok(())
    }

    /// Retrieve the WAN IP address from OPNsense interfaces overview.
    pub async fn get_wan_ip(&self, interface: &str) -> Result<IpAddr, Error> {
        let resp = self
            .get("/api/interfaces/overview/interfaces_info")
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!(
                "interfaces_info returned {status}"
            )));
        }

        let parsed: InterfacesInfoResponse = resp.json().await?;
        let iface = parsed
            .rows
            .iter()
            .find(|r| r.identifier == interface)
            .ok_or_else(|| {
                Error::OpnSense(format!("interface {interface} not found in overview"))
            })?;

        let addr_str = iface.addr4.as_deref().ok_or_else(|| {
            Error::OpnSense(format!("interface {interface} has no IPv4 address"))
        })?;

        // Strip CIDR prefix if present (e.g., "188.142.71.248/32" -> "188.142.71.248")
        let bare = addr_str.split('/').next().unwrap_or(addr_str);

        bare.parse().map_err(|e| {
            Error::OpnSense(format!("failed to parse WAN IP '{addr_str}': {e}"))
        })
    }

    /// Reconcile NAT (DNAT + filter) rules for entries with WAN-exposed ports.
    ///
    /// Creates paired DNAT and filter rules for each desired port forward.
    /// Uses firewall savepoints for atomic apply with automatic rollback on
    /// verification failure.
    pub async fn reconcile_nat(
        &self,
        entries: &[DnsEntry],
        dry_run: bool,
    ) -> Result<ReconcileStats, Error> {
        let existing_dnat = self.search_dnat_rules().await?;
        let existing_filter = self.search_filter_rules().await?;
        let mut stats = ReconcileStats::default();

        // Index existing rules by their marker description.
        let dnat_by_desc: HashSet<&str> = existing_dnat
            .iter()
            .filter(|r| is_fleet_dns_managed(&r.description))
            .map(|r| r.description.as_str())
            .collect();

        let filter_by_desc: HashSet<&str> = existing_filter
            .iter()
            .filter(|r| is_fleet_dns_managed(&r.description))
            .map(|r| r.description.as_str())
            .collect();

        // Collect desired markers.
        let mut desired_markers: HashSet<String> = HashSet::new();

        for entry in entries {
            if !entry.managed {
                stats.skipped += 1;
                continue;
            }

            let ports = match &entry.wan_expose {
                WanExpose::Expose { ports } => ports,
                WanExpose::Skip => {
                    stats.skipped += 1;
                    continue;
                }
            };

            let target_ip = match entry.macvlan_ip {
                Some(ip) => ip,
                None => {
                    warn!(
                        hostname = %entry.hostname,
                        "WAN expose requested but no macvlan IP; skipping NAT rules"
                    );
                    stats.skipped += 1;
                    continue;
                }
            };

            for pf in ports {
                let marker = nat_marker(&entry.hostname, pf.port, &pf.protocol);
                desired_markers.insert(marker.clone());

                let proto_str = match pf.protocol {
                    Protocol::Tcp => "TCP",
                    Protocol::Udp => "UDP",
                };

                let dnat_exists = dnat_by_desc.contains(marker.as_str());
                let filter_exists = filter_by_desc.contains(marker.as_str());

                if dnat_exists && filter_exists {
                    debug!(
                        hostname = %entry.hostname,
                        port = pf.port,
                        protocol = proto_str,
                        "NAT rule pair already exists"
                    );
                    continue;
                }

                if dry_run {
                    info!(
                        hostname = %entry.hostname,
                        port = pf.port,
                        protocol = proto_str,
                        "[dry-run] would create NAT rule pair"
                    );
                } else {
                    if !dnat_exists {
                        let uuid = self
                            .add_dnat_rule(
                                &target_ip.to_string(),
                                pf.port,
                                proto_str,
                                &marker,
                            )
                            .await?;
                        info!(
                            hostname = %entry.hostname,
                            port = pf.port,
                            protocol = proto_str,
                            uuid = %uuid,
                            "created DNAT rule"
                        );
                    }

                    if !filter_exists {
                        let uuid = self
                            .add_filter_rule(
                                &target_ip.to_string(),
                                pf.port,
                                proto_str,
                                &marker,
                            )
                            .await?;
                        info!(
                            hostname = %entry.hostname,
                            port = pf.port,
                            protocol = proto_str,
                            uuid = %uuid,
                            "created filter rule"
                        );
                    }
                }
                stats.created += 1;
            }
        }

        // Delete orphaned DNAT rules.
        for rule in &existing_dnat {
            if is_fleet_dns_managed(&rule.description)
                && !desired_markers.contains(&rule.description)
            {
                if dry_run {
                    info!(
                        description = %rule.description,
                        uuid = %rule.uuid,
                        "[dry-run] would delete orphaned DNAT rule"
                    );
                } else {
                    self.del_dnat_rule(&rule.uuid).await?;
                    info!(
                        description = %rule.description,
                        uuid = %rule.uuid,
                        "deleted orphaned DNAT rule"
                    );
                }
                stats.deleted += 1;
            }
        }

        // Delete orphaned filter rules.
        for rule in &existing_filter {
            if is_fleet_dns_managed(&rule.description)
                && !desired_markers.contains(&rule.description)
            {
                if dry_run {
                    info!(
                        description = %rule.description,
                        uuid = %rule.uuid,
                        "[dry-run] would delete orphaned filter rule"
                    );
                } else {
                    self.del_filter_rule(&rule.uuid).await?;
                    info!(
                        description = %rule.description,
                        uuid = %rule.uuid,
                        "deleted orphaned filter rule"
                    );
                }
                stats.deleted += 1;
            }
        }

        // Apply firewall changes atomically with savepoint rollback protection.
        let mutated = stats.created > 0 || stats.deleted > 0;

        if mutated && !dry_run {
            let savepoint = self.firewall_savepoint().await?;
            info!(revision = %savepoint, "firewall savepoint created");

            self.firewall_apply().await?;
            info!("firewall changes applied");

            // Verify rules exist by re-searching.
            let verify_dnat = self.search_dnat_rules().await?;
            let verify_filter = self.search_filter_rules().await?;

            let dnat_ok = desired_markers.iter().all(|m| {
                verify_dnat.iter().any(|r| r.description == *m)
            });
            let filter_ok = desired_markers.iter().all(|m| {
                verify_filter.iter().any(|r| r.description == *m)
            });

            if dnat_ok && filter_ok {
                self.cancel_rollback(&savepoint).await?;
                info!(revision = %savepoint, "firewall savepoint confirmed");
            } else {
                warn!(
                    revision = %savepoint,
                    "firewall verification failed; savepoint will auto-revert"
                );
                return Err(Error::OpnSense(
                    "firewall rule verification failed after apply".to_owned(),
                ));
            }
        }

        if mutated {
            info!(
                created = stats.created,
                deleted = stats.deleted,
                skipped = stats.skipped,
                dry_run,
                "NAT reconciliation complete"
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
    fn split_hostname_subdomain() {
        assert_eq!(split_hostname("plex.hr-home.xyz"), ("plex", "hr-home.xyz"));
    }

    #[test]
    fn split_hostname_bare_domain() {
        assert_eq!(split_hostname("hr-home.xyz"), ("hr-home", "xyz"));
    }

    #[test]
    fn split_hostname_deep_subdomain() {
        assert_eq!(
            split_hostname("deep.sub.hr-home.xyz"),
            ("deep", "sub.hr-home.xyz")
        );
    }

    #[test]
    fn split_hostname_no_dot() {
        assert_eq!(split_hostname("localhost"), ("", "localhost"));
    }

    #[test]
    fn is_fleet_dns_managed_positive() {
        assert!(is_fleet_dns_managed("[fleet-dns:plex.hr-home.xyz]"));
    }

    #[test]
    fn is_fleet_dns_managed_negative() {
        assert!(!is_fleet_dns_managed("manual entry"));
    }

    #[test]
    fn is_fleet_dns_managed_empty() {
        assert!(!is_fleet_dns_managed(""));
    }

    #[test]
    fn extract_marker_payload_hostname() {
        assert_eq!(
            extract_marker_payload("[fleet-dns:plex.hr-home.xyz]"),
            Some("plex.hr-home.xyz")
        );
    }

    #[test]
    fn extract_marker_payload_port_forward() {
        assert_eq!(
            extract_marker_payload("[fleet-dns:plex.hr-home.xyz:32400/tcp]"),
            Some("plex.hr-home.xyz:32400/tcp")
        );
    }

    #[test]
    fn extract_marker_payload_not_managed() {
        assert_eq!(extract_marker_payload("manual entry"), None);
    }

    #[test]
    fn extract_marker_payload_empty_payload() {
        assert_eq!(extract_marker_payload("[fleet-dns:]"), None);
    }

    #[test]
    fn extract_marker_payload_no_closing_bracket() {
        assert_eq!(extract_marker_payload("[fleet-dns:plex.hr-home.xyz"), None);
    }

    #[test]
    fn unbound_marker_format() {
        assert_eq!(
            unbound_marker("plex.hr-home.xyz"),
            "[fleet-dns:plex.hr-home.xyz]"
        );
    }

    #[test]
    fn nat_marker_tcp() {
        assert_eq!(
            nat_marker("plex.hr-home.xyz", 32400, &Protocol::Tcp),
            "[fleet-dns:plex.hr-home.xyz:32400/tcp]"
        );
    }

    #[test]
    fn nat_marker_udp() {
        assert_eq!(
            nat_marker("hass.hr-home.xyz", 5353, &Protocol::Udp),
            "[fleet-dns:hass.hr-home.xyz:5353/udp]"
        );
    }

    #[test]
    fn reconcile_stats_default_is_all_zeros() {
        let stats = ReconcileStats::default();
        assert_eq!(stats.created, 0);
        assert_eq!(stats.updated, 0);
        assert_eq!(stats.deleted, 0);
        assert_eq!(stats.skipped, 0);
    }

    #[test]
    fn unbound_host_override_deserializes() {
        let json = r#"{
            "uuid": "abc-123",
            "hostname": "plex",
            "domain": "hr-home.xyz",
            "server": "192.168.2.52",
            "description": "[fleet-dns:plex.hr-home.xyz]",
            "enabled": "1"
        }"#;

        let parsed: UnboundHostOverride =
            serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.uuid, "abc-123");
        assert_eq!(parsed.hostname, "plex");
        assert_eq!(parsed.domain, "hr-home.xyz");
        assert_eq!(parsed.server, "192.168.2.52");
        assert!(is_fleet_dns_managed(&parsed.description));
    }

    #[test]
    fn firewall_rule_deserializes() {
        let json = r#"{
            "uuid": "def-456",
            "description": "[fleet-dns:plex.hr-home.xyz:32400/tcp]"
        }"#;

        let parsed: FirewallRule = serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.uuid, "def-456");
        assert!(is_fleet_dns_managed(&parsed.description));
    }

    #[test]
    fn unbound_search_response_deserializes() {
        let json = r#"{
            "rows": [
                {
                    "uuid": "abc-123",
                    "hostname": "plex",
                    "domain": "hr-home.xyz",
                    "server": "192.168.2.52",
                    "description": "[fleet-dns:plex.hr-home.xyz]",
                    "enabled": "1"
                }
            ]
        }"#;

        let parsed: UnboundSearchResponse =
            serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.rows.len(), 1);
    }

    #[test]
    fn firewall_search_response_deserializes() {
        let json = r#"{
            "rows": [
                {
                    "uuid": "def-456",
                    "description": "[fleet-dns:plex.hr-home.xyz:32400/tcp]"
                }
            ]
        }"#;

        let parsed: FirewallSearchResponse =
            serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.rows.len(), 1);
    }
}
