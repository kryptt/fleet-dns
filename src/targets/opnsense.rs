use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::crd::DhcpConfigSpec;
use crate::error::Error;
use crate::state::{DnsEntry, Protocol, WanExpose};
use crate::{ReconcileStats, ZONE};

/// Marker prefix embedded in OPNsense descriptions to identify fleet-dns-managed entries.
const MARKER_PREFIX: &str = "[fleet-dns:";

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/// Split an FQDN into `(host, domain)`.
///
/// Examples:
/// - `"plex.hr-home.xyz"` -> `("plex", "hr-home.xyz")`
/// - `"hr-home.xyz"` -> `("", "hr-home.xyz")`
/// - `"deep.sub.hr-home.xyz"` -> `("deep", "sub.hr-home.xyz")`
#[must_use]
pub fn split_hostname(fqdn: &str) -> (&str, &str) {
    match fqdn.find('.') {
        Some(pos) => (&fqdn[..pos], &fqdn[pos + 1..]),
        None => ("", fqdn),
    }
}

/// Check whether a description string was created by fleet-dns.
#[must_use]
pub fn is_fleet_dns_managed(description: &str) -> bool {
    description.starts_with(MARKER_PREFIX)
}

/// Extract the payload from a fleet-dns marker description.
///
/// `"[fleet-dns:plex.hr-home.xyz]"` -> `Some("plex.hr-home.xyz")`
/// `"[fleet-dns:plex.hr-home.xyz:32400/tcp]"` -> `Some("plex.hr-home.xyz:32400/tcp")`
/// `"manual entry"` -> `None`
#[must_use]
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

/// Build the Dnsmasq DHCP host description marker for a hostname.
fn dnsmasq_host_marker(hostname: &str) -> String {
    format!("{MARKER_PREFIX}dhcp:{hostname}]")
}

/// Extract the hostname from a `[fleet-dns:dhcp:{hostname}]` marker.
///
/// Returns `None` if the string is not a valid DHCP host marker.
fn extract_dhcp_hostname(descr: &str) -> Option<&str> {
    let rest = descr.strip_prefix("[fleet-dns:dhcp:")?;
    let hostname = rest.strip_suffix(']')?;
    if hostname.is_empty() { None } else { Some(hostname) }
}

/// Build the Dnsmasq DHCP range description marker.
fn dnsmasq_range_marker() -> String {
    format!("{MARKER_PREFIX}dhcp-range]")
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
    #[serde(default)]
    pub target: String,
    #[serde(default, rename = "local-port")]
    pub local_port: String,
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
    source: DnatEndpoint,
    destination: DnatEndpoint,
    target: String,
    #[serde(rename = "local-port")]
    local_port: String,
    descr: String,
}

#[derive(Debug, Serialize)]
struct DnatEndpoint {
    network: String,
    port: String,
    not: String,
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

// ---------------------------------------------------------------------------
// Dnsmasq DHCP wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DnsmasqHostSearchResponse {
    rows: Vec<DnsmasqHost>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsmasqHost {
    pub uuid: String,
    pub host: String,
    pub domain: String,
    pub ip: String,
    pub hwaddr: String,
    pub descr: String,
}

#[derive(Debug, Serialize)]
struct DnsmasqHostPayload {
    host: DnsmasqHostData,
}

#[derive(Debug, Serialize)]
struct DnsmasqHostData {
    host: String,
    domain: String,
    ip: String,
    hwaddr: String,
    descr: String,
}

// ---------------------------------------------------------------------------
// Dnsmasq DHCP range wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DnsmasqRangeSearchResponse {
    rows: Vec<DnsmasqRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsmasqRange {
    pub uuid: String,
    pub start_addr: String,
    pub end_addr: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
struct DnsmasqRangePayload {
    range: DnsmasqRangeData,
}

#[derive(Debug, Serialize)]
struct DnsmasqRangeData {
    interface: String,
    start_addr: String,
    end_addr: String,
    lease_time: String,
    domain: String,
    description: String,
}

// ---------------------------------------------------------------------------
// IP validation (pure, testable)
// ---------------------------------------------------------------------------

/// Parse an IPv4 address string into its four octets.
///
/// Returns `None` for anything that is not a valid dotted-quad.
#[must_use]
pub fn parse_ipv4_octets(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a = parts[0].parse::<u8>().ok()?;
    let b = parts[1].parse::<u8>().ok()?;
    let c = parts[2].parse::<u8>().ok()?;
    let d = parts[3].parse::<u8>().ok()?;
    Some([a, b, c, d])
}

/// Convert four octets to a `u32` for range comparisons.
#[must_use]
pub fn octets_to_u32(octets: [u8; 4]) -> u32 {
    u32::from_be_bytes(octets)
}

/// Validate that reserved ranges and static reservation IPs do not overlap
/// with the dynamic DHCP pool.
///
/// Returns a list of human-readable conflict descriptions. An empty vec
/// means no conflicts were found.
#[must_use]
pub fn validate_ip_allocation(
    reserved_ranges: &[String],
    reservation_ips: &[String],
    pool_start: &str,
    pool_end: &str,
) -> Vec<String> {
    let mut conflicts = Vec::new();

    let ps = match parse_ipv4_octets(pool_start) {
        Some(o) => octets_to_u32(o),
        None => {
            conflicts.push(format!("Invalid pool start address: {pool_start}"));
            return conflicts;
        }
    };
    let pe = match parse_ipv4_octets(pool_end) {
        Some(o) => octets_to_u32(o),
        None => {
            conflicts.push(format!("Invalid pool end address: {pool_end}"));
            return conflicts;
        }
    };

    for range_str in reserved_ranges {
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() != 2 {
            conflicts.push(format!("Malformed reserved range: {range_str}"));
            continue;
        }

        let rs = match parse_ipv4_octets(parts[0]) {
            Some(o) => octets_to_u32(o),
            None => {
                conflicts.push(format!("Invalid start IP in reserved range: {}", parts[0]));
                continue;
            }
        };
        let re = match parse_ipv4_octets(parts[1]) {
            Some(o) => octets_to_u32(o),
            None => {
                conflicts.push(format!("Invalid end IP in reserved range: {}", parts[1]));
                continue;
            }
        };

        // Two ranges overlap when neither is entirely before or after the other.
        if rs <= pe && re >= ps {
            conflicts.push(format!(
                "Reserved range {range_str} overlaps with DHCP pool {pool_start}-{pool_end}"
            ));
        }
    }

    for ip_str in reservation_ips {
        let ip = match parse_ipv4_octets(ip_str) {
            Some(o) => octets_to_u32(o),
            None => {
                conflicts.push(format!("Invalid reservation IP: {ip_str}"));
                continue;
            }
        };

        if ip >= ps && ip <= pe {
            conflicts.push(format!(
                "Reservation {ip_str} falls inside DHCP pool {pool_start}-{pool_end}"
            ));
        }
    }

    conflicts
}

/// A desired DHCP host reservation for reconciliation.
pub struct DhcpHostEntry {
    pub hostname: String,
    pub ip: String,
    pub mac: String,
}

// ---------------------------------------------------------------------------
// Generic OPNsense response types
// ---------------------------------------------------------------------------

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

    /// POST JSON to `path`, check for a success status, and deserialize the response.
    ///
    /// `context` is used in the error message on failure (e.g. `"add_host_override"`).
    async fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        context: &str,
    ) -> Result<R, Error> {
        let resp = self.post(path).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!("{context} returned {status}")));
        }
        Ok(resp.json().await?)
    }

    /// POST JSON to `path`, check for a success status, and discard the response body.
    ///
    /// `context` is used in the error message on failure.
    async fn post_json_ok<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        context: &str,
    ) -> Result<(), Error> {
        let resp = self.post(path).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Error::OpnSense(format!("{context} returned {status}")));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Unbound host overrides
    // -----------------------------------------------------------------------

    /// Search all host overrides, filtering by the fleet-dns marker prefix.
    pub async fn search_host_overrides(&self) -> Result<Vec<UnboundHostOverride>, Error> {
        let body = serde_json::json!({"searchPhrase": MARKER_PREFIX});
        let parsed: UnboundSearchResponse = self
            .post_json(
                "/api/unbound/settings/search_host_override",
                &body,
                "search_host_override",
            )
            .await?;
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
        self.post_json_ok(
            "/api/unbound/settings/add_host_override",
            &body,
            "add_host_override",
        )
        .await
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
        self.post_json_ok(
            &format!("/api/unbound/settings/set_host_override/{uuid}"),
            &body,
            &format!("set_host_override({uuid})"),
        )
        .await
    }

    /// Delete a host override by UUID.
    pub async fn del_host_override(&self, uuid: &str) -> Result<(), Error> {
        self.post_json_ok(
            &format!("/api/unbound/settings/del_host_override/{uuid}"),
            &serde_json::json!({}),
            &format!("del_host_override({uuid})"),
        )
        .await
    }

    /// Apply pending Unbound configuration changes.
    pub async fn unbound_reconfigure(&self) -> Result<(), Error> {
        self.post_json_ok(
            "/api/unbound/service/reconfigure",
            &serde_json::json!({}),
            "unbound reconfigure",
        )
        .await
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
    // Dnsmasq DHCP host reservations
    // -----------------------------------------------------------------------

    /// Search all Dnsmasq hosts managed by fleet-dns.
    pub async fn search_dnsmasq_hosts(&self) -> Result<Vec<DnsmasqHost>, Error> {
        let body = serde_json::json!({"searchPhrase": "[fleet-dns:dhcp:"});
        let parsed: DnsmasqHostSearchResponse = self
            .post_json("/api/dnsmasq/settings/searchHost", &body, "searchHost")
            .await?;
        Ok(parsed.rows)
    }

    /// Create a new Dnsmasq DHCP host reservation.
    pub async fn add_dnsmasq_host(
        &self,
        hostname: &str,
        domain: &str,
        ip: &str,
        mac: &str,
        description: &str,
    ) -> Result<(), Error> {
        let body = DnsmasqHostPayload {
            host: DnsmasqHostData {
                host: hostname.to_owned(),
                domain: domain.to_owned(),
                ip: ip.to_owned(),
                hwaddr: mac.to_owned(),
                descr: description.to_owned(),
            },
        };
        self.post_json_ok("/api/dnsmasq/settings/addHost", &body, "addHost")
            .await
    }

    /// Update an existing Dnsmasq DHCP host reservation by UUID.
    pub async fn set_dnsmasq_host(
        &self,
        uuid: &str,
        hostname: &str,
        domain: &str,
        ip: &str,
        mac: &str,
        description: &str,
    ) -> Result<(), Error> {
        let body = DnsmasqHostPayload {
            host: DnsmasqHostData {
                host: hostname.to_owned(),
                domain: domain.to_owned(),
                ip: ip.to_owned(),
                hwaddr: mac.to_owned(),
                descr: description.to_owned(),
            },
        };
        self.post_json_ok(
            &format!("/api/dnsmasq/settings/setHost/{uuid}"),
            &body,
            &format!("setHost({uuid})"),
        )
        .await
    }

    /// Delete a Dnsmasq DHCP host reservation by UUID.
    pub async fn del_dnsmasq_host(&self, uuid: &str) -> Result<(), Error> {
        self.post_json_ok(
            &format!("/api/dnsmasq/settings/delHost/{uuid}"),
            &serde_json::json!({}),
            &format!("delHost({uuid})"),
        )
        .await
    }

    /// Apply pending Dnsmasq configuration changes.
    pub async fn dnsmasq_reconfigure(&self) -> Result<(), Error> {
        self.post_json_ok(
            "/api/dnsmasq/service/reconfigure",
            &serde_json::json!({}),
            "dnsmasq reconfigure",
        )
        .await
    }

    /// Reconcile Dnsmasq DHCP host reservations to match desired entries.
    ///
    /// Each entry produces a reservation with marker `[fleet-dns:dhcp:{hostname}]`.
    /// Domain is always `hr-home.xyz`.
    pub async fn reconcile_dnsmasq_hosts(
        &self,
        reservations: &[DhcpHostEntry],
        dry_run: bool,
    ) -> Result<ReconcileStats, Error> {
        let existing = self.search_dnsmasq_hosts().await?;
        let mut stats = ReconcileStats::default();

        // Index existing fleet-dns DHCP hosts by their marker hostname.
        let existing_by_hostname: HashMap<&str, &DnsmasqHost> = existing
            .iter()
            .filter_map(|h| extract_dhcp_hostname(&h.descr).map(|name| (name, h)))
            .collect();

        let mut accounted: HashSet<&str> = HashSet::with_capacity(reservations.len());

        for entry in reservations {
            let marker = dnsmasq_host_marker(&entry.hostname);
            let (host, domain) = split_hostname(&entry.hostname);

            accounted.insert(&entry.hostname);

            match existing_by_hostname.get(entry.hostname.as_str()) {
                Some(existing_host) => {
                    let ip_changed = existing_host.ip != entry.ip;
                    let mac_changed = existing_host.hwaddr != entry.mac;

                    if ip_changed || mac_changed {
                        if dry_run {
                            info!(
                                hostname = %entry.hostname,
                                old_ip = %existing_host.ip,
                                new_ip = %entry.ip,
                                old_mac = %existing_host.hwaddr,
                                new_mac = %entry.mac,
                                "[dry-run] would update Dnsmasq DHCP host"
                            );
                        } else {
                            self.set_dnsmasq_host(
                                &existing_host.uuid,
                                host,
                                domain,
                                &entry.ip,
                                &entry.mac,
                                &marker,
                            )
                            .await?;
                            info!(
                                hostname = %entry.hostname,
                                ip = %entry.ip,
                                mac = %entry.mac,
                                uuid = %existing_host.uuid,
                                "updated Dnsmasq DHCP host"
                            );
                        }
                        stats.updated += 1;
                    } else {
                        debug!(hostname = %entry.hostname, "Dnsmasq DHCP host unchanged");
                    }
                }
                None => {
                    if dry_run {
                        info!(
                            hostname = %entry.hostname,
                            ip = %entry.ip,
                            mac = %entry.mac,
                            "[dry-run] would create Dnsmasq DHCP host"
                        );
                    } else {
                        self.add_dnsmasq_host(
                            host,
                            domain,
                            &entry.ip,
                            &entry.mac,
                            &marker,
                        )
                        .await?;
                        info!(
                            hostname = %entry.hostname,
                            ip = %entry.ip,
                            mac = %entry.mac,
                            "created Dnsmasq DHCP host"
                        );
                    }
                    stats.created += 1;
                }
            }
        }

        // Delete orphaned DHCP hosts that fleet-dns manages but no longer desires.
        for host in &existing {
            let hostname = match extract_dhcp_hostname(&host.descr) {
                Some(h) => h,
                None => continue,
            };

            if !accounted.contains(hostname) {
                if dry_run {
                    info!(
                        hostname = hostname,
                        uuid = %host.uuid,
                        "[dry-run] would delete orphaned Dnsmasq DHCP host"
                    );
                } else {
                    self.del_dnsmasq_host(&host.uuid).await?;
                    info!(
                        hostname = hostname,
                        uuid = %host.uuid,
                        "deleted orphaned Dnsmasq DHCP host"
                    );
                }
                stats.deleted += 1;
            }
        }

        let mutated = stats.created > 0 || stats.updated > 0 || stats.deleted > 0;

        if mutated && !dry_run {
            self.dnsmasq_reconfigure().await?;
            info!("Dnsmasq reconfigured");
        }

        if mutated {
            info!(
                created = stats.created,
                updated = stats.updated,
                deleted = stats.deleted,
                dry_run,
                "Dnsmasq DHCP reconciliation complete"
            );
        }

        Ok(stats)
    }

    // -----------------------------------------------------------------------
    // Dnsmasq DHCP ranges
    // -----------------------------------------------------------------------

    /// Search all Dnsmasq DHCP ranges.
    pub async fn search_dnsmasq_ranges(&self) -> Result<Vec<DnsmasqRange>, Error> {
        let body = serde_json::json!({"searchPhrase": MARKER_PREFIX});
        let parsed: DnsmasqRangeSearchResponse = self
            .post_json("/api/dnsmasq/settings/searchRange", &body, "searchRange")
            .await?;
        Ok(parsed.rows)
    }

    /// Create a new Dnsmasq DHCP range.
    pub async fn add_dnsmasq_range(
        &self,
        start: &str,
        end: &str,
        interface: &str,
        lease_time: &str,
        description: &str,
    ) -> Result<(), Error> {
        let body = DnsmasqRangePayload {
            range: DnsmasqRangeData {
                interface: interface.to_owned(),
                start_addr: start.to_owned(),
                end_addr: end.to_owned(),
                lease_time: lease_time.to_owned(),
                domain: ZONE.to_owned(),
                description: description.to_owned(),
            },
        };
        self.post_json_ok("/api/dnsmasq/settings/addRange", &body, "addRange")
            .await
    }

    /// Update an existing Dnsmasq DHCP range by UUID.
    pub async fn set_dnsmasq_range(
        &self,
        uuid: &str,
        start: &str,
        end: &str,
        interface: &str,
        lease_time: &str,
        description: &str,
    ) -> Result<(), Error> {
        let body = DnsmasqRangePayload {
            range: DnsmasqRangeData {
                interface: interface.to_owned(),
                start_addr: start.to_owned(),
                end_addr: end.to_owned(),
                lease_time: lease_time.to_owned(),
                domain: ZONE.to_owned(),
                description: description.to_owned(),
            },
        };
        self.post_json_ok(
            &format!("/api/dnsmasq/settings/setRange/{uuid}"),
            &body,
            &format!("setRange({uuid})"),
        )
        .await
    }

    /// Reconcile the Dnsmasq DHCP range to match the desired config.
    ///
    /// Uses marker `[fleet-dns:dhcp-range]` to identify the managed range.
    /// Creates or updates the range from `config.range_start`/`range_end`.
    /// Calls `dnsmasq_reconfigure()` after any mutation.
    pub async fn reconcile_dnsmasq_range(
        &self,
        config: &DhcpConfigSpec,
        dry_run: bool,
    ) -> Result<ReconcileStats, Error> {
        let existing = self.search_dnsmasq_ranges().await?;
        let mut stats = ReconcileStats::default();
        let marker = dnsmasq_range_marker();

        let lease_time = config
            .lease_time
            .map_or_else(|| "3600".to_owned(), |s| s.to_string());

        // Find the existing fleet-dns-managed range, if any.
        let managed = existing
            .iter()
            .find(|r| r.description == marker);

        // Default interface for the LAN DHCP scope.
        let interface = "lan";

        match managed {
            Some(range) => {
                let start_changed = range.start_addr != config.range_start;
                let end_changed = range.end_addr != config.range_end;

                if start_changed || end_changed {
                    if dry_run {
                        info!(
                            old_start = %range.start_addr,
                            old_end = %range.end_addr,
                            new_start = %config.range_start,
                            new_end = %config.range_end,
                            "[dry-run] would update Dnsmasq DHCP range"
                        );
                    } else {
                        self.set_dnsmasq_range(
                            &range.uuid,
                            &config.range_start,
                            &config.range_end,
                            interface,
                            &lease_time,
                            &marker,
                        )
                        .await?;
                        info!(
                            start = %config.range_start,
                            end = %config.range_end,
                            uuid = %range.uuid,
                            "updated Dnsmasq DHCP range"
                        );
                    }
                    stats.updated += 1;
                } else {
                    debug!("Dnsmasq DHCP range unchanged");
                }
            }
            None => {
                if dry_run {
                    info!(
                        start = %config.range_start,
                        end = %config.range_end,
                        "[dry-run] would create Dnsmasq DHCP range"
                    );
                } else {
                    self.add_dnsmasq_range(
                        &config.range_start,
                        &config.range_end,
                        interface,
                        &lease_time,
                        &marker,
                    )
                    .await?;
                    info!(
                        start = %config.range_start,
                        end = %config.range_end,
                        "created Dnsmasq DHCP range"
                    );
                }
                stats.created += 1;
            }
        }

        let mutated = stats.created > 0 || stats.updated > 0;

        if mutated && !dry_run {
            self.dnsmasq_reconfigure().await?;
            info!("Dnsmasq reconfigured after range update");
        }

        if mutated {
            info!(
                created = stats.created,
                updated = stats.updated,
                dry_run,
                "Dnsmasq DHCP range reconciliation complete"
            );
        }

        Ok(stats)
    }

    // -----------------------------------------------------------------------
    // NAT / Firewall
    // -----------------------------------------------------------------------

    /// Search all DNAT rules.
    pub async fn search_dnat_rules(&self) -> Result<Vec<DnatRule>, Error> {
        let body = serde_json::json!({"searchPhrase": MARKER_PREFIX});
        let parsed: DnatSearchResponse = self
            .post_json("/api/firewall/d_nat/search_rule", &body, "search_dnat_rule")
            .await?;
        Ok(parsed.rows)
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
                source: DnatEndpoint {
                    network: "any".to_owned(),
                    port: "any".to_owned(),
                    not: "0".to_owned(),
                },
                destination: DnatEndpoint {
                    network: "wanip".to_owned(),
                    port: port.to_string(),
                    not: "0".to_owned(),
                },
                target: target_ip.to_owned(),
                local_port: port.to_string(),
                descr: description.to_owned(),
            },
        };
        let parsed: UuidResponse = self
            .post_json("/api/firewall/d_nat/add_rule", &body, "add_dnat_rule")
            .await?;
        parsed.uuid.ok_or_else(|| {
            Error::OpnSense("add_dnat_rule response missing uuid".to_owned())
        })
    }

    /// Delete a DNAT rule by UUID.
    pub async fn del_dnat_rule(&self, uuid: &str) -> Result<(), Error> {
        self.post_json_ok(
            &format!("/api/firewall/d_nat/del_rule/{uuid}"),
            &serde_json::json!({}),
            &format!("del_dnat_rule({uuid})"),
        )
        .await
    }

    /// Search all firewall filter rules.
    pub async fn search_filter_rules(&self) -> Result<Vec<FirewallRule>, Error> {
        let body = serde_json::json!({"searchPhrase": MARKER_PREFIX});
        let parsed: FirewallSearchResponse = self
            .post_json(
                "/api/firewall/filter/search_rule",
                &body,
                "search_filter_rule",
            )
            .await?;
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
        let parsed: UuidResponse = self
            .post_json("/api/firewall/filter/add_rule", &body, "add_filter_rule")
            .await?;
        parsed.uuid.ok_or_else(|| {
            Error::OpnSense("add_filter_rule response missing uuid".to_owned())
        })
    }

    /// Delete a firewall filter rule by UUID.
    pub async fn del_filter_rule(&self, uuid: &str) -> Result<(), Error> {
        self.post_json_ok(
            &format!("/api/firewall/filter/del_rule/{uuid}"),
            &serde_json::json!({}),
            &format!("del_filter_rule({uuid})"),
        )
        .await
    }

    /// Create a firewall savepoint for atomic apply with rollback.
    pub async fn firewall_savepoint(&self) -> Result<String, Error> {
        let parsed: SavepointResponse = self
            .post_json(
                "/api/firewall/d_nat/savepoint",
                &serde_json::json!({}),
                "firewall savepoint",
            )
            .await?;
        parsed.revision.ok_or_else(|| {
            Error::OpnSense("savepoint response missing revision".to_owned())
        })
    }

    /// Apply pending firewall changes.
    pub async fn firewall_apply(&self) -> Result<(), Error> {
        self.post_json_ok(
            "/api/firewall/d_nat/apply",
            &serde_json::json!({}),
            "firewall apply",
        )
        .await
    }

    /// Cancel rollback (confirm the savepoint), making changes permanent.
    pub async fn cancel_rollback(&self, savepoint: &str) -> Result<(), Error> {
        self.post_json_ok(
            &format!("/api/firewall/d_nat/cancel_rollback/{savepoint}"),
            &serde_json::json!({}),
            &format!("cancel_rollback({savepoint})"),
        )
        .await
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

        // Index existing DNAT rules by description, keeping target+port for comparison.
        let dnat_by_desc: HashMap<&str, &DnatRule> = existing_dnat
            .iter()
            .filter(|r| is_fleet_dns_managed(&r.descr))
            .map(|r| (r.descr.as_str(), r))
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

                let mut dnat_exists = false;
                if let Some(existing) = dnat_by_desc.get(marker.as_str()) {
                    let target_str = target_ip.to_string();
                    let port_str = pf.port.to_string();
                    if existing.target == target_str && existing.local_port == port_str {
                        dnat_exists = true;
                    } else {
                        // Target or port changed — delete stale rule so it gets recreated.
                        warn!(
                            hostname = %entry.hostname,
                            port = pf.port,
                            old_target = %existing.target,
                            new_target = %target_str,
                            "DNAT rule has stale target; replacing"
                        );
                        if !dry_run {
                            self.del_dnat_rule(&existing.uuid).await?;
                        }
                    }
                }
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
            if is_fleet_dns_managed(&rule.descr)
                && !desired_markers.contains(&rule.descr)
            {
                if dry_run {
                    info!(
                        description = %rule.descr,
                        uuid = %rule.uuid,
                        "[dry-run] would delete orphaned DNAT rule"
                    );
                } else {
                    self.del_dnat_rule(&rule.uuid).await?;
                    info!(
                        description = %rule.descr,
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
                verify_dnat.iter().any(|r| r.descr == *m)
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

    #[test]
    fn dnsmasq_host_marker_format() {
        assert_eq!(
            dnsmasq_host_marker("plex.hr-home.xyz"),
            "[fleet-dns:dhcp:plex.hr-home.xyz]"
        );
    }

    #[test]
    fn dnsmasq_host_deserializes() {
        let json = r#"{
            "uuid": "dhcp-001",
            "host": "plex",
            "domain": "hr-home.xyz",
            "ip": "192.168.2.52",
            "hwaddr": "aa:bb:cc:dd:ee:ff",
            "descr": "[fleet-dns:dhcp:plex.hr-home.xyz]"
        }"#;

        let parsed: DnsmasqHost =
            serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.uuid, "dhcp-001");
        assert_eq!(parsed.host, "plex");
        assert_eq!(parsed.domain, "hr-home.xyz");
        assert_eq!(parsed.ip, "192.168.2.52");
        assert_eq!(parsed.hwaddr, "aa:bb:cc:dd:ee:ff");
        assert!(parsed.descr.starts_with("[fleet-dns:dhcp:"));
    }

    #[test]
    fn dnsmasq_host_search_response_deserializes() {
        let json = r#"{
            "rows": [
                {
                    "uuid": "dhcp-001",
                    "host": "plex",
                    "domain": "hr-home.xyz",
                    "ip": "192.168.2.52",
                    "hwaddr": "aa:bb:cc:dd:ee:ff",
                    "descr": "[fleet-dns:dhcp:plex.hr-home.xyz]"
                }
            ]
        }"#;

        let parsed: DnsmasqHostSearchResponse =
            serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.rows.len(), 1);
    }

    // -- DHCP range tests --

    #[test]
    fn dnsmasq_range_marker_format() {
        assert_eq!(dnsmasq_range_marker(), "[fleet-dns:dhcp-range]");
    }

    #[test]
    fn dnsmasq_range_deserializes() {
        let json = r#"{
            "uuid": "range-001",
            "start_addr": "192.168.2.80",
            "end_addr": "192.168.2.245",
            "description": "[fleet-dns:dhcp-range]"
        }"#;

        let parsed: DnsmasqRange =
            serde_json::from_str(json).expect("should deserialize");
        assert_eq!(parsed.uuid, "range-001");
        assert_eq!(parsed.start_addr, "192.168.2.80");
        assert_eq!(parsed.end_addr, "192.168.2.245");
        assert_eq!(parsed.description, "[fleet-dns:dhcp-range]");
    }

    // -- IP validation tests --

    #[test]
    fn validate_ip_allocation_no_conflicts() {
        let conflicts = validate_ip_allocation(
            &["192.168.2.1-192.168.2.79".to_owned()],
            &["192.168.2.250".to_owned()],
            "192.168.2.80",
            "192.168.2.245",
        );
        assert!(conflicts.is_empty(), "expected no conflicts: {conflicts:?}");
    }

    #[test]
    fn validate_ip_allocation_reservation_inside_pool() {
        let conflicts = validate_ip_allocation(
            &[],
            &["192.168.2.100".to_owned()],
            "192.168.2.80",
            "192.168.2.245",
        );
        assert_eq!(conflicts.len(), 1);
        assert!(
            conflicts[0].contains("192.168.2.100"),
            "should mention the conflicting IP: {}",
            conflicts[0]
        );
        assert!(
            conflicts[0].contains("falls inside DHCP pool"),
            "should describe the conflict: {}",
            conflicts[0]
        );
    }

    #[test]
    fn validate_ip_allocation_reserved_range_overlaps_pool() {
        let conflicts = validate_ip_allocation(
            &["192.168.2.70-192.168.2.90".to_owned()],
            &[],
            "192.168.2.80",
            "192.168.2.245",
        );
        assert_eq!(conflicts.len(), 1);
        assert!(
            conflicts[0].contains("overlaps"),
            "should describe an overlap: {}",
            conflicts[0]
        );
    }

    #[test]
    fn validate_ip_allocation_reservation_outside_pool() {
        let conflicts = validate_ip_allocation(
            &[],
            &["192.168.2.250".to_owned(), "192.168.2.10".to_owned()],
            "192.168.2.80",
            "192.168.2.245",
        );
        assert!(conflicts.is_empty(), "expected no conflicts: {conflicts:?}");
    }

    #[test]
    fn validate_ip_allocation_empty_inputs() {
        let conflicts = validate_ip_allocation(
            &[],
            &[],
            "192.168.2.80",
            "192.168.2.245",
        );
        assert!(conflicts.is_empty(), "expected no conflicts: {conflicts:?}");
    }
}
