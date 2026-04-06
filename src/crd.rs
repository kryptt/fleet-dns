use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Spec for a CoreDnsPolicy custom resource.
///
/// Each CoreDnsPolicy declares a fragment of CoreDNS configuration that
/// fleet-dns reconciles into a ConfigMap key.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "fleet-dns.hr-home.xyz",
    version = "v1",
    kind = "CoreDnsPolicy",
    namespaced
)]
pub struct CoreDnsPolicySpec {
    /// "template" or "hosts"
    pub policy_type: String,

    /// DNS zone this policy applies to (e.g. "hr-home.xyz").
    pub zone: Option<String>,

    /// ConfigMap key name where this fragment is stored.
    pub key: String,

    /// Raw CoreDNS config fragment.
    pub content: String,
}

/// Spec for a DhcpReservation custom resource.
///
/// Each DhcpReservation binds a MAC address to a fixed IP and hostname,
/// so the DHCP server always hands out a predictable lease.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "fleet-dns.hr-home.xyz",
    version = "v1",
    kind = "DhcpReservation",
    namespaced
)]
pub struct DhcpReservationSpec {
    /// Hardware (MAC) address of the client.
    pub mac: String,

    /// IP address to assign.
    pub ip: String,

    /// Hostname to associate with this reservation.
    pub hostname: String,

    /// Optional human-readable description.
    pub description: Option<String>,
}

/// Spec for a DhcpConfig custom resource.
///
/// A DhcpConfig describes the parameters for a DHCP scope: the
/// dynamic range, gateway, DNS servers, lease duration, and any
/// sub-ranges that are carved out for other uses (e.g. Multus macvlan).
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "fleet-dns.hr-home.xyz",
    version = "v1",
    kind = "DhcpConfig",
    namespaced
)]
pub struct DhcpConfigSpec {
    /// First address in the dynamic DHCP range.
    pub range_start: String,

    /// Last address in the dynamic DHCP range.
    pub range_end: String,

    /// Default gateway advertised to clients.
    pub gateway: String,

    /// DNS servers advertised to clients.
    pub dns_servers: Vec<String>,

    /// Lease duration in seconds. Uses server default when absent.
    pub lease_time: Option<u32>,

    /// Ranges excluded from dynamic allocation (e.g. `["192.168.2.1-192.168.2.79"]`
    /// for addresses reserved by Multus macvlan).
    pub reserved_ranges: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn coredns_policy_crd_has_correct_group_and_kind() {
        let crd = CoreDnsPolicy::crd();
        assert_eq!(crd.spec.group, "fleet-dns.hr-home.xyz");
        assert_eq!(crd.spec.names.kind, "CoreDnsPolicy");
    }

    #[test]
    fn dhcp_reservation_crd_has_correct_group_and_kind() {
        let crd = DhcpReservation::crd();
        assert_eq!(crd.spec.group, "fleet-dns.hr-home.xyz");
        assert_eq!(crd.spec.names.kind, "DhcpReservation");
    }

    #[test]
    fn dhcp_config_crd_has_correct_group_and_kind() {
        let crd = DhcpConfig::crd();
        assert_eq!(crd.spec.group, "fleet-dns.hr-home.xyz");
        assert_eq!(crd.spec.names.kind, "DhcpConfig");
    }

    #[test]
    fn dhcp_reservation_spec_deserializes_all_fields() {
        let json = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.2.100",
            "hostname": "my-host",
            "description": "Living room AP"
        });
        let spec: DhcpReservationSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(spec.ip, "192.168.2.100");
        assert_eq!(spec.hostname, "my-host");
        assert_eq!(spec.description.as_deref(), Some("Living room AP"));
    }

    #[test]
    fn dhcp_reservation_spec_deserializes_without_description() {
        let json = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.2.101",
            "hostname": "kitchen-sensor"
        });
        let spec: DhcpReservationSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.hostname, "kitchen-sensor");
        assert!(spec.description.is_none());
    }
}
