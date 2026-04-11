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

/// Spec for an OidcApplication custom resource.
///
/// Declares a Zitadel OIDC application and its corresponding Traefik
/// Middleware. Fleet-dns syncs redirect URIs from IngressRoutes labeled
/// with `hr-home.xyz/oidc: "<name>"` and manages the Zitadel app +
/// Traefik Middleware lifecycle.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "fleet-dns.hr-home.xyz",
    version = "v1",
    kind = "OidcApplication",
    namespaced,
    status = "OidcApplicationStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct OidcApplicationSpec {
    /// Zitadel project name (resolved to project ID at runtime).
    pub project_name: String,

    /// Name of the OIDC application in Zitadel.
    pub app_name: String,

    /// Traefik Middleware configuration.
    pub middleware: OidcMiddlewareSpec,

    /// Extra redirect URIs beyond those auto-synced from IngressRoutes
    /// (e.g. Postman OAuth callback).
    #[serde(default)]
    pub extra_redirect_uris: Vec<String>,
}

/// Configuration for the Traefik OIDC Middleware that fleet-dns manages.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OidcMiddlewareSpec {
    /// Middleware resource name.
    pub name: String,

    /// Namespace for the Middleware resource.
    pub namespace: String,

    /// OIDC scopes to request (e.g. `["openid", "profile", "email"]`).
    pub scopes: Vec<String>,
}

/// Status of an OidcApplication, updated by fleet-dns after reconciliation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct OidcApplicationStatus {
    /// Zitadel project ID (resolved from `project_name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    /// Zitadel OIDC application ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,

    /// OIDC client ID (used in the Traefik Middleware).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// Redirect URIs last synced to Zitadel.
    #[serde(default)]
    pub synced_redirect_uris: Vec<String>,

    /// ISO 8601 timestamp of the last successful sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced: Option<String>,
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
    fn oidc_application_crd_has_correct_group_and_kind() {
        let crd = OidcApplication::crd();
        assert_eq!(crd.spec.group, "fleet-dns.hr-home.xyz");
        assert_eq!(crd.spec.names.kind, "OidcApplication");
    }

    #[test]
    fn oidc_application_spec_deserializes() {
        let json = serde_json::json!({
            "projectName": "Home Services",
            "appName": "system-oidc",
            "middleware": {
                "name": "system-oidc",
                "namespace": "ingress",
                "scopes": ["openid", "profile", "email"]
            },
            "extraRedirectUris": ["https://oauth.pstmn.io/v1/callback"]
        });
        let spec: OidcApplicationSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.project_name, "Home Services");
        assert_eq!(spec.app_name, "system-oidc");
        assert_eq!(spec.middleware.name, "system-oidc");
        assert_eq!(spec.middleware.namespace, "ingress");
        assert_eq!(spec.middleware.scopes, vec!["openid", "profile", "email"]);
        assert_eq!(spec.extra_redirect_uris, vec!["https://oauth.pstmn.io/v1/callback"]);
    }

    #[test]
    fn oidc_application_spec_deserializes_without_extras() {
        let json = serde_json::json!({
            "projectName": "Home",
            "appName": "test-oidc",
            "middleware": {
                "name": "test-oidc",
                "namespace": "ingress",
                "scopes": ["openid"]
            }
        });
        let spec: OidcApplicationSpec = serde_json::from_value(json).unwrap();
        assert!(spec.extra_redirect_uris.is_empty());
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
