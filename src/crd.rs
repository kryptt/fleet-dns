use crate::crd_prelude::*;

macro_rules! fleet_crd {
    ($(#[doc = $doc:expr])* kind = $kind:literal, struct $name:ident { $($body:tt)* }) => {
        $(#[doc = $doc])*
        #[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
        #[kube(group = "fleet-dns.hr-home.xyz", version = "v1", kind = $kind, namespaced)]
        pub struct $name { $($body)* }
    };
}

fleet_crd! {
    /// Spec for a CoreDnsPolicy custom resource.
    ///
    /// Each CoreDnsPolicy declares a fragment of CoreDNS configuration that
    /// fleet-dns reconciles into a ConfigMap key.
    kind = "CoreDnsPolicy",
    struct CoreDnsPolicySpec {
    /// "template" or "hosts"
    pub policy_type: String,

    /// DNS zone this policy applies to (e.g. "hr-home.xyz"). Takes precedence
    /// over `org` when both are set.
    pub zone: Option<String>,

    /// Organization whose DNS zone this policy applies to. An alternative to
    /// spelling the zone out in `zone`; ignored when `zone` is set. Absent
    /// from both means a non-zone policy, which gets its own ConfigMap key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,

    /// ConfigMap key name where this fragment is stored.
    pub key: String,

    /// Raw CoreDNS config fragment.
    pub content: String,
}
}

fleet_crd! {
    /// Spec for a DhcpReservation custom resource.
    ///
    /// Each DhcpReservation binds a MAC address to a fixed IP and hostname,
    /// so the DHCP server always hands out a predictable lease.
    kind = "DhcpReservation",
    struct DhcpReservationSpec {
    /// Hardware (MAC) address of the client.
    pub mac: String,

    /// IP address to assign.
    pub ip: String,

    /// Hostname to associate with this reservation.
    pub hostname: String,

    /// Organization whose DNS zone this reservation's bare hostname belongs
    /// to. Absent means the default organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,

    /// Optional human-readable description.
    pub description: Option<String>,
}
}

fleet_crd! {
    /// Spec for a DhcpConfig custom resource.
    ///
    /// A DhcpConfig describes the parameters for a DHCP scope: the
    /// dynamic range, gateway, DNS servers, lease duration, and any
    /// sub-ranges that are carved out for other uses (e.g. Multus macvlan).
    kind = "DhcpConfig",
    struct DhcpConfigSpec {
    /// Organization whose DNS zone this DHCP scope advertises as its domain.
    /// Absent means the default organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,

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
}

fleet_crd! {
    /// Spec for an Organization custom resource.
    ///
    /// Declares a tenant: a Zitadel organization paired with a DNS zone. This
    /// repo is the source of truth — fleet-dns manages an organization only
    /// when an Organization resource declares it, never because one happens to
    /// exist in Zitadel.
    kind = "Organization",
    struct OrganizationSpec {
    /// DNS zone this organization owns (e.g. "quota.fitness").
    pub zone: String,

    /// OIDC issuer for this organization's generated Middlewares, e.g.
    /// `https://sso.quota.fitness` — a Zitadel instance custom domain that
    /// serves this organization's login. When set, generated Middlewares use
    /// it as `Provider.Url` and also request the scope
    /// `urn:zitadel:iam:org:id:<org>`, because Zitadel picks the organization
    /// from that scope, never from the hostname. Absent means the global
    /// `ZITADEL_URL` and no organization scope (the pre-0.9 behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,

    /// Zitadel organization name. Defaults to the resource's own name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,

    /// Write DNS records for this zone — CoreDNS, Unbound, Cloudflare and WAN
    /// forwards.
    ///
    /// Defaults to **false**: declaring an organization registers it for OIDC
    /// and for qualifying DHCP hostnames, but does not hand fleet-dns its DNS.
    /// Turning this on makes fleet-dns authoritative for the zone, which means
    /// records in it that fleet-dns does not know about become orphans and are
    /// deleted. Only enable it for a zone whose records are not hand-managed,
    /// and check for conflicts first.
    #[serde(default)]
    pub manage_dns: bool,

    /// Create the organization in Zitadel when no organization of this name
    /// exists. Defaults to true.
    #[serde(default = "crate::crd::default_true")]
    pub create: bool,

    /// Cloudflare zone ID. Resolved from `zone` by name when absent; absent
    /// and unresolvable means no Cloudflare records for this organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare_zone_id: Option<String>,

    /// Hostname holding the WAN A record that service CNAMEs point at.
    /// Defaults to `origin.{zone}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare_cname_target: Option<String>,

    /// Unbound anchor hostname that IngressRoute hostnames in this zone alias.
    /// Defaults to `ha.{zone}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unbound_anchor: Option<String>,
}
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
    /// Zitadel organization holding the project. Absent means the default
    /// organization, which is how every OidcApplication behaved before
    /// organizations existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,

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

/// A header to inject into proxied requests via the Traefik OIDC plugin.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OidcHeaderSpec {
    /// HTTP header name (e.g. `"X-Oidc-Email"`).
    pub name: String,

    /// Value template (e.g. `"{{ .claims.email }}"`).
    pub value: String,
}

/// Configuration for the Traefik OIDC Middleware that fleet-dns manages.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OidcMiddlewareSpec {
    /// Middleware resource name.
    pub name: String,

    /// Namespace for the Middleware resource.
    pub namespace: String,

    /// OIDC scopes to request (e.g. `["openid", "profile", "email"]`).
    pub scopes: Vec<String>,

    /// Inject the standard OIDC claim headers (X-Oidc-Name, X-Oidc-Email,
    /// X-Oidc-Username, X-Oidc-Subject, Authorization). Defaults to true.
    /// Extra headers in `headers` are appended after the defaults.
    #[serde(default = "default_true")]
    pub default_headers: bool,

    /// Extra headers forwarding OIDC claims to the upstream service.
    /// Appended after default headers when `defaultHeaders` is true.
    #[serde(default)]
    pub headers: Vec<OidcHeaderSpec>,

    /// Let the plugin accept an inbound `Authorization: Bearer <token>` as an
    /// externally minted OIDC access token. Defaults to true. Set false for
    /// upstreams whose own SPA sends `Authorization` on API calls (e.g. its own
    /// API key) — otherwise the plugin tries to validate that value as a
    /// Zitadel token and answers 401 before the request reaches the upstream.
    #[serde(default = "default_true")]
    pub authorization_header: bool,
}

pub(crate) fn default_true() -> bool {
    true
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

    fn dhcp_reservation_json(hostname: &str, desc: Option<&str>) -> serde_json::Value {
        let mut v = serde_json::json!({"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.2.100", "hostname": hostname});
        if let Some(d) = desc {
            v["description"] = serde_json::json!(d);
        }
        v
    }

    #[test]
    fn dhcp_reservation_spec_deserializes_all_fields() {
        let spec: DhcpReservationSpec =
            serde_json::from_value(dhcp_reservation_json("my-host", Some("Living room AP")))
                .unwrap();
        assert_eq!(spec.mac, "aa:bb:cc:dd:ee:ff");
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
                "scopes": ["openid", "profile", "email"],
                "headers": [
                    {"name": "X-Oidc-Email", "value": "{{ .claims.email }}"}
                ]
            },
            "extraRedirectUris": ["https://oauth.pstmn.io/v1/callback"]
        });
        let spec: OidcApplicationSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.project_name, "Home Services");
        assert_eq!(spec.app_name, "system-oidc");
        assert_eq!(spec.middleware.name, "system-oidc");
        assert_eq!(spec.middleware.namespace, "ingress");
        assert!(
            spec.middleware.authorization_header,
            "authorizationHeader defaults to true"
        );
        assert_eq!(spec.middleware.scopes, vec!["openid", "profile", "email"]);
        assert_eq!(
            spec.extra_redirect_uris,
            vec!["https://oauth.pstmn.io/v1/callback"]
        );
        assert_eq!(spec.middleware.headers.len(), 1);
        assert_eq!(spec.middleware.headers[0].name, "X-Oidc-Email");
        assert_eq!(spec.middleware.headers[0].value, "{{ .claims.email }}");
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
        assert!(spec.middleware.headers.is_empty());
    }

    #[test]
    fn dhcp_reservation_spec_deserializes_without_description() {
        let spec: DhcpReservationSpec =
            serde_json::from_value(dhcp_reservation_json("kitchen-sensor", None)).unwrap();
        assert_eq!(spec.hostname, "kitchen-sensor");
        assert!(spec.description.is_none());
    }
}
