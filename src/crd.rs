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

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_has_correct_group_and_kind() {
        let crd = CoreDnsPolicy::crd();
        assert_eq!(crd.spec.group, "fleet-dns.hr-home.xyz");
        assert_eq!(crd.spec.names.kind, "CoreDnsPolicy");
    }
}
