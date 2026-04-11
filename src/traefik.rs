use std::sync::LazyLock;

use kube::CustomResource;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Compiled regex for extracting Host() patterns from Traefik match rules.
static HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(Host(?:Regexp)?)\(`([^`]+)`\)").expect("valid regex"));

/// Minimal representation of a Traefik IngressRoute CRD.
/// Only the fields fleet-dns needs for hostname extraction.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "traefik.io",
    version = "v1alpha1",
    kind = "IngressRoute",
    namespaced,
    plural = "ingressroutes"
)]
pub struct IngressRouteSpec {
    #[serde(default)]
    pub entry_points: Option<Vec<String>>,

    pub routes: Vec<IngressRouteRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IngressRouteRoute {
    /// Traefik match expression. Renamed because `match` is a Rust keyword.
    #[serde(rename = "match")]
    pub match_rule: String,

    #[serde(default)]
    pub services: Option<Vec<IngressRouteService>>,

    /// Middleware references applied to this route.
    #[serde(default)]
    pub middlewares: Option<Vec<IngressRouteMiddlewareRef>>,
}

/// Reference to a Traefik Middleware from an IngressRoute route.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IngressRouteMiddlewareRef {
    pub name: String,

    #[serde(default)]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IngressRouteService {
    pub name: String,

    #[serde(default)]
    pub namespace: Option<String>,
}

/// Extract hostnames from a Traefik match expression.
///
/// Recognises `Host(` backtick-delimited `)` patterns and ignores
/// `HostRegexp(...)`.
///
/// Examples:
/// - `Host(`foo.hr-home.xyz`)` -> `["foo.hr-home.xyz"]`
/// - `Host(`a.x`) || Host(`b.x`)` -> `["a.x", "b.x"]`
/// - `Host(`a.x`) && PathPrefix(`/api`)` -> `["a.x"]`
#[must_use]
pub fn extract_hostnames(match_rule: &str) -> Vec<String> {
    HOST_RE
        .captures_iter(match_rule)
        .filter(|cap| &cap[1] == "Host")
        .map(|cap| cap[2].to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_host() {
        let hosts = extract_hostnames("Host(`foo.hr-home.xyz`)");
        assert_eq!(hosts, vec!["foo.hr-home.xyz"]);
    }

    #[test]
    fn multiple_or() {
        let hosts =
            extract_hostnames("Host(`a.hr-home.xyz`) || Host(`b.hr-home.xyz`)");
        assert_eq!(hosts, vec!["a.hr-home.xyz", "b.hr-home.xyz"]);
    }

    #[test]
    fn combined_with_path() {
        let hosts =
            extract_hostnames("Host(`foo.hr-home.xyz`) && PathPrefix(`/api`)");
        assert_eq!(hosts, vec!["foo.hr-home.xyz"]);
    }

    #[test]
    fn ignores_host_regexp() {
        let hosts = extract_hostnames("HostRegexp(`.*\\.hr-home\\.xyz`)");
        assert!(hosts.is_empty());
    }

    #[test]
    fn empty_on_no_match() {
        let hosts = extract_hostnames("PathPrefix(`/health`)");
        assert!(hosts.is_empty());
    }
}
