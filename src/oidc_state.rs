//! OIDC state computation — builds desired Zitadel OIDC app state from
//! `OidcApplication` CRDs and `IngressRoute` labels.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tracing::warn;

use crate::crd::{OidcApplication, OidcApplicationSpec};
use crate::traefik::{IngressRoute, extract_hostnames};

/// Desired state for a single OIDC application.
#[derive(Debug, Clone)]
pub struct OidcAppDesired {
    /// CRD name (used as the lookup key).
    pub crd_name: String,
    /// CRD namespace.
    pub crd_namespace: String,
    /// Full CRD spec.
    pub spec: OidcApplicationSpec,
    /// Aggregated redirect URIs: auto-synced from IngressRoutes + extra.
    pub redirect_uris: BTreeSet<String>,
}

/// Build the desired OIDC state from CRDs and labeled IngressRoutes.
///
/// For each `OidcApplication`, collects all IngressRoutes with
/// `hr-home.xyz/oidc: "<crd-name>"` and builds redirect URIs from their
/// hostnames. Also checks for missing middleware references and warns.
pub fn build_oidc_desired(
    oidc_apps: &[Arc<OidcApplication>],
    ingresses: &[Arc<IngressRoute>],
) -> BTreeMap<String, OidcAppDesired> {
    let mut desired: BTreeMap<String, OidcAppDesired> = BTreeMap::new();

    for app in oidc_apps {
        let crd_name = app.metadata.name.as_deref().unwrap_or_default().to_owned();
        let crd_ns = app
            .metadata
            .namespace
            .as_deref()
            .unwrap_or_default()
            .to_owned();

        let redirect_uris: BTreeSet<String> =
            app.spec.extra_redirect_uris.iter().cloned().collect();

        desired.insert(
            crd_name.clone(),
            OidcAppDesired {
                crd_name,
                crd_namespace: crd_ns,
                spec: app.spec.clone(),
                redirect_uris,
            },
        );
    }

    // Scan IngressRoutes for hr-home.xyz/oidc labels.
    for ir in ingresses {
        let ir_name = ir.metadata.name.as_deref().unwrap_or("?");
        let ir_ns = ir.metadata.namespace.as_deref().unwrap_or("?");
        let ir_display = format!("{ir_ns}/{ir_name}");

        let labels = ir.metadata.labels.as_ref();
        let oidc_ref = labels.and_then(|l| l.get("hr-home.xyz/oidc"));
        let oidc_ref = match oidc_ref {
            Some(v) => v.as_str(),
            None => continue,
        };

        let entry = match desired.get_mut(oidc_ref) {
            Some(e) => e,
            None => {
                warn!(
                    ingress = %ir_display,
                    oidc_ref = oidc_ref,
                    "IngressRoute references non-existent OidcApplication"
                );
                continue;
            }
        };

        let mw_name = &entry.spec.middleware.name;
        let mw_ns = &entry.spec.middleware.namespace;

        for route in &ir.spec.routes {
            // Collect hostnames → redirect URIs.
            for host in extract_hostnames(&route.match_rule) {
                entry
                    .redirect_uris
                    .insert(format!("https://{host}/oidc/callback"));
            }

            // Warn if the route doesn't reference the expected middleware.
            let has_ref = route.middlewares.as_ref().is_some_and(|mws| {
                mws.iter().any(|m| {
                    m.name == *mw_name && m.namespace.as_deref().unwrap_or_default() == mw_ns
                })
            });

            if !has_ref {
                warn!(
                    ingress = %ir_display,
                    expected_middleware = %format!("{mw_ns}/{mw_name}"),
                    "IngressRoute has hr-home.xyz/oidc label but does not reference the OIDC middleware"
                );
            }
        }
    }

    desired
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{OidcApplicationSpec, OidcMiddlewareSpec};
    use crate::traefik::{
        IngressRouteMiddlewareRef, IngressRouteRoute, IngressRouteService, IngressRouteSpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    /// Shorthand for the middleware ref used by most test ingresses.
    const OIDC_MW_NS: &str = "ingress";

    fn make_oidc_app(name: &str, project: &str, mw_name: &str) -> Arc<OidcApplication> {
        let spec = OidcApplicationSpec {
            project_name: project.to_owned(),
            app_name: name.to_owned(),
            middleware: OidcMiddlewareSpec {
                name: mw_name.to_owned(),
                namespace: OIDC_MW_NS.to_owned(),
                scopes: vec!["openid".to_owned()],
                default_headers: true,
                headers: vec![],
            },
            extra_redirect_uris: vec![],
        };
        let metadata = ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(OIDC_MW_NS.to_owned()),
            ..ObjectMeta::default()
        };
        Arc::new(OidcApplication {
            metadata,
            spec,
            status: None,
        })
    }

    /// Build an `IngressRoute` test fixture.
    ///
    /// `oidc_mw` bundles the OIDC label and middleware ref together --
    /// pass `Some(("crd-name", "mw-name"))` for labeled ingresses, or
    /// `None` for unlabeled ones.
    fn make_ingress(
        name: &str,
        ns: &str,
        host: &str,
        oidc_mw: Option<(&str, &str)>,
    ) -> Arc<IngressRoute> {
        let mut labels = std::collections::BTreeMap::new();
        let mw_refs = oidc_mw.map(|(oidc_label, mw_name)| {
            labels.insert("hr-home.xyz/oidc".to_owned(), oidc_label.to_owned());
            vec![IngressRouteMiddlewareRef {
                name: mw_name.to_owned(),
                namespace: Some(OIDC_MW_NS.to_owned()),
            }]
        });

        Arc::new(IngressRoute {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                namespace: Some(ns.to_owned()),
                labels: Some(labels),
                ..ObjectMeta::default()
            },
            spec: IngressRouteSpec {
                entry_points: None,
                routes: vec![IngressRouteRoute {
                    match_rule: format!("Host(`{host}`)"),
                    services: Some(vec![IngressRouteService {
                        name: "svc".to_owned(),
                        namespace: None,
                    }]),
                    middlewares: mw_refs,
                }],
            },
        })
    }

    /// Build desired state and return the entry for `app_key`, asserting
    /// the redirect-URI count matches `expected_count`.
    fn assert_redirect_count(
        apps: &[Arc<OidcApplication>],
        ingresses: &[Arc<IngressRoute>],
        app_key: &str,
        expected_count: usize,
    ) -> OidcAppDesired {
        let desired = build_oidc_desired(apps, ingresses);
        let entry = desired.get(app_key).unwrap().clone();
        assert_eq!(
            entry.redirect_uris.len(),
            expected_count,
            "expected {expected_count} redirect URIs for {app_key}, got {}",
            entry.redirect_uris.len(),
        );
        entry
    }

    fn callback_uri(host: &str) -> String {
        format!("https://{host}/oidc/callback")
    }

    #[test]
    fn builds_redirect_uris_from_ingress_labels() {
        let apps = vec![make_oidc_app("system-oidc", "Home", "system-oidc")];
        let ingresses = vec![
            make_ingress(
                "mail",
                "system",
                "mail.hr-home.xyz",
                Some(("system-oidc", "system-oidc")),
            ),
            make_ingress(
                "network",
                "system",
                "network.hr-home.xyz",
                Some(("system-oidc", "system-oidc")),
            ),
        ];

        let result = assert_redirect_count(&apps, &ingresses, "system-oidc", 2);
        assert!(
            result
                .redirect_uris
                .contains(&callback_uri("mail.hr-home.xyz"))
        );
        assert!(
            result
                .redirect_uris
                .contains(&callback_uri("network.hr-home.xyz"))
        );
    }

    #[test]
    fn includes_extra_redirect_uris() {
        let postman_cb = "https://oauth.pstmn.io/v1/callback".to_owned();
        let mut app = make_oidc_app("test", "Home", "test-oidc");
        Arc::get_mut(&mut app).unwrap().spec.extra_redirect_uris = vec![postman_cb.clone()];

        let entry = assert_redirect_count(&[app], &[], "test", 1);
        assert!(entry.redirect_uris.contains(&postman_cb));
    }

    #[test]
    fn ignores_ingress_without_oidc_label() {
        let apps = vec![make_oidc_app("system-oidc", "Home", "system-oidc")];
        let labeled = make_ingress(
            "labeled",
            "system",
            "a.hr-home.xyz",
            Some(("system-oidc", "system-oidc")),
        );
        let unlabeled = make_ingress("unlabeled", "system", "b.hr-home.xyz", None);

        let result = assert_redirect_count(&apps, &[labeled, unlabeled], "system-oidc", 1);
        assert!(
            result
                .redirect_uris
                .contains(&callback_uri("a.hr-home.xyz"))
        );
    }

    #[test]
    fn deduplicates_hostnames_from_multiple_routes() {
        let apps = vec![make_oidc_app("test", "Home", "test-oidc")];
        let same_host = "app.hr-home.xyz";
        let ingresses: Vec<_> = ["ir1", "ir2"]
            .iter()
            .map(|id| make_ingress(id, "ns", same_host, Some(("test", "test-oidc"))))
            .collect();

        assert_redirect_count(&apps, &ingresses, "test", 1);
    }
}
