//! OIDC state computation — builds desired Zitadel OIDC app state from
//! `OidcApplication` CRDs and `IngressRoute` labels.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tracing::warn;

use crate::crd::{OidcApplication, OidcApplicationSpec};
use crate::traefik::{extract_hostnames, IngressRoute};

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

        let redirect_uris: BTreeSet<String> = app
            .spec
            .extra_redirect_uris
            .iter()
            .cloned()
            .collect();

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
        let labels = ir.metadata.labels.as_ref();
        let oidc_ref = labels.and_then(|l| l.get("hr-home.xyz/oidc"));
        let oidc_ref = match oidc_ref {
            Some(v) => v.as_str(),
            None => continue,
        };

        let entry = match desired.get_mut(oidc_ref) {
            Some(e) => e,
            None => {
                let ir_name = ir.metadata.name.as_deref().unwrap_or("?");
                let ir_ns = ir.metadata.namespace.as_deref().unwrap_or("?");
                warn!(
                    ingress = %format!("{ir_ns}/{ir_name}"),
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
            let has_ref = route
                .middlewares
                .as_ref()
                .is_some_and(|mws| {
                    mws.iter().any(|m| {
                        m.name == *mw_name
                            && m.namespace.as_deref().unwrap_or_default() == mw_ns
                    })
                });

            if !has_ref {
                let ir_name = ir.metadata.name.as_deref().unwrap_or("?");
                let ir_ns = ir.metadata.namespace.as_deref().unwrap_or("?");
                warn!(
                    ingress = %format!("{ir_ns}/{ir_name}"),
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

    fn make_oidc_app(name: &str, project: &str, mw_name: &str) -> Arc<OidcApplication> {
        Arc::new(OidcApplication {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                namespace: Some("ingress".to_owned()),
                ..Default::default()
            },
            spec: OidcApplicationSpec {
                project_name: project.to_owned(),
                app_name: name.to_owned(),
                middleware: OidcMiddlewareSpec {
                    name: mw_name.to_owned(),
                    namespace: "ingress".to_owned(),
                    scopes: vec!["openid".to_owned()],
                },
                extra_redirect_uris: vec![],
            },
            status: None,
        })
    }

    fn make_ingress(
        name: &str,
        ns: &str,
        host: &str,
        oidc_label: Option<&str>,
        middleware: Option<(&str, &str)>,
    ) -> Arc<IngressRoute> {
        let mut labels = std::collections::BTreeMap::new();
        if let Some(oidc) = oidc_label {
            labels.insert("hr-home.xyz/oidc".to_owned(), oidc.to_owned());
        }

        let mw_refs = middleware.map(|(mw_name, mw_ns)| {
            vec![IngressRouteMiddlewareRef {
                name: mw_name.to_owned(),
                namespace: Some(mw_ns.to_owned()),
            }]
        });

        Arc::new(IngressRoute {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                namespace: Some(ns.to_owned()),
                labels: Some(labels),
                ..Default::default()
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

    #[test]
    fn builds_redirect_uris_from_ingress_labels() {
        let apps = vec![make_oidc_app("system-oidc", "Home", "system-oidc")];
        let ingresses = vec![
            make_ingress("mail", "system", "mail.hr-home.xyz", Some("system-oidc"), Some(("system-oidc", "ingress"))),
            make_ingress("network", "system", "network.hr-home.xyz", Some("system-oidc"), Some(("system-oidc", "ingress"))),
        ];

        let desired = build_oidc_desired(&apps, &ingresses);
        let app = desired.get("system-oidc").unwrap();
        assert_eq!(app.redirect_uris.len(), 2);
        assert!(app.redirect_uris.contains("https://mail.hr-home.xyz/oidc/callback"));
        assert!(app.redirect_uris.contains("https://network.hr-home.xyz/oidc/callback"));
    }

    #[test]
    fn includes_extra_redirect_uris() {
        let mut app = make_oidc_app("test", "Home", "test-oidc");
        Arc::get_mut(&mut app).unwrap().spec.extra_redirect_uris =
            vec!["https://oauth.pstmn.io/v1/callback".to_owned()];

        let desired = build_oidc_desired(&[app], &[]);
        let entry = desired.get("test").unwrap();
        assert!(entry.redirect_uris.contains("https://oauth.pstmn.io/v1/callback"));
    }

    #[test]
    fn ignores_ingress_without_oidc_label() {
        let apps = vec![make_oidc_app("system-oidc", "Home", "system-oidc")];
        let ingresses = vec![
            make_ingress("labeled", "system", "a.hr-home.xyz", Some("system-oidc"), Some(("system-oidc", "ingress"))),
            make_ingress("unlabeled", "system", "b.hr-home.xyz", None, None),
        ];

        let desired = build_oidc_desired(&apps, &ingresses);
        let app = desired.get("system-oidc").unwrap();
        assert_eq!(app.redirect_uris.len(), 1);
        assert!(app.redirect_uris.contains("https://a.hr-home.xyz/oidc/callback"));
    }

    #[test]
    fn deduplicates_hostnames_from_multiple_routes() {
        let apps = vec![make_oidc_app("test", "Home", "test-oidc")];
        // Two IngressRoutes with the same hostname
        let ingresses = vec![
            make_ingress("ir1", "ns", "app.hr-home.xyz", Some("test"), Some(("test-oidc", "ingress"))),
            make_ingress("ir2", "ns", "app.hr-home.xyz", Some("test"), Some(("test-oidc", "ingress"))),
        ];

        let desired = build_oidc_desired(&apps, &ingresses);
        let entry = desired.get("test").unwrap();
        assert_eq!(entry.redirect_uris.len(), 1);
    }
}
