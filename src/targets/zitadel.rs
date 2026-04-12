use std::time::{Duration, Instant};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::error::Error;

/// Buffer subtracted from token expiry to trigger proactive refresh.
const TOKEN_REFRESH_BUFFER: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Wire types (serde)
// ---------------------------------------------------------------------------

/// A Zitadel project, as returned by the management API.
#[derive(Debug, Clone, Deserialize)]
pub struct ZitadelProject {
    pub id: String,
    pub name: String,
}

/// A Zitadel OIDC application, as returned by the management API.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZitadelApp {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub oidc_config: Option<OidcConfig>,
}

impl ZitadelApp {
    /// Extract the client ID from the embedded OIDC config, if present.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.oidc_config.as_ref().map(|c| c.client_id.as_str())
    }

    /// Extract redirect URIs from the embedded OIDC config, if present.
    #[must_use]
    pub fn redirect_uris(&self) -> &[String] {
        self.oidc_config
            .as_ref()
            .map(|c| c.redirect_uris.as_slice())
            .unwrap_or_default()
    }
}

/// OIDC configuration nested inside a Zitadel app response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcConfig {
    pub client_id: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
}

// -- Search responses (paginated envelope) --

#[derive(Debug, Deserialize)]
struct ProjectSearchResponse {
    #[serde(default)]
    result: Vec<ZitadelProject>,
}

#[derive(Debug, Deserialize)]
struct AppSearchResponse {
    #[serde(default)]
    result: Vec<ZitadelApp>,
}

// -- Create OIDC app response --

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOidcAppResponse {
    app_id: String,
    client_id: String,
}

// -- JWT claims for the bearer grant --

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
}

// -- Token endpoint response --

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default = "default_expires_in")]
    expires_in: u64,
}

fn default_expires_in() -> u64 {
    300
}

// -- OIDC app request bodies --

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateOidcAppRequest {
    name: String,
    redirect_uris: Vec<String>,
    response_types: Vec<String>,
    grant_types: Vec<String>,
    app_type: String,
    auth_method_type: String,
    post_logout_redirect_uris: Vec<String>,
    dev_mode: bool,
    access_token_type: String,
    id_token_role_assertion: bool,
    id_token_userinfo_assertion: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateOidcConfigRequest {
    redirect_uris: Vec<String>,
    response_types: Vec<String>,
    grant_types: Vec<String>,
    app_type: String,
    auth_method_type: String,
    post_logout_redirect_uris: Vec<String>,
    dev_mode: bool,
    access_token_type: String,
    id_token_role_assertion: bool,
    id_token_userinfo_assertion: bool,
}

// ---------------------------------------------------------------------------
// Cached token
// ---------------------------------------------------------------------------

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Async client for the Zitadel Management API v1.
///
/// Authenticates via the JWT bearer grant flow: builds a signed JWT from an
/// RSA private key and exchanges it for a short-lived access token, which is
/// cached and refreshed transparently.
pub struct ZitadelClient {
    client: Client,
    base_url: String,
    key_id: String,
    user_id: String,
    encoding_key: jsonwebtoken::EncodingKey,
    token: Mutex<Option<CachedToken>>,
}

impl ZitadelClient {
    /// Create a new Zitadel API client.
    ///
    /// `private_key_pem` must be a PEM-encoded RSA private key.
    /// TLS verification is disabled because the cluster Zitadel instance
    /// uses a self-signed certificate.
    pub fn new(
        url: &str,
        key_id: &str,
        user_id: &str,
        private_key_pem: &str,
    ) -> Result<Self, Error> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| Error::Zitadel(format!("failed to parse RSA private key: {e}")))?;

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(Error::Reqwest)?;

        Ok(Self {
            client,
            base_url: url.trim_end_matches('/').to_owned(),
            key_id: key_id.to_owned(),
            user_id: user_id.to_owned(),
            encoding_key,
            token: Mutex::new(None),
        })
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /// Build a signed JWT assertion for the bearer grant.
    fn build_assertion(&self) -> Result<String, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        let claims = JwtClaims {
            iss: self.user_id.clone(),
            sub: self.user_id.clone(),
            aud: self.base_url.clone(),
            iat: now,
            exp: now + 3600,
        };

        let header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(self.key_id.clone()),
            ..Default::default()
        };

        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| Error::Zitadel(format!("failed to sign JWT assertion: {e}")))
    }

    /// Exchange a JWT assertion for an access token via the token endpoint.
    async fn fetch_token(&self) -> Result<CachedToken, Error> {
        let assertion = self.build_assertion()?;

        let resp = self
            .client
            .post(format!("{}/oauth/v2/token", self.base_url))
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ),
                (
                    "scope",
                    "openid urn:zitadel:iam:org:project:id:zitadel:aud",
                ),
                ("assertion", &assertion),
            ])
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Zitadel(format!(
                "token exchange returned {status}: {body}"
            )));
        }

        let token_resp: TokenResponse = resp.json().await?;

        let expires_at = Instant::now()
            + Duration::from_secs(token_resp.expires_in)
            - TOKEN_REFRESH_BUFFER;

        info!(expires_in_secs = token_resp.expires_in, "acquired Zitadel access token");

        Ok(CachedToken {
            access_token: token_resp.access_token,
            expires_at,
        })
    }

    /// Return a valid access token, refreshing if expired or absent.
    async fn access_token(&self) -> Result<String, Error> {
        let mut guard = self.token.lock().await;

        if let Some(cached) = guard.as_ref() {
            if Instant::now() < cached.expires_at {
                return Ok(cached.access_token.clone());
            }
            warn!("Zitadel access token expired, refreshing");
        }

        let fresh = self.fetch_token().await?;
        let token = fresh.access_token.clone();
        *guard = Some(fresh);
        Ok(token)
    }

    // -----------------------------------------------------------------------
    // Request helpers
    // -----------------------------------------------------------------------

    /// Build an authenticated POST request.
    async fn authed_post(&self, path: &str) -> Result<reqwest::RequestBuilder, Error> {
        let token = self.access_token().await?;
        Ok(self
            .client
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(token))
    }

    /// Build an authenticated PUT request.
    async fn authed_put(&self, path: &str) -> Result<reqwest::RequestBuilder, Error> {
        let token = self.access_token().await?;
        Ok(self
            .client
            .put(format!("{}{path}", self.base_url))
            .bearer_auth(token))
    }

    /// Build an authenticated DELETE request.
    async fn authed_delete(&self, path: &str) -> Result<reqwest::RequestBuilder, Error> {
        let token = self.access_token().await?;
        Ok(self
            .client
            .delete(format!("{}{path}", self.base_url))
            .bearer_auth(token))
    }

    /// Send an authenticated POST with a JSON body, check status, deserialize.
    async fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        context: &str,
    ) -> Result<R, Error> {
        let resp = self.authed_post(path).await?.json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Zitadel(format!(
                "{context} returned {status}: {body}"
            )));
        }
        Ok(resp.json().await?)
    }

    // -----------------------------------------------------------------------
    // Project operations
    // -----------------------------------------------------------------------

    /// List all projects visible to the service user.
    pub async fn list_projects(&self) -> Result<Vec<ZitadelProject>, Error> {
        let resp: ProjectSearchResponse = self
            .post_json(
                "/management/v1/projects/_search",
                &serde_json::json!({}),
                "list_projects",
            )
            .await?;

        info!(count = resp.result.len(), "listed Zitadel projects");
        Ok(resp.result)
    }

    /// Find a project by exact name, returning its ID if found.
    pub async fn find_project_by_name(&self, name: &str) -> Result<Option<String>, Error> {
        let projects = self.list_projects().await?;
        let found = projects.into_iter().find(|p| p.name == name).map(|p| p.id);
        Ok(found)
    }

    // -----------------------------------------------------------------------
    // Application operations
    // -----------------------------------------------------------------------

    /// List all applications in a project.
    pub async fn list_apps(&self, project_id: &str) -> Result<Vec<ZitadelApp>, Error> {
        let path = format!("/management/v1/projects/{project_id}/apps/_search");
        let resp: AppSearchResponse = self
            .post_json(&path, &serde_json::json!({}), "list_apps")
            .await?;

        info!(
            project_id,
            count = resp.result.len(),
            "listed Zitadel apps"
        );
        Ok(resp.result)
    }

    /// Create an OIDC application in a project.
    ///
    /// Returns `(app_id, client_id)`.
    pub async fn create_oidc_app(
        &self,
        project_id: &str,
        name: &str,
        redirect_uris: &[String],
    ) -> Result<(String, String), Error> {
        let path = format!("/management/v1/projects/{project_id}/apps/oidc");

        let body = CreateOidcAppRequest {
            name: name.to_owned(),
            redirect_uris: redirect_uris.to_vec(),
            response_types: vec!["OIDC_RESPONSE_TYPE_CODE".to_owned()],
            grant_types: vec!["OIDC_GRANT_TYPE_AUTHORIZATION_CODE".to_owned()],
            app_type: "OIDC_APP_TYPE_WEB".to_owned(),
            auth_method_type: "OIDC_AUTH_METHOD_TYPE_NONE".to_owned(),
            post_logout_redirect_uris: Vec::new(),
            dev_mode: false,
            access_token_type: "OIDC_TOKEN_TYPE_BEARER".to_owned(),
            id_token_role_assertion: false,
            id_token_userinfo_assertion: true,
        };

        let resp: CreateOidcAppResponse =
            self.post_json(&path, &body, "create_oidc_app").await?;

        info!(
            project_id,
            app_id = %resp.app_id,
            client_id = %resp.client_id,
            name,
            "created Zitadel OIDC app"
        );

        Ok((resp.app_id, resp.client_id))
    }

    /// Update the OIDC configuration of an existing application.
    pub async fn update_oidc_config(
        &self,
        project_id: &str,
        app_id: &str,
        redirect_uris: &[String],
    ) -> Result<(), Error> {
        let path = format!(
            "/management/v1/projects/{project_id}/apps/{app_id}/oidc_config"
        );

        let body = UpdateOidcConfigRequest {
            redirect_uris: redirect_uris.to_vec(),
            response_types: vec!["OIDC_RESPONSE_TYPE_CODE".to_owned()],
            grant_types: vec!["OIDC_GRANT_TYPE_AUTHORIZATION_CODE".to_owned()],
            app_type: "OIDC_APP_TYPE_WEB".to_owned(),
            auth_method_type: "OIDC_AUTH_METHOD_TYPE_NONE".to_owned(),
            post_logout_redirect_uris: Vec::new(),
            dev_mode: false,
            access_token_type: "OIDC_TOKEN_TYPE_BEARER".to_owned(),
            id_token_role_assertion: false,
            id_token_userinfo_assertion: true,
        };

        let resp = self.authed_put(&path).await?.json(&body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Zitadel(format!(
                "update_oidc_config returned {status}: {text}"
            )));
        }

        info!(project_id, app_id, "updated Zitadel OIDC config");
        Ok(())
    }

    /// Delete an application from a project.
    pub async fn delete_app(&self, project_id: &str, app_id: &str) -> Result<(), Error> {
        let path = format!("/management/v1/projects/{project_id}/apps/{app_id}");

        let resp = self.authed_delete(&path).await?.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Zitadel(format!(
                "delete_app returned {status}: {text}"
            )));
        }

        info!(project_id, app_id, "deleted Zitadel app");
        Ok(())
    }
}
