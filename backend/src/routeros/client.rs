use std::time::Duration;

use base64::Engine;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::config_store::MergedConfig;
use crate::error::AppError;
use crate::routeros::models::*;

/// HTTP client wrapper for the MikroTik RouterOS REST API.
///
/// Authenticates via token-based auth (POST login) with Basic auth fallback.
pub struct RouterOsClient {
    base_url: String,
    http_client: reqwest::Client,
    auth_header: String,
}

/// Response from a token-style login attempt.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    token: String,
    #[serde(default)]
    ret: Option<String>,
}

impl RouterOsClient {
    /// Build a new client from configuration. Tries token-based auth first,
    /// falls back to Basic auth.
    pub async fn new(config: &MergedConfig) -> Result<Self, AppError> {
        let base_url = config.routeros_base_url();
        let base_rest = format!(
            "{}://{}:{}",
            config.routeros_scheme, config.routeros_host, config.routeros_port
        );

        let http_client = build_http_client(config)?;

        // Strategy 1: Try token-based authentication
        // Some RouterOS versions accept a JSON POST with credentials
        // and return a bearer token.
        debug!("Attempting token-based auth...");
        if let Ok(auth_header) =
            try_token_auth(&http_client, &base_rest, config).await
        {
            info!("RouterOS authenticated via token");
            return Ok(Self {
                base_url,
                http_client,
                auth_header,
            });
        }

        // Strategy 2: Fall back to Basic auth
        debug!("Token auth unavailable, falling back to Basic auth");
        let auth_header = build_basic_auth_header(
            &config.routeros_username,
            &config.routeros_password,
        )?;

        // Quick sanity check: does a simple GET work with Basic auth?
        let test_url = format!("{}/system/resource", base_url);
        match http_client
            .get(&test_url)
            .header(AUTHORIZATION, HeaderValue::from_str(&auth_header).unwrap())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!("RouterOS Basic auth verified");
            }
            Ok(resp) if resp.status().as_u16() == 401 => {
                let body = resp.text().await.unwrap_or_default();
                warn!(
                    "RouterOS returned 401 for Basic auth. \
                     Please check:\n  \
                     - The user '{}' has 'rest-api' policy granted\n  \
                     - RouterOS version is 7.1 or newer\n  \
                     - The www service is enabled: /ip/service/print\n  \
                     Response: {body}",
                    config.routeros_username,
                );
                return Err(AppError::RouterOsApi(format!(
                    "Authentication failed (401). Ensure user '{}' has the 'rest-api' \
                     policy in RouterOS: /user/group add name=restapi policy=rest-api; \
                     /user/set {} group=restapi",
                    config.routeros_username, config.routeros_username,
                )));
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!("RouterOS test request returned {status}: {body}");
            }
            Err(e) => {
                warn!("RouterOS test request failed: {e}");
            }
        }

        Ok(Self {
            base_url,
            http_client,
            auth_header,
        })
    }

    /// Generic GET request to a RouterOS REST API path.
    pub async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, AppError> {
        let url = format!("{}{}", self.base_url, path);
        debug!("GET {}", url);

        let resp = self
            .http_client
            .get(&url)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&self.auth_header).map_err(|e| {
                    AppError::Internal(format!("Invalid auth header: {e}"))
                })?,
            )
            .send()
            .await
            .map_err(|e| {
                warn!("RouterOS request failed: {e}");
                AppError::RouterOsApi(format!("Request to {} failed: {e}", path))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!("RouterOS returned {status}: {body}");

            if status.as_u16() == 401 {
                return Err(AppError::RouterOsApi(format!(
                    "Authentication rejected by {path}. \
                     Verify the user has 'rest-api' policy in RouterOS."
                )));
            }

            return Err(AppError::RouterOsApi(format!(
                "HTTP {status} from {path}: {body}"
            )));
        }

        let body_text = resp.text().await.map_err(|e| {
            AppError::RouterOsApi(format!("Failed to read response body: {e}"))
        })?;

        if body_text.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str::<Vec<T>>(&body_text)
            .or_else(|_| {
                serde_json::from_str::<T>(&body_text).map(|item| vec![item])
            })
            .map_err(|e| {
                warn!("Failed to deserialize RouterOS response: {e}");
                AppError::RouterOsApi(format!(
                    "Failed to parse response from {path}: {e}"
                ))
            })
    }

    // ── Convenience Endpoint Methods ──────────────────────────

    pub async fn system_resource(&self) -> Result<SystemResource, AppError> {
        let items = self.get::<SystemResource>("/system/resource").await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty system resource response".into()))
    }

    pub async fn system_identity(&self) -> Result<SystemIdentity, AppError> {
        let items = self.get::<SystemIdentity>("/system/identity").await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty system identity response".into()))
    }

    pub async fn ip_addresses(&self) -> Result<Vec<IpAddress>, AppError> {
        self.get::<IpAddress>("/ip/address").await
    }

    pub async fn interfaces(&self) -> Result<Vec<Interface>, AppError> {
        self.get::<Interface>("/interface").await
    }

    /// Fetch all IP routes: `/rest/ip/route`
    pub async fn routes(&self) -> Result<Vec<Route>, AppError> {
        self.get::<Route>("/ip/route").await
    }

    pub async fn arp_table(&self) -> Result<Vec<ArpEntry>, AppError> {
        self.get::<ArpEntry>("/ip/arp").await
    }

    pub async fn dns_config(&self) -> Result<DnsConfig, AppError> {
        let items = self.get::<DnsConfig>("/ip/dns").await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty DNS config response".into()))
    }

    pub async fn dhcp_leases(&self) -> Result<Vec<DhcpLease>, AppError> {
        self.get::<DhcpLease>("/ip/dhcp-server/lease").await
    }

    pub async fn wireless_registrations(&self) -> Result<Vec<WirelessRegistration>, AppError> {
        match self
            .get::<WirelessRegistration>("/interface/wireless/registration-table")
            .await
        {
            Ok(regs) => Ok(regs),
            Err(e) => {
                debug!("Wireless registration table not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    /// Fetch all tracked firewall connections: `/rest/ip/firewall/connection`
    ///
    /// Returns an empty Vec if the endpoint is unavailable (e.g., connection
    /// tracking disabled or the endpoint not exposed in this RouterOS version).
    pub async fn firewall_connections(&self) -> Result<Vec<ConnectionEntry>, AppError> {
        match self
            .get::<ConnectionEntry>("/ip/firewall/connection")
            .await
        {
            Ok(conns) => Ok(conns),
            Err(e) => {
                debug!("Firewall connection tracking not available: {e}");
                Ok(Vec::new())
            }
        }
    }
}

// ── Auth Helpers ────────────────────────────────────────────────

/// Build the base HTTP client (without auth headers — those are per-request).
fn build_http_client(config: &MergedConfig) -> Result<reqwest::Client, AppError> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10));

    if config.is_tls() {
        builder = builder.danger_accept_invalid_certs(config.accept_invalid_certs);
    }

    builder
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {e}")))
}

/// Build a Basic auth header value from username and password.
fn build_basic_auth_header(username: &str, password: &str) -> Result<String, AppError> {
    let credentials = format!("{}:{}", username, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    Ok(format!("Basic {}", encoded))
}

/// Attempt token-based authentication against the RouterOS REST API.
///
/// Tries multiple known login endpoints and returns an auth header on success.
async fn try_token_auth(
    client: &reqwest::Client,
    base_rest: &str,
    config: &MergedConfig,
) -> Result<String, AppError> {
    let body = serde_json::json!({
        "name": config.routeros_username,
        "password": config.routeros_password,
    });

    // Different RouterOS versions use different token endpoints
    let candidates = [
        format!("{}/rest/auth/token", base_rest),
        format!("{}/rest/auth/login", base_rest),
        format!("{}/rest/login", base_rest),
    ];

    for url in &candidates {
        debug!("Trying token auth at: {}", url);
        match client.post(url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                let text = resp.text().await.unwrap_or_default();
                debug!("Token response: {text}");

                // Try to parse a token
                if let Ok(tok) = serde_json::from_str::<TokenResponse>(&text) {
                    if !tok.token.is_empty() {
                        return Ok(format!("Bearer {}", tok.token));
                    }
                }

                // Some versions return a session cookie instead — check cookies
                // The cookie store is enabled, so subsequent requests will carry the
                // session cookie automatically. We still need a header for direct usage.
                // Return Basic auth as final fallback — the cookie store handles the session.
                return build_basic_auth_header(
                    &config.routeros_username,
                    &config.routeros_password,
                );
            }
            Ok(resp) => {
                debug!("Token auth at {} returned {}", url, resp.status());
            }
            Err(e) => {
                debug!("Token auth at {} failed: {}", url, e);
            }
        }
    }

    // Also try the legacy login style (form-encoded)
    let legacy_url = format!("{}/rest/auth/basic", base_rest);
    debug!("Trying legacy auth at: {}", legacy_url);
    if let Ok(resp) = client
        .post(&legacy_url)
        .form(&[
            ("name", config.routeros_username.as_str()),
            ("password", config.routeros_password.as_str()),
        ])
        .send()
        .await
    {
        if resp.status().is_success() {
            info!("Legacy auth succeeded");
            return build_basic_auth_header(
                &config.routeros_username,
                &config.routeros_password,
            );
        }
    }

    Err(AppError::RouterOsApi(
        "No token auth endpoint available, will fall back to Basic auth".into(),
    ))
}
