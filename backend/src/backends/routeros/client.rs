use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::backends::{
    ConnectionTestResult, RouterBackend, RouterConnectionConfig, RouterData, RouterType,
};
use crate::error::AppError;
use crate::backends::routeros::models::*;

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
    /// Build a new client from a generic `RouterConnectionConfig`.
    fn base_url(config: &RouterConnectionConfig) -> String {
        format!("{}://{}:{}/rest", config.scheme, config.host, config.port)
    }

    /// Generic GET request to a RouterOS REST API path.
    async fn get<T: serde::de::DeserializeOwned>(
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
                AppError::RouterApi(format!("Request to {} failed: {e}", path))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            warn!("RouterOS returned {status}: {body}");

            if status.as_u16() == 401 {
                return Err(AppError::RouterApi(format!(
                    "Authentication rejected by {path}. \
                     Verify the user has 'rest-api' policy in RouterOS."
                )));
            }

            return Err(AppError::RouterApi(format!(
                "HTTP {status} from {path}: {body}"
            )));
        }

        let body_text = resp.text().await.map_err(|e| {
            AppError::RouterApi(format!("Failed to read response body: {e}"))
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
                AppError::RouterApi(format!(
                    "Failed to parse response from {path}: {e}"
                ))
            })
    }

    // ── Convenience Endpoint Methods ──────────────────────────

    async fn system_resource(&self) -> Result<SystemResource, AppError> {
        let items = self.get::<SystemResource>("/system/resource").await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty system resource response".into()))
    }

    async fn system_identity(&self) -> Result<SystemIdentity, AppError> {
        let items = self.get::<SystemIdentity>("/system/identity").await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty system identity response".into()))
    }

    async fn ip_addresses(&self) -> Result<Vec<IpAddress>, AppError> {
        self.get::<IpAddress>("/ip/address").await
    }

    async fn interfaces(&self) -> Result<Vec<Interface>, AppError> {
        self.get::<Interface>("/interface").await
    }

    async fn routes(&self) -> Result<Vec<Route>, AppError> {
        self.get::<Route>("/ip/route").await
    }

    async fn arp_table(&self) -> Result<Vec<ArpEntry>, AppError> {
        self.get::<ArpEntry>("/ip/arp").await
    }

    async fn dns_config(&self) -> Result<DnsConfig, AppError> {
        let items = self.get::<DnsConfig>("/ip/dns").await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty DNS config response".into()))
    }

    async fn dhcp_leases(&self) -> Result<Vec<DhcpLease>, AppError> {
        self.get::<DhcpLease>("/ip/dhcp-server/lease").await
    }

    async fn wireless_registrations(&self) -> Result<Vec<WirelessRegistration>, AppError> {
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

    async fn firewall_connections(&self) -> Result<Vec<ConnectionEntry>, AppError> {
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

    // ── IPv6 Endpoint Methods ─────────────────────────────────

    async fn ipv6_addresses(&self) -> Result<Vec<Ipv6Address>, AppError> {
        match self.get::<Ipv6Address>("/ipv6/address").await {
            Ok(addrs) => Ok(addrs),
            Err(e) => {
                debug!("IPv6 addresses not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    async fn ipv6_routes(&self) -> Result<Vec<Ipv6Route>, AppError> {
        match self.get::<Ipv6Route>("/ipv6/route").await {
            Ok(routes) => Ok(routes),
            Err(e) => {
                debug!("IPv6 routes not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    async fn ipv6_neighbors(&self) -> Result<Vec<Ipv6Neighbor>, AppError> {
        match self.get::<Ipv6Neighbor>("/ipv6/neighbor").await {
            Ok(neighbors) => Ok(neighbors),
            Err(e) => {
                debug!("IPv6 neighbors not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    async fn ipv6_firewall_connections(&self) -> Result<Vec<Ipv6ConnectionEntry>, AppError> {
        match self.get::<Ipv6ConnectionEntry>("/ipv6/firewall/connection").await {
            Ok(conns) => Ok(conns),
            Err(e) => {
                debug!("IPv6 firewall connection tracking not available: {e}");
                Ok(Vec::new())
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// RouterBackend trait implementation
// ═══════════════════════════════════════════════════════════════════

#[async_trait]
impl RouterBackend for RouterOsClient {
    async fn connect(config: &RouterConnectionConfig) -> Result<Self, AppError> {
        let base_url = Self::base_url(config);
        let base_rest = format!(
            "{}://{}:{}",
            config.scheme, config.host, config.port
        );

        let http_client = build_http_client(config)?;

        // Strategy 1: Try token-based authentication
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
            &config.username,
            &config.password,
        )?;

        // Quick sanity check: does a simple GET work with Basic auth?
        let test_url = format!("{}/system/resource", base_url);
        match http_client
            .get(&test_url)
            .header(AUTHORIZATION, HeaderValue::from_str(&auth_header).map_err(|e| {
                AppError::InvalidData(format!("Invalid auth header: {e}"))
            })?)
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
                    config.username,
                );
                return Err(AppError::RouterApi(format!(
                    "Authentication failed (401). Ensure user '{}' has the 'rest-api' \
                     policy in RouterOS: /user/group add name=restapi policy=rest-api; \
                     /user/set {} group=restapi",
                    config.username, config.username,
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

    async fn fetch_all(&self) -> Result<RouterData, AppError> {
        // Fetch all IPv4 endpoints in parallel
        let (
            sys_result,
            identity_result,
            ips_result,
            interfaces_result,
            arp_result,
            dns_result,
            leases_result,
            wireless_result,
            routes_result,
            connections_result,
        ) = tokio::try_join!(
            self.system_resource(),
            self.system_identity(),
            self.ip_addresses(),
            self.interfaces(),
            self.arp_table(),
            self.dns_config(),
            self.dhcp_leases(),
            self.wireless_registrations(),
            self.routes(),
            self.firewall_connections(),
        )?;

        // Fetch IPv6 endpoints in a separate parallel batch
        // IPv6 methods use graceful degradation (return Ok(empty) on error)
        let (ipv6_ips_result, ipv6_routes_result, ipv6_neighbors_result, ipv6_connections_result) =
            tokio::join!(
                self.ipv6_addresses(),
                self.ipv6_routes(),
                self.ipv6_neighbors(),
                self.ipv6_firewall_connections(),
            );
        let ipv6_ips_result = ipv6_ips_result.unwrap_or_default();
        let ipv6_routes_result = ipv6_routes_result.unwrap_or_default();
        let ipv6_neighbors_result = ipv6_neighbors_result.unwrap_or_default();
        let ipv6_connections_result = ipv6_connections_result.unwrap_or_default();

        Ok(crate::backends::routeros::transform::routeros_to_router_data(
            sys_result,
            identity_result,
            ips_result,
            interfaces_result,
            arp_result,
            dns_result,
            leases_result,
            wireless_result,
            routes_result,
            connections_result,
            ipv6_ips_result,
            ipv6_routes_result,
            ipv6_neighbors_result,
            ipv6_connections_result,
        ))
    }

    async fn test_connection(
        config: &RouterConnectionConfig,
    ) -> Result<ConnectionTestResult, AppError> {
        let test_url = format!(
            "{}://{}:{}/rest/system/resource",
            config.scheme, config.host, config.port
        );

        let http_client = {
            let mut builder = reqwest::Client::builder()
                .timeout(Duration::from_secs(10));
            if config.scheme == "https" {
                builder = builder.danger_accept_invalid_certs(config.accept_invalid_certs);
            }
            builder.build().map_err(|e| AppError::Internal(e.to_string()))?
        };

        let auth_header = build_basic_auth_header(&config.username, &config.password)?;

        match http_client
            .get(&test_url)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_header).map_err(|e| {
                    AppError::Internal(format!("Invalid auth header: {e}"))
                })?,
            )
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                #[derive(Deserialize)]
                struct Resource {
                    #[serde(default, rename = "board-name")]
                    board_name: String,
                    #[serde(default)]
                    version: String,
                }
                let info = resp.json::<Vec<Resource>>().await.ok();
                let model = info.as_ref().and_then(|v| v.first()).map(|r| r.board_name.clone());
                let version = info.as_ref().and_then(|v| v.first()).map(|r| r.version.clone());

                Ok(ConnectionTestResult {
                    success: true,
                    model,
                    version,
                    error: None,
                })
            }
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                Ok(ConnectionTestResult {
                    success: false,
                    model: None,
                    version: None,
                    error: Some(format!("HTTP {status}: {body}")),
                })
            }
            Err(e) => Ok(ConnectionTestResult {
                success: false,
                model: None,
                version: None,
                error: Some(e.to_string()),
            }),
        }
    }

    fn router_type() -> RouterType {
        RouterType::RouterOs
    }
}

// ═══════════════════════════════════════════════════════════════════
// Auth Helpers
// ═══════════════════════════════════════════════════════════════════

/// Build the base HTTP client (without auth headers — those are per-request).
fn build_http_client(config: &RouterConnectionConfig) -> Result<reqwest::Client, AppError> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10));

    if config.scheme == "https" {
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
async fn try_token_auth(
    client: &reqwest::Client,
    base_rest: &str,
    config: &RouterConnectionConfig,
) -> Result<String, AppError> {
    let body = serde_json::json!({
        "name": config.username,
        "password": config.password,
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

                if let Ok(tok) = serde_json::from_str::<TokenResponse>(&text) {
                    if !tok.token.is_empty() {
                        return Ok(format!("Bearer {}", tok.token));
                    }
                }

                return build_basic_auth_header(&config.username, &config.password);
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
            ("name", config.username.as_str()),
            ("password", config.password.as_str()),
        ])
        .send()
        .await
    {
        if resp.status().is_success() {
            info!("Legacy auth succeeded");
            return build_basic_auth_header(&config.username, &config.password);
        }
    }

    Err(AppError::RouterApi(
        "No token auth endpoint available, will fall back to Basic auth".into(),
    ))
}
