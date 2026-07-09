use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use base64::Engine;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::backends::routeros::models::*;
use crate::backends::{
    ConnectionTestResult, RouterBackend, RouterConnectionConfig, RouterData, RouterType,
};
use crate::error::AppError;

/// HTTP client wrapper for the MikroTik RouterOS REST API.
///
/// Authenticates using RouterOS REST Basic authentication.
pub struct RouterOsClient {
    base_url: String,
    http_client: reqwest::Client,
    auth_header: String,
}

impl RouterOsClient {
    /// Build a new client from a generic `RouterConnectionConfig`.
    fn base_url(config: &RouterConnectionConfig) -> Result<String, AppError> {
        let host = config.host.trim();
        let authority = match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(address)) => format!("[{address}]"),
            _ => host.to_string(),
        };
        let value = format!("{}://{}:{}/rest", config.scheme, authority, config.port);
        let parsed = url::Url::parse(&value)
            .map_err(|_| AppError::InvalidData("router target is not a valid host".into()))?;
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.host_str().is_none()
            || parsed.path() != "/rest"
        {
            return Err(AppError::InvalidData(
                "router target must be a hostname or IP address".into(),
            ));
        }
        Ok(value)
    }

    /// Generic GET request to a RouterOS REST API path.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Vec<T>, AppError> {
        let url = format!("{}{}", self.base_url, path);
        debug!("GET {}", url);

        let resp = self
            .http_client
            .get(&url)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&self.auth_header)
                    .map_err(|e| AppError::Internal(format!("Invalid auth header: {e}")))?,
            )
            .send()
            .await
            .map_err(|e| {
                warn!("RouterOS request failed: {e}");
                AppError::RouterApi(format!("Request to {} failed: {e}", path))
            })?;

        let status = resp.status();
        if !status.is_success() {
            warn!("RouterOS returned {status} for {path}");

            if status.as_u16() == 401 {
                return Err(AppError::RouterApi(format!(
                    "Authentication rejected by {path}. \
                     Verify the user has 'rest-api' policy in RouterOS."
                )));
            }

            return Err(AppError::RouterApi(format!("HTTP {status} from {path}")));
        }

        let body_bytes = read_limited_body(resp, 1024 * 1024).await?;
        let body_text = std::str::from_utf8(&body_bytes)
            .map_err(|_| AppError::RouterApi("RouterOS returned non-UTF-8 JSON".into()))?;

        if body_text.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str::<Vec<T>>(&body_text)
            .or_else(|_| serde_json::from_str::<T>(&body_text).map(|item| vec![item]))
            .map_err(|e| {
                warn!("Failed to deserialize RouterOS response: {e}");
                AppError::RouterApi(format!("Failed to parse response from {path}: {e}"))
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
        match self.get::<ConnectionEntry>("/ip/firewall/connection").await {
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
        match self
            .get::<Ipv6ConnectionEntry>("/ipv6/firewall/connection")
            .await
        {
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
        let base_url = Self::base_url(config)?;
        let http_client = build_http_client(config).await?;
        let auth_header = build_basic_auth_header(&config.username, &config.password)?;

        // Quick sanity check: does a simple GET work with Basic auth?
        let test_url = format!("{}/system/resource", base_url);
        match http_client
            .get(&test_url)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_header)
                    .map_err(|e| AppError::InvalidData(format!("Invalid auth header: {e}")))?,
            )
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!("RouterOS Basic auth verified");
            }
            Ok(resp) if resp.status().as_u16() == 401 => {
                warn!(
                    "RouterOS returned 401 for Basic auth. \
                     Please check:\n  \
                     - The user '{}' has 'rest-api' policy granted\n  \
                     - RouterOS version is 7.1 or newer\n  \
                     - The www service is enabled: /ip/service/print",
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
                warn!("RouterOS test request returned {status}");
                return Err(AppError::RouterApi(format!(
                    "RouterOS connection check returned HTTP {status}"
                )));
            }
            Err(e) => {
                warn!("RouterOS test request failed: {e}");
                return Err(AppError::RouterUnreachable);
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
        let (ipv6_ips_result, ipv6_routes_result, ipv6_neighbors_result, ipv6_connections_result) = tokio::join!(
            self.ipv6_addresses(),
            self.ipv6_routes(),
            self.ipv6_neighbors(),
            self.ipv6_firewall_connections(),
        );
        let ipv6_ips_result = ipv6_ips_result.unwrap_or_default();
        let ipv6_routes_result = ipv6_routes_result.unwrap_or_default();
        let ipv6_neighbors_result = ipv6_neighbors_result.unwrap_or_default();
        let ipv6_connections_result = ipv6_connections_result.unwrap_or_default();

        Ok(
            crate::backends::routeros::transform::routeros_to_router_data(
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
            ),
        )
    }

    async fn test_connection(
        config: &RouterConnectionConfig,
    ) -> Result<ConnectionTestResult, AppError> {
        let test_url = format!(
            "{}://{}:{}/rest/system/resource",
            config.scheme,
            format_url_host(&config.host),
            config.port
        );

        let http_client = build_http_client(config).await?;

        let auth_header = build_basic_auth_header(&config.username, &config.password)?;

        match http_client
            .get(&test_url)
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_header)
                    .map_err(|e| AppError::Internal(format!("Invalid auth header: {e}")))?,
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
                let body = read_limited_body(resp, 64 * 1024).await?;
                let info = serde_json::from_slice::<Vec<Resource>>(&body).ok();
                let model = info
                    .as_ref()
                    .and_then(|v| v.first())
                    .map(|r| r.board_name.clone());
                let version = info
                    .as_ref()
                    .and_then(|v| v.first())
                    .map(|r| r.version.clone());

                Ok(ConnectionTestResult {
                    success: true,
                    model,
                    version,
                    error: None,
                })
            }
            Ok(resp) => {
                let status = resp.status().as_u16();
                Ok(ConnectionTestResult {
                    success: false,
                    model: None,
                    version: None,
                    error: Some(format!("Router returned HTTP {status}")),
                })
            }
            Err(_) => Ok(ConnectionTestResult {
                success: false,
                model: None,
                version: None,
                error: Some("Router connection failed".to_string()),
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

/// Build a client whose DNS answers are allowlisted and pinned for its lifetime.
async fn build_http_client(config: &RouterConnectionConfig) -> Result<reqwest::Client, AppError> {
    let addresses = resolve_management_target(config).await?;
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(&config.host, &addresses);

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

async fn resolve_management_target(
    config: &RouterConnectionConfig,
) -> Result<Vec<std::net::SocketAddr>, AppError> {
    if config.scheme != "https" && !(config.scheme == "http" && config.allow_insecure_http) {
        return Err(AppError::InvalidData(
            "cleartext RouterOS HTTP is disabled".into(),
        ));
    }
    if config.host.trim().is_empty() || config.host != config.host.trim() {
        return Err(AppError::InvalidData("invalid router host".into()));
    }
    let addresses: Vec<_> = tokio::net::lookup_host((config.host.as_str(), config.port))
        .await
        .map_err(|_| AppError::RouterUnreachable)?
        .collect();
    if addresses.is_empty() {
        return Err(AppError::RouterUnreachable);
    }
    for address in &addresses {
        let ip = address.ip();
        let forbidden = ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || match ip {
                IpAddr::V4(ipv4) => ipv4.is_link_local() || ipv4.is_broadcast(),
                IpAddr::V6(ipv6) => ipv6.is_unicast_link_local() || ipv6.to_ipv4_mapped().is_some(),
            };
        if forbidden
            || !config
                .management_cidrs
                .iter()
                .any(|network| network.contains(&ip))
        {
            return Err(AppError::Forbidden(format!(
                "router target resolved outside ROUTER_MANAGEMENT_CIDRS ({ip})"
            )));
        }
    }
    Ok(addresses)
}

fn format_url_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(address)) => format!("[{address}]"),
        _ => host.to_string(),
    }
}

async fn read_limited_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, AppError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(AppError::RouterApi("RouterOS response is too large".into()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(AppError::RouterApi("RouterOS response is too large".into()));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(host: &str, cidr: &str) -> RouterConnectionConfig {
        RouterConnectionConfig {
            router_type: RouterType::RouterOs,
            host: host.to_string(),
            port: 443,
            scheme: "https".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
            accept_invalid_certs: false,
            management_cidrs: vec![cidr.parse().unwrap()],
            allow_insecure_http: false,
        }
    }

    #[tokio::test]
    async fn rejects_loopback_even_when_cidr_contains_it() {
        let error = resolve_management_target(&config("127.0.0.1", "127.0.0.0/8"))
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::Forbidden(_)));
    }

    #[tokio::test]
    async fn accepts_allowlisted_private_address() {
        let addresses = resolve_management_target(&config("192.168.88.1", "192.168.0.0/16"))
            .await
            .unwrap();
        assert_eq!(addresses[0].ip().to_string(), "192.168.88.1");
    }
}
