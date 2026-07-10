use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use base64::Engine;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::backends::routeros::models::*;
use crate::backends::{
    ConnectionTestResult, CounterSampleTime, RouterBackend, RouterConnectionConfig, RouterData,
};
use crate::error::AppError;

const SYSTEM_RESOURCE_PATH: &str = "/system/resource?.proplist=uptime,cpu-load,free-memory,total-memory,free-hdd-space,total-hdd-space,architecture-name,board-name,version";
const SYSTEM_IDENTITY_PATH: &str = "/system/identity?.proplist=name";
const SYSTEM_ROUTERBOARD_PATH: &str = "/system/routerboard?.proplist=serial-number";
const IP_ADDRESS_PATH: &str = "/ip/address?.proplist=address,interface,actual-interface,disabled";
const INTERFACE_PATH: &str =
    "/interface?.proplist=.id,name,type,mac-address,running,rx-byte,tx-byte,default-name";
const IP_ROUTE_PATH: &str = "/ip/route?.proplist=.id,dst-address,gateway,immediate-gw,gateway-status,interface,active,disabled,distance";
const ARP_PATH: &str = "/ip/arp?.proplist=address,mac-address,interface,status,disabled";
const DHCP_LEASE_PATH: &str =
    "/ip/dhcp-server/lease?.proplist=mac-address,host-name,status,expires-after,active-mac-address";
const WIRELESS_REGISTRATION_PATH: &str =
    "/interface/wireless/registration-table?.proplist=mac-address,signal-strength,uptime";
const IPV6_ADDRESS_PATH: &str =
    "/ipv6/address?.proplist=address,interface,actual-interface,disabled";
const IPV6_ROUTE_PATH: &str = "/ipv6/route?.proplist=.id,dst-address,gateway,immediate-gw,gateway-status,interface,active,disabled,distance";
const IPV6_NEIGHBOR_PATH: &str =
    "/ipv6/neighbor?.proplist=address,mac-address,interface,status,disabled";
const FIREWALL_CONNECTION_IDS_PATH: &str = "/ip/firewall/connection?.proplist=.id";
const IPV6_FIREWALL_CONNECTION_IDS_PATH: &str = "/ipv6/firewall/connection?.proplist=.id";
const CONNECTION_COUNT_CACHE_TTL: Duration = Duration::from_secs(30);
const HARDWARE_IDENTITY_RETRY_TTL: Duration = Duration::from_secs(10 * 60);
const HARDWARE_IDENTITY_REFRESH_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Default)]
struct ConnectionCountCache {
    ipv4_sampled_at: Option<Instant>,
    ipv6_sampled_at: Option<Instant>,
    ipv4: u32,
    ipv6: u32,
}

#[derive(Default)]
struct HardwareIdentityCache {
    sampled_at: Option<Instant>,
    value: Option<String>,
}

/// HTTP client wrapper for the MikroTik RouterOS REST API.
///
/// Authenticates using RouterOS REST Basic authentication.
pub struct RouterOsClient {
    base_url: String,
    http_client: reqwest::Client,
    auth_header: String,
    connection_counts: Mutex<ConnectionCountCache>,
    hardware_identity: Mutex<HardwareIdentityCache>,
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

        serde_json::from_str::<Vec<T>>(body_text)
            .or_else(|_| serde_json::from_str::<T>(body_text).map(|item| vec![item]))
            .map_err(|e| {
                warn!("Failed to deserialize RouterOS response: {e}");
                AppError::RouterApi(format!("Failed to parse response from {path}: {e}"))
            })
    }

    // ── Convenience Endpoint Methods ──────────────────────────

    async fn system_resource(&self) -> Result<SystemResource, AppError> {
        let items = self.get::<SystemResource>(SYSTEM_RESOURCE_PATH).await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty system resource response".into()))
    }

    async fn system_identity(&self) -> Result<SystemIdentity, AppError> {
        let items = self.get::<SystemIdentity>(SYSTEM_IDENTITY_PATH).await?;
        items
            .into_iter()
            .next()
            .ok_or_else(|| AppError::InvalidData("Empty system identity response".into()))
    }

    async fn hardware_identity(&self) -> Option<String> {
        let now = Instant::now();
        {
            let cache = self.hardware_identity.lock().await;
            let ttl = if cache.value.is_some() {
                HARDWARE_IDENTITY_REFRESH_TTL
            } else {
                HARDWARE_IDENTITY_RETRY_TTL
            };
            if connection_cache_is_fresh(cache.sampled_at, now, ttl) {
                return cache.value.clone();
            }
        }

        let value = match self.get::<RouterboardInfo>(SYSTEM_ROUTERBOARD_PATH).await {
            Ok(items) => extract_hardware_identity(items),
            Err(error) => {
                debug!("RouterBOARD hardware identity not available: {error}");
                None
            }
        };
        let mut cache = self.hardware_identity.lock().await;
        cache.sampled_at = Some(Instant::now());
        cache.value = value.clone();
        value
    }

    async fn ip_addresses(&self) -> Result<Vec<IpAddress>, AppError> {
        self.get::<IpAddress>(IP_ADDRESS_PATH).await
    }

    async fn interfaces(&self) -> Result<(Vec<Interface>, CounterSampleTime), AppError> {
        let interfaces = self.get::<Interface>(INTERFACE_PATH).await?;
        Ok((
            interfaces,
            CounterSampleTime {
                monotonic: Instant::now(),
                unix_ms: chrono::Utc::now().timestamp_millis(),
            },
        ))
    }

    async fn routes(&self) -> Result<Vec<Route>, AppError> {
        self.get::<Route>(IP_ROUTE_PATH).await
    }

    async fn arp_table(&self) -> Result<Vec<ArpEntry>, AppError> {
        self.get::<ArpEntry>(ARP_PATH).await
    }

    async fn dhcp_leases(&self) -> Result<Vec<DhcpLease>, AppError> {
        self.get::<DhcpLease>(DHCP_LEASE_PATH).await
    }

    async fn wireless_registrations(&self) -> Result<Vec<WirelessRegistration>, AppError> {
        match self
            .get::<WirelessRegistration>(WIRELESS_REGISTRATION_PATH)
            .await
        {
            Ok(regs) => Ok(regs),
            Err(e) => {
                debug!("Wireless registration table not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    async fn firewall_connection_count(&self) -> Result<u32, AppError> {
        self.get::<ConnectionEntry>(FIREWALL_CONNECTION_IDS_PATH)
            .await
            .map(|connections| connections.len() as u32)
    }

    // ── IPv6 Endpoint Methods ─────────────────────────────────

    async fn ipv6_addresses(&self) -> Result<Vec<Ipv6Address>, AppError> {
        match self.get::<Ipv6Address>(IPV6_ADDRESS_PATH).await {
            Ok(addrs) => Ok(addrs),
            Err(e) => {
                debug!("IPv6 addresses not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    async fn ipv6_routes(&self) -> Result<Vec<Ipv6Route>, AppError> {
        match self.get::<Ipv6Route>(IPV6_ROUTE_PATH).await {
            Ok(routes) => Ok(routes),
            Err(e) => {
                debug!("IPv6 routes not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    async fn ipv6_neighbors(&self) -> Result<Vec<Ipv6Neighbor>, AppError> {
        match self.get::<Ipv6Neighbor>(IPV6_NEIGHBOR_PATH).await {
            Ok(neighbors) => Ok(neighbors),
            Err(e) => {
                debug!("IPv6 neighbors not available: {e}");
                Ok(Vec::new())
            }
        }
    }

    async fn ipv6_firewall_connection_count(&self) -> Result<u32, AppError> {
        self.get::<Ipv6ConnectionEntry>(IPV6_FIREWALL_CONNECTION_IDS_PATH)
            .await
            .map(|connections| connections.len() as u32)
    }

    async fn cached_connection_counts(&self) -> (u32, u32) {
        let now = Instant::now();
        let (refresh_ipv4, refresh_ipv6, cached_ipv4, cached_ipv6) = {
            let cache = self.connection_counts.lock().await;
            (
                !connection_cache_is_fresh(cache.ipv4_sampled_at, now, CONNECTION_COUNT_CACHE_TTL),
                !connection_cache_is_fresh(cache.ipv6_sampled_at, now, CONNECTION_COUNT_CACHE_TTL),
                cache.ipv4,
                cache.ipv6,
            )
        };

        let (ipv4, ipv6) = tokio::join!(
            async {
                if refresh_ipv4 {
                    Some(self.firewall_connection_count().await)
                } else {
                    None
                }
            },
            async {
                if refresh_ipv6 {
                    Some(self.ipv6_firewall_connection_count().await)
                } else {
                    None
                }
            }
        );
        if ipv4.is_none() && ipv6.is_none() {
            return (cached_ipv4, cached_ipv6);
        }

        let mut cache = self.connection_counts.lock().await;
        match ipv4 {
            Some(Ok(count)) => {
                cache.ipv4 = count;
                cache.ipv4_sampled_at = Some(Instant::now());
            }
            Some(Err(error)) => debug!("Firewall connection tracking not available: {error}"),
            None => {}
        }
        match ipv6 {
            Some(Ok(count)) => {
                cache.ipv6 = count;
                cache.ipv6_sampled_at = Some(Instant::now());
            }
            Some(Err(error)) => {
                debug!("IPv6 firewall connection tracking not available: {error}")
            }
            None => {}
        }
        (cache.ipv4, cache.ipv6)
    }
}

fn extract_hardware_identity(items: Vec<RouterboardInfo>) -> Option<String> {
    items
        .into_iter()
        .next()
        .map(|item| item.serial_number.trim().to_string())
        .filter(|serial| !serial.is_empty())
}

fn connection_cache_is_fresh(sampled_at: Option<Instant>, now: Instant, ttl: Duration) -> bool {
    sampled_at.is_some_and(|sampled| now.saturating_duration_since(sampled) < ttl)
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
        let test_url = format!("{base_url}{SYSTEM_RESOURCE_PATH}");
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
            connection_counts: Mutex::new(ConnectionCountCache::default()),
            hardware_identity: Mutex::new(HardwareIdentityCache::default()),
        })
    }

    async fn fetch_all(&self) -> Result<RouterData, AppError> {
        let primary = async {
            tokio::try_join!(
                self.system_resource(),
                self.system_identity(),
                self.ip_addresses(),
                self.interfaces(),
                self.arp_table(),
                self.dhcp_leases(),
                self.wireless_registrations(),
                self.routes(),
            )
        };
        let optional_ipv6 = async {
            tokio::join!(
                self.ipv6_addresses(),
                self.ipv6_routes(),
                self.ipv6_neighbors(),
            )
        };
        let (primary_result, ipv6_result, hardware_identity, connection_counts) = tokio::join!(
            primary,
            optional_ipv6,
            self.hardware_identity(),
            self.cached_connection_counts()
        );
        let (
            sys_result,
            identity_result,
            ips_result,
            interfaces_result,
            arp_result,
            leases_result,
            wireless_result,
            routes_result,
        ) = primary_result?;
        let (interfaces_result, counter_sample_time) = interfaces_result;
        let (ipv6_ips_result, ipv6_routes_result, ipv6_neighbors_result) = ipv6_result;
        let ipv6_ips_result = ipv6_ips_result.unwrap_or_default();
        let ipv6_routes_result = ipv6_routes_result.unwrap_or_default();
        let ipv6_neighbors_result = ipv6_neighbors_result.unwrap_or_default();

        Ok(
            crate::backends::routeros::transform::routeros_to_router_data(
                crate::backends::routeros::transform::RouterOsSnapshot {
                    counter_sample_time,
                    system: sys_result,
                    hardware_identity,
                    identity: identity_result,
                    ip_addresses: ips_result,
                    interfaces: interfaces_result,
                    arp_entries: arp_result,
                    dhcp_leases: leases_result,
                    wireless_registrations: wireless_result,
                    routes: routes_result,
                    connection_count: connection_counts.0,
                    ipv6_addresses: ipv6_ips_result,
                    ipv6_routes: ipv6_routes_result,
                    ipv6_neighbors: ipv6_neighbors_result,
                    ipv6_connection_count: connection_counts.1,
                },
            ),
        )
    }

    async fn test_connection(
        config: &RouterConnectionConfig,
    ) -> Result<ConnectionTestResult, AppError> {
        let test_url = format!("{}{}", Self::base_url(config)?, SYSTEM_RESOURCE_PATH);

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
    let addresses: Vec<_> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((config.host.as_str(), config.port)),
    )
    .await
    .map_err(|_| AppError::RouterUnreachable)?
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
            router_type: crate::backends::RouterType::RouterOs,
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

    #[test]
    fn every_collection_endpoint_uses_a_property_list() {
        let paths = [
            SYSTEM_RESOURCE_PATH,
            SYSTEM_IDENTITY_PATH,
            SYSTEM_ROUTERBOARD_PATH,
            IP_ADDRESS_PATH,
            INTERFACE_PATH,
            IP_ROUTE_PATH,
            ARP_PATH,
            DHCP_LEASE_PATH,
            WIRELESS_REGISTRATION_PATH,
            IPV6_ADDRESS_PATH,
            IPV6_ROUTE_PATH,
            IPV6_NEIGHBOR_PATH,
            FIREWALL_CONNECTION_IDS_PATH,
            IPV6_FIREWALL_CONNECTION_IDS_PATH,
        ];

        assert!(paths
            .iter()
            .all(|path| path.contains("?.proplist=") && !path.ends_with(".proplist=")));
        assert!(FIREWALL_CONNECTION_IDS_PATH.ends_with("=.id"));
        assert!(IPV6_FIREWALL_CONNECTION_IDS_PATH.ends_with("=.id"));
    }

    #[test]
    fn collection_property_lists_only_request_consumed_fields() {
        fn properties(path: &str) -> Vec<&str> {
            path.split_once("?.proplist=")
                .expect("collection path must include .proplist")
                .1
                .split(',')
                .collect()
        }

        assert_eq!(
            properties(SYSTEM_RESOURCE_PATH),
            [
                "uptime",
                "cpu-load",
                "free-memory",
                "total-memory",
                "free-hdd-space",
                "total-hdd-space",
                "architecture-name",
                "board-name",
                "version",
            ]
        );
        assert_eq!(properties(SYSTEM_IDENTITY_PATH), ["name"]);
        assert_eq!(properties(SYSTEM_ROUTERBOARD_PATH), ["serial-number"]);
        assert_eq!(
            properties(IP_ADDRESS_PATH),
            ["address", "interface", "actual-interface", "disabled"]
        );
        assert_eq!(
            properties(INTERFACE_PATH),
            [
                ".id",
                "name",
                "type",
                "mac-address",
                "running",
                "rx-byte",
                "tx-byte",
                "default-name",
            ]
        );
        assert_eq!(
            properties(IP_ROUTE_PATH),
            [
                ".id",
                "dst-address",
                "gateway",
                "immediate-gw",
                "gateway-status",
                "interface",
                "active",
                "disabled",
                "distance",
            ]
        );
        assert_eq!(
            properties(ARP_PATH),
            ["address", "mac-address", "interface", "status", "disabled",]
        );
        assert_eq!(
            properties(DHCP_LEASE_PATH),
            [
                "mac-address",
                "host-name",
                "status",
                "expires-after",
                "active-mac-address",
            ]
        );
        assert_eq!(
            properties(WIRELESS_REGISTRATION_PATH),
            ["mac-address", "signal-strength", "uptime"]
        );
        assert_eq!(
            properties(IPV6_ADDRESS_PATH),
            ["address", "interface", "actual-interface", "disabled"]
        );
        assert_eq!(properties(IPV6_ROUTE_PATH), properties(IP_ROUTE_PATH));
        assert_eq!(
            properties(IPV6_NEIGHBOR_PATH),
            ["address", "mac-address", "interface", "status", "disabled",]
        );
        assert_eq!(properties(FIREWALL_CONNECTION_IDS_PATH), [".id"]);
        assert_eq!(properties(IPV6_FIREWALL_CONNECTION_IDS_PATH), [".id"]);
    }

    #[test]
    fn normalizes_optional_routerboard_serial_number() {
        let identity = extract_hardware_identity(vec![RouterboardInfo {
            serial_number: "  ABC123  ".to_string(),
        }]);
        let empty = extract_hardware_identity(vec![RouterboardInfo {
            serial_number: "  ".to_string(),
        }]);

        assert_eq!(identity.as_deref(), Some("ABC123"));
        assert_eq!(empty, None);
        assert_eq!(extract_hardware_identity(Vec::new()), None);
    }

    #[test]
    fn connection_count_cache_is_bounded_to_thirty_seconds() {
        let now = Instant::now();
        let recent = now.checked_sub(Duration::from_secs(29)).unwrap();
        let expired = now.checked_sub(Duration::from_secs(30)).unwrap();

        assert!(connection_cache_is_fresh(
            Some(recent),
            now,
            CONNECTION_COUNT_CACHE_TTL
        ));
        assert!(!connection_cache_is_fresh(
            Some(expired),
            now,
            CONNECTION_COUNT_CACHE_TTL
        ));
        assert!(!connection_cache_is_fresh(
            None,
            now,
            CONNECTION_COUNT_CACHE_TTL
        ));
    }
}
