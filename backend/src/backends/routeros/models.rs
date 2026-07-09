use serde::Deserialize;

/// Raw response from `/rest/system/resource`.
///
/// RouterOS REST API returns all values as strings, so we keep them
/// as strings here and do type conversion in the transform layer.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemResource {
    #[serde(default)]
    pub uptime: String,
    #[serde(default, rename = "uptime_seconds")]
    pub uptime_seconds: String,
    #[serde(default, rename = "cpu-load")]
    pub cpu_load: String,
    #[serde(default, rename = "free-memory")]
    pub free_memory: String,
    #[serde(default, rename = "total-memory")]
    pub total_memory: String,
    #[serde(default, rename = "free-hdd-space")]
    pub free_hdd: String,
    #[serde(default, rename = "total-hdd-space")]
    pub total_hdd: String,
    #[serde(default, rename = "cpu-count")]
    pub cpu_count: String,
    #[serde(default, rename = "cpu-frequency")]
    pub cpu_frequency: String,
    #[serde(default, rename = "architecture-name")]
    pub architecture_name: String,
    #[serde(default, rename = "board-name")]
    pub board_name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default, rename = "platform")]
    pub platform: String,
}

/// Raw response from `/rest/system/identity`.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemIdentity {
    #[serde(default)]
    pub name: String,
}

/// Raw response from `/rest/ip/address`.
#[derive(Debug, Clone, Deserialize)]
pub struct IpAddress {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub actual_interface: String,
    #[serde(default)]
    pub disabled: String,
    #[serde(default)]
    pub dynamic: String,
    #[serde(default)]
    pub comment: String,
}

/// Raw response from `/rest/interface`.
#[derive(Debug, Clone, Deserialize)]
pub struct Interface {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub iface_type: String,
    #[serde(default)]
    pub mtu: String,
    #[serde(default)]
    pub mac_address: String,
    #[serde(default)]
    pub running: String,
    #[serde(default)]
    pub disabled: String,
    #[serde(default, rename = "rx-byte")]
    pub rx_byte: String,
    #[serde(default, rename = "tx-byte")]
    pub tx_byte: String,
    #[serde(default, rename = "rx-packet")]
    pub rx_packet: String,
    #[serde(default, rename = "tx-packet")]
    pub tx_packet: String,
    #[serde(default, rename = "rx-drop")]
    pub rx_drop: String,
    #[serde(default, rename = "tx-drop")]
    pub tx_drop: String,
    #[serde(default, rename = "tx-queue-drop")]
    pub tx_queue_drop: String,
    #[serde(default, rename = "last-link-up-time")]
    pub last_link_up_time: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub default_name: String,
}

/// Raw response from `/rest/ip/arp`.
#[derive(Debug, Clone, Deserialize)]
pub struct ArpEntry {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub dynamic: String,
    #[serde(default)]
    pub disabled: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default, rename = "dhcp-name")]
    pub dhcp_name: String,
}

/// Raw response from `/rest/ip/route`.
#[derive(Debug, Clone, Deserialize)]
pub struct Route {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default, rename = "dst-address")]
    pub dst_address: String,
    #[serde(default)]
    pub gateway: String,
    #[serde(default, rename = "gateway-status")]
    pub gateway_status: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default, rename = "active")]
    pub active: String,
    #[serde(default)]
    pub disabled: String,
    #[serde(default)]
    pub distance: String,
    #[serde(default)]
    pub comment: String,
}

/// Raw response from `/rest/ip/dns`.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub servers: String,
    #[serde(default, rename = "allow-remote-requests")]
    pub allow_remote_requests: String,
    #[serde(default, rename = "cache-size")]
    pub cache_size: String,
    #[serde(default, rename = "cache-max-ttl")]
    pub cache_max_ttl: String,
}

/// Raw response from `/rest/ip/dhcp-server/lease`.
#[derive(Debug, Clone, Deserialize)]
pub struct DhcpLease {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default, rename = "host-name")]
    pub host_name: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, rename = "expires-after")]
    pub expires_after: String,
    #[serde(default, rename = "active-mac-address")]
    pub active_mac_address: String,
    #[serde(default, rename = "active-address")]
    pub active_address: String,
    #[serde(default, rename = "active-server")]
    pub active_server: String,
}

/// Raw response from `/rest/system/health` (if available on the device).
#[derive(Debug, Clone, Deserialize)]
pub struct SystemHealth {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
    #[serde(default, rename = "type")]
    pub health_type: String,
}

/// Raw response from `/rest/interface/wireless/registration-table`
/// (if WiFi interfaces exist).
#[derive(Debug, Clone, Deserialize)]
pub struct WirelessRegistration {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default)]
    pub ap: String,
    #[serde(default, rename = "signal-strength")]
    pub signal_strength: String,
    #[serde(default, rename = "signal-to-noise")]
    pub signal_to_noise: String,
    #[serde(default, rename = "tx-rate")]
    pub tx_rate: String,
    #[serde(default, rename = "rx-rate")]
    pub rx_rate: String,
    #[serde(default)]
    pub uptime: String,
    #[serde(default, rename = "ack-timeout")]
    pub ack_timeout: String,
    #[serde(default, rename = "tx-ccq")]
    pub tx_ccq: String,
    #[serde(default, rename = "rx-ccq")]
    pub rx_ccq: String,
}

/// Raw response from `/rest/ip/firewall/connection`.
///
/// Minimal representation — we only count the entries for the dashboard.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionEntry {
    #[serde(rename = ".id")]
    pub id: String,
}

// ═══════════════════════════════════════════════════════════════════
// IPv6 models — mirroring the IPv4 structures above
// ═══════════════════════════════════════════════════════════════════

/// Raw response from `/rest/ipv6/address`.
#[derive(Debug, Clone, Deserialize)]
pub struct Ipv6Address {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub actual_interface: String,
    #[serde(default)]
    pub disabled: String,
    #[serde(default)]
    pub dynamic: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub advertise: String,
    #[serde(default, rename = "eui-64")]
    pub eui_64: String,
    #[serde(default, rename = "from-pool")]
    pub from_pool: String,
    #[serde(default, rename = "no-dad")]
    pub no_dad: String,
}

/// Raw response from `/rest/ipv6/route`.
#[derive(Debug, Clone, Deserialize)]
pub struct Ipv6Route {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default, rename = "dst-address")]
    pub dst_address: String,
    #[serde(default)]
    pub gateway: String,
    #[serde(default, rename = "gateway-status")]
    pub gateway_status: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub active: String,
    #[serde(default)]
    pub disabled: String,
    #[serde(default)]
    pub distance: String,
    #[serde(default)]
    pub comment: String,
}

/// Raw response from `/rest/ipv6/neighbor`.
#[derive(Debug, Clone, Deserialize)]
pub struct Ipv6Neighbor {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(default)]
    pub address: String,
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub dynamic: String,
    #[serde(default)]
    pub disabled: String,
    #[serde(default)]
    pub comment: String,
}

/// Raw response from `/rest/ipv6/firewall/connection`.
///
/// Minimal representation — we only count the entries for the dashboard.
#[derive(Debug, Clone, Deserialize)]
pub struct Ipv6ConnectionEntry {
    #[serde(rename = ".id")]
    pub id: String,
}
