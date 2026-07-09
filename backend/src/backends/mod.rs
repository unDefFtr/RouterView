use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

pub mod routeros;

/// The type of router operating system / management interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouterType {
    #[default]
    RouterOs,
    // Future: Ubiquiti, OpenWrt, Vyos, etc.
}

// ═══════════════════════════════════════════════════════════════════
// Vendor-neutral intermediate data types
// ═══════════════════════════════════════════════════════════════════

/// Vendor-neutral data collected from any router OS.
///
/// This is the single struct returned by `RouterBackend::fetch_all()`.
/// Fields are typed (bool, u64, f64) rather than raw strings — each backend
/// is responsible for parsing its own format into these neutral types.
///
/// Use `Option` or empty `Vec` when a particular router OS does not support
/// the corresponding data type (graceful degradation at the transform layer).
#[derive(Debug, Clone)]
pub struct RouterData {
    // ── System ────────────────────────────────────
    pub system: SystemData,
    pub identity: IdentityData,

    // ── IP addressing ─────────────────────────────
    pub ip_addresses: Vec<IpAddrEntry>,
    pub ipv6_addresses: Vec<Ipv6AddrEntry>,

    // ── Interfaces ────────────────────────────────
    pub interfaces: Vec<InterfaceEntry>,

    // ── Routing ───────────────────────────────────
    pub routes: Vec<RouteEntry>,
    pub ipv6_routes: Vec<RouteEntry>,

    // ── Neighbor tables ───────────────────────────
    pub arp_entries: Vec<NeighborEntry>,
    pub ipv6_neighbors: Vec<NeighborEntry>,

    // ── DNS ───────────────────────────────────────
    pub dns_servers: Vec<String>,

    // ── DHCP ──────────────────────────────────────
    pub dhcp_leases: Vec<DhcpLeaseEntry>,

    // ── Wireless ──────────────────────────────────
    pub wireless_clients: Vec<WirelessClientEntry>,

    // ── Connections / NAT ─────────────────────────
    pub connection_count: u32,
    pub ipv6_connection_count: u32,
}

// ── Sub-structs ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SystemData {
    pub uptime: String,
    pub uptime_seconds: u64,
    pub cpu_load: f64,
    pub free_memory: u64,
    pub total_memory: u64,
    pub free_hdd: u64,
    pub total_hdd: u64,
    pub cpu_count: u32,
    pub cpu_frequency: String,
    pub architecture_name: String,
    pub board_name: String,
    pub version: String,
    pub platform: String,
}

#[derive(Debug, Clone)]
pub struct IdentityData {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct IpAddrEntry {
    pub id: String,
    pub address: String,
    pub network: String,
    pub interface: String,
    pub actual_interface: String,
    pub disabled: bool,
    pub dynamic: bool,
    pub comment: String,
}

#[derive(Debug, Clone)]
pub struct Ipv6AddrEntry {
    pub id: String,
    pub address: String,
    pub network: String,
    pub interface: String,
    pub actual_interface: String,
    pub disabled: bool,
    pub dynamic: bool,
    pub comment: String,
    pub advertise: bool,
    pub eui_64: bool,
    pub from_pool: bool,
    pub no_dad: bool,
}

#[derive(Debug, Clone)]
pub struct InterfaceEntry {
    pub id: String,
    pub name: String,
    pub iface_type: String,
    pub mtu: u64,
    pub mac_address: String,
    pub running: bool,
    pub disabled: bool,
    pub rx_byte: u64,
    pub tx_byte: u64,
    pub rx_packet: u64,
    pub tx_packet: u64,
    pub rx_drop: u64,
    pub tx_drop: u64,
    pub tx_queue_drop: u64,
    pub last_link_up_time: String,
    pub comment: String,
    pub default_name: String,
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub id: String,
    pub dst_address: String,
    pub gateway: String,
    pub gateway_status: String, // "reachable" / "unreachable"
    pub interface: String,
    pub active: bool,
    pub disabled: bool,
    pub distance: u32,
    pub comment: String,
}

/// Represents both IPv4 ARP entries and IPv6 neighbor entries.
#[derive(Debug, Clone)]
pub struct NeighborEntry {
    pub id: String,
    pub address: String,
    pub mac_address: String,
    pub interface: String,
    pub status: String, // "reachable", "stale", "permanent", etc.
    pub dynamic: bool,
    pub disabled: bool,
    pub comment: String,
    pub dhcp_name: String, // IPv4 ARP only, empty for IPv6
}

#[derive(Debug, Clone)]
pub struct DhcpLeaseEntry {
    pub id: String,
    pub address: String,
    pub mac_address: String,
    pub host_name: String,
    pub server: String,
    pub status: String, // "bound", "waiting", etc.
    pub expires_after: String,
    pub active_mac_address: String,
    pub active_address: String,
    pub active_server: String,
}

#[derive(Debug, Clone)]
pub struct WirelessClientEntry {
    pub id: String,
    pub interface: String,
    pub mac_address: String,
    pub ap: String,
    pub signal_strength: Option<i32>,
    pub signal_to_noise: Option<i32>,
    pub tx_rate: i64,
    pub rx_rate: i64,
    pub uptime: String,
    pub tx_ccq: i32,
    pub rx_ccq: i32,
}

// ═══════════════════════════════════════════════════════════════════
// Router Backend Trait
// ═══════════════════════════════════════════════════════════════════

/// Generic connection configuration for any router backend.
#[derive(Debug, Clone)]
pub struct RouterConnectionConfig {
    pub router_type: RouterType,
    pub host: String,
    pub port: u16,
    pub scheme: String, // "http" or "https"
    pub username: String,
    pub password: String,
    pub accept_invalid_certs: bool,
}

/// Result from a connection test, returned by `RouterBackend::test_connection()`.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionTestResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The core trait every router OS backend must implement.
#[async_trait]
pub trait RouterBackend: Send + Sync + 'static {
    /// Create a new backend instance from configuration.
    async fn connect(config: &RouterConnectionConfig) -> Result<Self, AppError>
    where
        Self: Sized;

    /// Fetch _all_ available data from the router in a single call.
    /// The backend decides how to parallelize internally.
    async fn fetch_all(&self) -> Result<RouterData, AppError>;

    /// Test connectivity and return a human-readable device summary.
    /// Used by the `/api/config/test-connection` endpoint.
    /// This is an associated function (not a method) so it can be called
    /// without an existing backend instance.
    async fn test_connection(
        config: &RouterConnectionConfig,
    ) -> Result<ConnectionTestResult, AppError>
    where
        Self: Sized;

    /// The type identifier for this backend.
    fn router_type() -> RouterType
    where
        Self: Sized;
}
