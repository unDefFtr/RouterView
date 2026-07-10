use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Instant;

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
    pub counter_sample_time: CounterSampleTime,
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

    // ── DHCP ──────────────────────────────────────
    pub dhcp_leases: Vec<DhcpLeaseEntry>,

    // ── Wireless ──────────────────────────────────
    pub wireless_clients: Vec<WirelessClientEntry>,

    // ── Connections / NAT ─────────────────────────
    pub connection_count: u32,
    pub ipv6_connection_count: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct CounterSampleTime {
    pub monotonic: Instant,
    pub unix_ms: i64,
}

// ── Sub-structs ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SystemData {
    /// Stable hardware identity when the backend exposes one (for example,
    /// RouterBOARD's serial number). Virtual routers may not have one.
    pub hardware_identity: Option<String>,
    pub uptime: String,
    pub uptime_seconds: Option<u64>,
    pub cpu_load: f64,
    pub free_memory: u64,
    pub total_memory: u64,
    pub free_hdd: u64,
    pub total_hdd: u64,
    pub architecture_name: String,
    pub board_name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct IdentityData {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct IpAddrEntry {
    pub address: String,
    pub interface: String,
    pub actual_interface: String,
    pub disabled: bool,
}

#[derive(Debug, Clone)]
pub struct Ipv6AddrEntry {
    pub address: String,
    pub interface: String,
    pub actual_interface: String,
    pub disabled: bool,
}

#[derive(Debug, Clone)]
pub struct InterfaceEntry {
    pub id: String,
    pub name: String,
    pub iface_type: String,
    pub mac_address: String,
    pub running: bool,
    pub rx_byte: Option<u64>,
    pub tx_byte: Option<u64>,
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
}

/// Represents both IPv4 ARP entries and IPv6 neighbor entries.
#[derive(Debug, Clone)]
pub struct NeighborEntry {
    pub address: String,
    pub mac_address: String,
    pub interface: String,
    pub status: String, // "reachable", "stale", "permanent", etc.
    pub disabled: bool,
}

#[derive(Debug, Clone)]
pub struct DhcpLeaseEntry {
    pub mac_address: String,
    pub host_name: String,
    pub status: String, // "bound", "waiting", etc.
    pub expires_after: String,
    pub active_mac_address: String,
}

#[derive(Debug, Clone)]
pub struct WirelessClientEntry {
    pub mac_address: String,
    pub signal_strength: Option<i32>,
    pub uptime: String,
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
    /// Deployment allowlist for resolved management addresses.
    pub management_cidrs: Vec<ipnet::IpNet>,
    /// Explicit deployment opt-in for cleartext HTTP.
    pub allow_insecure_http: bool,
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
}
