use serde::{Deserialize, Serialize};

/// Envelope for all WebSocket messages sent from server to client.
///
/// The `type` field discriminates between snapshot, differential update,
/// and connection status notifications.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Full dashboard state — sent on initial WebSocket connection.
    #[serde(rename = "snapshot")]
    Snapshot {
        #[serde(rename = "data")]
        data: DashboardSnapshot,
    },
    /// Differential update — only changed fields since last poll.
    #[serde(rename = "update")]
    Update {
        #[serde(rename = "data")]
        data: DashboardUpdate,
    },
    /// RouterOS connectivity status notification.
    #[serde(rename = "connection_status")]
    ConnectionStatus {
        #[serde(rename = "routeros")]
        routeros: bool,
        #[serde(rename = "lastPoll")]
        last_poll: Option<String>,
    },
}

/// Complete dashboard state snapshot.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DashboardSnapshot {
    pub system: SystemInfo,
    pub gateway: GatewayInfo,
    pub interfaces: InterfaceSummary,
    pub isp: IspInfo,
    pub traffic: TrafficSnapshot,
    pub latency_probes: Vec<LatencyProbe>,
    pub wifi: WifiInfo,
    pub stability: IspStability,
    pub interface_statuses: Vec<InterfaceStatus>,
    pub timestamp: String,
    /// All WAN gateway entries (multi-WAN)
    #[serde(default)]
    pub wans: Vec<WanEntry>,
    /// Per-WAN ISP info (multi-WAN)
    #[serde(default)]
    pub wans_isp: Vec<WanIspInfo>,
    /// Per-WAN traffic points for the current poll (multi-WAN)
    #[serde(default)]
    pub wan_traffic_points: Vec<TrafficPoint>,
}

/// Differential update — every field is optional; only present when changed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DashboardUpdate {
    pub system: Option<SystemInfo>,
    pub gateway: Option<GatewayInfo>,
    pub interfaces: Option<InterfaceSummary>,
    pub isp: Option<IspInfo>,
    pub traffic: Option<TrafficPoint>,
    pub latency_probes: Option<Vec<LatencyProbe>>,
    pub wifi: Option<WifiInfo>,
    pub stability: Option<IspStability>,
    pub interface_statuses: Option<Vec<InterfaceStatus>>,
    pub timestamp: String,
    /// All WAN gateway entries (when changed)
    #[serde(default)]
    pub wans: Option<Vec<WanEntry>>,
    /// Per-WAN ISP info (when changed)
    #[serde(default)]
    pub wans_isp: Option<Vec<WanIspInfo>>,
    /// Per-WAN traffic points for this poll (always sent when available)
    #[serde(default)]
    pub wan_traffic_points: Option<Vec<TrafficPoint>>,
}

// ── System Info ──────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SystemInfo {
    /// Hardware model (e.g., "RB5009UG+S+IN")
    pub model: String,
    /// RouterOS version (e.g., "7.16")
    pub version: String,
    /// System uptime in human-readable form
    pub uptime: String,
    /// Uptime in seconds for easier computation
    pub uptime_seconds: u64,
    /// CPU load percentage (0–100)
    pub cpu_load: f64,
    /// Free memory in bytes
    pub free_memory: u64,
    /// Total memory in bytes
    pub total_memory: u64,
    /// Total HDD space in bytes
    pub total_hdd: u64,
    /// Free HDD space in bytes
    pub free_hdd: u64,
    /// Architecture name (e.g., "arm64")
    pub architecture: String,
    /// Board name from system resource
    pub board_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GatewayInfo {
    /// WAN interface name (primary WAN — preserved for backward compat)
    pub wan_interface: String,
    /// WAN IP address (primary WAN)
    pub wan_ip: String,
    /// Gateway IP address (primary WAN)
    pub gateway_ip: String,
    /// Whether the primary WAN link is up
    pub wan_online: bool,
    /// Number of IP addresses assigned (DHCP pool used)
    pub ip_allocations: u32,
    /// All WAN entries (multi-WAN support)
    #[serde(default)]
    pub wans: Vec<WanEntry>,
}

/// Per-WAN gateway status entry for multi-WAN deployments.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WanEntry {
    /// WAN interface name (e.g. "pppoe-cntelecom", "ether1")
    pub wan_name: String,
    /// IP address assigned to this WAN interface
    pub wan_ip: String,
    /// Gateway IP for this WAN
    pub gateway_ip: String,
    /// Whether this WAN link is up
    pub online: bool,
    /// Current download rate in bps
    pub download_bps: f64,
    /// Current upload rate in bps
    pub upload_bps: f64,
    /// Whether this is the primary (lowest-distance) default route
    pub is_primary: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct InterfaceSummary {
    /// Number of ethernet interfaces
    pub ethernet_count: u32,
    /// Number of wireless interfaces
    pub wifi_count: u32,
    /// Number of currently connected devices (ARP entries)
    pub connected_devices: u32,
    /// Whether WiFi is enabled
    pub wifi_online: bool,
}

// ── ISP & Probe ──────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IspInfo {
    /// ISP name (derived from system identity; primary WAN)
    pub name: String,
    /// Whether the ISP link is online (primary WAN)
    pub online: bool,
    /// Estimated monthly data usage in GB
    pub monthly_usage_gb: f64,
    /// Current download rate in bps (primary WAN)
    pub download_bps: f64,
    /// Current upload rate in bps (primary WAN)
    pub upload_bps: f64,
    /// Per-WAN ISP info (multi-WAN support)
    #[serde(default)]
    pub wans: Vec<WanIspInfo>,
}

/// Per-WAN ISP info for multi-WAN deployments.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WanIspInfo {
    /// WAN interface name this ISP corresponds to
    pub wan_name: String,
    /// ISP name for this WAN (derived from system identity)
    pub name: String,
    /// Whether this WAN link is online
    pub online: bool,
    /// Current download rate in bps for this WAN
    pub download_bps: f64,
    /// Current upload rate in bps for this WAN
    pub upload_bps: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LatencyProbe {
    /// Target name (e.g., "Cloudflare DNS", "Google DNS", "Alibaba")
    pub target: String,
    /// Target host/IP that was pinged
    pub host: String,
    /// Latency in milliseconds, or null if unreachable
    pub latency_ms: Option<f64>,
    /// Status: "good" (<30ms), "moderate" (30–100ms), "poor" (>100ms), "down"
    pub status: String,
    /// Category: "isp", "dns", "cloud", "cdn", "repo"
    pub category: String,
}

// ── Traffic ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrafficSnapshot {
    /// Array of traffic data points for initial chart population
    pub points: Vec<TrafficPoint>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TrafficPoint {
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Download rate in bps
    pub download_bps: f64,
    /// Upload rate in bps
    pub upload_bps: f64,
    /// WAN interface name (None = aggregate traffic)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_name: Option<String>,
}

// ── WiFi & Devices ───────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WifiInfo {
    /// WiFi interface count
    pub interface_count: u32,
    /// Connected WiFi clients
    pub client_count: u32,
    /// AP packet loss percentage
    pub packet_loss_pct: f64,
    /// AP retransmission rate percentage
    pub retransmit_pct: f64,
    /// List of connected devices
    pub devices: Vec<Device>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Device {
    /// MAC address
    pub mac: String,
    /// Hostname or device name
    pub hostname: String,
    /// IP address
    pub ip: String,
    /// Device type icon hint (e.g., "phone", "laptop", "router", "iot")
    pub device_type: String,
    /// Signal strength in dBm (only for wireless devices)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// Connection duration in seconds
    pub connected_duration: u64,
    /// DHCP lease status: "bound", "waiting", "offered" — null for static IPs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp_status: Option<String>,
    /// DHCP lease expiry time (e.g. "00:42:15") — null for static IPs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp_expires: Option<String>,
    /// Interface name the device is connected to (e.g. "bridge", "ether2", "wlan1")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// ARP status: "reachable", "permanent", "stale", "delay", "probe"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arp_status: Option<String>,
    /// User-assigned custom name (overrides hostname in UI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_name: Option<String>,
    /// User-assigned custom device type (overrides auto-detected type in UI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_type: Option<String>,
}

// ── Per-Interface Status ───────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct InterfaceStatus {
    /// Interface name (e.g. "ether2", "wlan1")
    pub name: String,
    /// Interface type: "ether", "wlan", "wifi", "bridge", "pppoe-out", etc.
    #[serde(rename = "type")]
    pub iface_type: String,
    /// Whether the interface is running
    pub running: bool,
    /// Current download rate in bps
    pub rx_bps: f64,
    /// Current upload rate in bps
    pub tx_bps: f64,
    /// Whether this interface is a WAN egress
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_wan: Option<bool>,
    /// WAN name this interface corresponds to (if it is a WAN)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_name: Option<String>,
}

// ── ISP Stability ────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IspStability {
    /// Overall online rate (0.0–100.0)
    pub online_rate: f64,
    /// Stability segments for the progress bar
    pub segments: Vec<StabilitySegment>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StabilitySegment {
    /// CSS color for this segment
    pub color: String,
    /// Numeric value (count of probes in this category)
    pub value: f64,
    /// Optional label
    pub label: Option<String>,
}

// ── Connection State (for the initial handshake) ─────────────

/// Sent by the server on initial WS connection to confirm state.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConnectionState {
    pub routeros_connected: bool,
    pub server_version: String,
    pub poll_interval_secs: u64,
}
