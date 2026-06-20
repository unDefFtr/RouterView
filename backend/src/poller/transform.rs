use std::collections::HashMap;
use std::net::IpAddr;

use tracing::debug;

use crate::error::AppError;
use crate::routeros::models::*;
use crate::ws::protocol::*;

/// ARP states that represent a currently-connected device.
/// RouterOS ARP statuses: permanent, reachable, stale, delay, probe, failed, incomplete.
/// We exclude "failed" (DHCP conflict / unreachable) and "incomplete" (unresolved).
const LIVE_ARP_STATES: &[&str] = &["permanent", "reachable", "stale", "delay", "probe"];

/// Transforms raw RouterOS REST API data into the dashboard-friendly
/// `DashboardSnapshot` structure.
///
/// This function is the bridge between the string-based RouterOS API
/// responses and the typed, normalized format the frontend expects.
pub fn to_dashboard_snapshot(
    sys: SystemResource,
    identity: SystemIdentity,
    ips: Vec<IpAddress>,
    interfaces: Vec<Interface>,
    arp: Vec<ArpEntry>,
    _dns: DnsConfig,
    leases: Vec<DhcpLease>,
    wireless_regs: Vec<WirelessRegistration>,
    routes: Vec<Route>,
    prev_counters: Option<&HashMap<String, (u64, u64)>>, // (rx_bytes, tx_bytes) from last tick
    latency_results: Vec<LatencyProbe>,
    stability: IspStability,
) -> Result<DashboardSnapshot, AppError> {
    let now = chrono::Utc::now().to_rfc3339();

    // ── Find the default-route WAN ───────────────────────
    let wan_info = resolve_wan(&ips, &interfaces, &routes);

    // ── System Info ───────────────────────────────────────
    let system = extract_system_info(&sys);

    // ── Gateway Info (from routing table) ────────────────
    let gateway = extract_gateway(&wan_info, &leases);

    // ── Interface Summary ─────────────────────────────────
    let interface_summary = extract_interface_summary(&interfaces, &arp);

    // ── ISP Info ──────────────────────────────────────────
    let isp = extract_isp(&identity, &wan_info, prev_counters);

    // ── Traffic (WAN interface only, from routing table) ──
    let traffic = extract_traffic(&wan_info, prev_counters, &now);

    // ── WiFi Info ─────────────────────────────────────────
    let wifi = extract_wifi(&wireless_regs, &arp, &leases);

    // ── Per-interface status with rates ───────────────────
    let interface_statuses = extract_interface_statuses(&interfaces, prev_counters);

    Ok(DashboardSnapshot {
        system,
        gateway,
        interfaces: interface_summary,
        isp,
        traffic,
        latency_probes: latency_results,
        wifi,
        stability,
        interface_statuses,
        timestamp: now,
    })
}

// ── WAN Resolution ───────────────────────────────────────────────

/// The resolved WAN — derived from the default route in the routing table.
struct WanInfo {
    /// Interface name of the default-route egress
    interface_name: String,
    /// The IP address assigned to that interface
    ip_address: String,
    /// The gateway address from the routing table
    gateway: String,
    /// Whether the interface is running
    online: bool,
    /// Matching Interface struct (for RX/TX byte counters)
    iface: Option<Interface>,
}

/// Look at `/ip/route` for the active default route (`dst-address=0.0.0.0/0`).
/// From it we get the real gateway IP and egress interface name, then match
/// an IP from `/ip/address` that lives on that interface.
///
/// Fallback chain:
///   1. Active default route with gateway-status=reachable
///   2. Any active default route
///   3. First running ethernet interface with a non-loopback IP
fn resolve_wan(ips: &[IpAddress], interfaces: &[Interface], routes: &[Route]) -> WanInfo {
    // ── Step 1: find the default route ─────────────────────
    let default_route = routes
        .iter()
        .filter(|r| {
            r.dst_address == "0.0.0.0/0"
                && r.active != "false"
                && r.disabled != "true"
                && !r.gateway.is_empty()
        })
        .max_by_key(|r| {
            // Prefer reachable gateways
            if r.gateway_status == "reachable" { 10u8 } else { 0u8 }
        });

    let (default_gateway, route_iface_name) = if let Some(r) = default_route {
        // RouterOS PPPoE/PPTP/L2TP: the route's `gateway` field contains the virtual
        // interface name (e.g. "pppoe-cntelecom") and `interface` is empty.
        // Detect this: if `interface` is empty and `gateway` isn't an IP address,
        // use `gateway` as the interface name.
        let iface_from_route = if r.interface.is_empty() && r.gateway.parse::<IpAddr>().is_err() {
            r.gateway.clone()
        } else {
            r.interface.clone()
        };
        (r.gateway.clone(), iface_from_route)
    } else {
        // No default route at all — fall back to heuristic
        return fallback_wan(ips, interfaces);
    };

    debug!(
        "Default route: gateway={}, interface={}",
        default_gateway, route_iface_name,
    );

    // ── Step 2: find the IP on that egress interface ───────
    let ip_entry = ips
        .iter()
        .filter(|ip| ip.disabled != "true")
        .find(|ip| {
            let ifname = if ip.actual_interface.is_empty() {
                &ip.interface
            } else {
                &ip.actual_interface
            };
            ifname == &route_iface_name
        });

    let ip_address = ip_entry
        .map(|e| extract_ip_from_cidr(&e.address))
        .unwrap_or_else(|| "—".to_string());

    // ── Step 3: find the matching Interface struct ─────────
    let iface = interfaces
        .iter()
        .find(|i| i.name == route_iface_name)
        .cloned();

    let online = iface
        .as_ref()
        .map(|i| i.running == "true")
        .unwrap_or(false);

    let wan_info = WanInfo {
        interface_name: route_iface_name.clone(),
        ip_address,
        gateway: default_gateway,
        online,
        iface,
    };

    debug!(
        "WAN resolved via default route: iface={}, ip={}, gw={}, online={}",
        route_iface_name, wan_info.ip_address, wan_info.gateway, wan_info.online
    );

    wan_info
}

/// Fallback when no default route exists.
fn fallback_wan(ips: &[IpAddress], interfaces: &[Interface]) -> WanInfo {
    // Pick the first running ethernet interface that has an IP
    for iface in interfaces
        .iter()
        .filter(|i| i.running == "true" && i.disabled != "true")
    {
        if let Some(ip) = ips.iter().find(|ip| {
            let ifname = if ip.actual_interface.is_empty() {
                &ip.interface
            } else {
                &ip.actual_interface
            };
            ifname == &iface.name && ip.disabled != "true"
        }) {
            let ip_addr = extract_ip_from_cidr(&ip.address);
            let gateway = extract_first_ip_in_subnet(&ip.address);
            return WanInfo {
                interface_name: iface.name.clone(),
                ip_address: ip_addr,
                gateway,
                online: true,
                iface: Some(iface.clone()),
            };
        }
    }

    WanInfo {
        interface_name: "—".into(),
        ip_address: "—".into(),
        gateway: "—".into(),
        online: false,
        iface: None,
    }
}

// ── Extraction Helpers ───────────────────────────────────────

fn extract_system_info(sys: &SystemResource) -> SystemInfo {
    let uptime_str = parse_routeros_uptime(&sys.uptime);
    let uptime_seconds = parse_routeros_uptime_to_seconds(&sys.uptime);

    SystemInfo {
        model: sys.board_name.clone(),
        version: sys.version.clone(),
        uptime: uptime_str,
        uptime_seconds,
        cpu_load: parse_f64(&sys.cpu_load),
        free_memory: parse_u64(&sys.free_memory),
        total_memory: parse_u64(&sys.total_memory),
        total_hdd: parse_u64(&sys.total_hdd),
        free_hdd: parse_u64(&sys.free_hdd),
        architecture: sys.architecture_name.clone(),
        board_name: sys.board_name.clone(),
    }
}

fn extract_gateway(wan: &WanInfo, leases: &[DhcpLease]) -> GatewayInfo {
    let ip_allocations = leases
        .iter()
        .filter(|l| l.status == "bound")
        .count() as u32;

    GatewayInfo {
        wan_interface: wan.interface_name.clone(),
        wan_ip: wan.ip_address.clone(),
        gateway_ip: wan.gateway.clone(),
        wan_online: wan.online,
        ip_allocations,
    }
}

fn extract_interface_summary(interfaces: &[Interface], arp: &[ArpEntry]) -> InterfaceSummary {
    let ethernet_count = interfaces
        .iter()
        .filter(|i| i.iface_type == "ether" || i.default_name.starts_with("ether"))
        .count() as u32;

    let wifi_count = interfaces
        .iter()
        .filter(|i| {
            i.iface_type == "wlan"
                || i.iface_type == "wifi"
                || i.default_name.starts_with("wlan")
                || i.default_name.starts_with("wifi")
        })
        .count() as u32;

    // Active ARP entries = connected devices.
    let connected_devices = arp
        .iter()
        .filter(|a| {
            LIVE_ARP_STATES.contains(&a.status.as_str())
                && a.disabled != "true"
                && !a.mac_address.is_empty()
        })
        .count() as u32;

    let wifi_online = interfaces
        .iter()
        .any(|i| {
            (i.iface_type == "wlan" || i.iface_type == "wifi")
                && i.running == "true"
        });

    InterfaceSummary {
        ethernet_count,
        wifi_count,
        connected_devices,
        wifi_online,
    }
}

/// Build per-interface status with real-time RX/TX rates.
fn extract_interface_statuses(
    interfaces: &[Interface],
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
) -> Vec<InterfaceStatus> {
    let mut statuses: Vec<InterfaceStatus> = interfaces
        .iter()
        .filter(|i| i.default_name != "lo" && i.name != "lo") // skip loopback
        .filter_map(|iface| {
            let (rx_bps, tx_bps) = prev_counters
                .and_then(|prev| prev.get(&iface.name))
                .map(|(prev_rx, prev_tx)| {
                    let rx = parse_u64(&iface.rx_byte);
                    let tx = parse_u64(&iface.tx_byte);
                    let rx_diff = rx.saturating_sub(*prev_rx);
                    let tx_diff = tx.saturating_sub(*prev_tx);
                    (rx_diff as f64 * 8.0 / 3.0, tx_diff as f64 * 8.0 / 3.0)
                })
                .unwrap_or((0.0, 0.0));

            Some(InterfaceStatus {
                name: iface.name.clone(),
                iface_type: iface.iface_type.clone(),
                running: iface.running == "true",
                rx_bps,
                tx_bps,
            })
        })
        .collect();

    // Sort: WAN/PPP first, then ether, then wlan/wifi, then bridge, then others
    statuses.sort_by(|a, b| {
        fn rank(t: &str) -> u8 {
            match t {
                "pppoe-out" | "pppoe-in" | "l2tp-out" | "sstp-out" => 0,
                "ether" => 1,
                "wlan" | "wifi" => 2,
                "bridge" => 3,
                _ => 4,
            }
        }
        rank(&a.iface_type)
            .cmp(&rank(&b.iface_type))
            .then(a.name.cmp(&b.name))
    });

    statuses
}

fn extract_isp(
    identity: &SystemIdentity,
    wan: &WanInfo,
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
) -> IspInfo {
    let isp_name = if identity.name.is_empty() {
        "Unknown ISP".to_string()
    } else {
        identity.name.clone()
    };

    // Only measure the routing-table-identified WAN interface.
    let (download_bps, upload_bps) = compute_wan_rate(wan, prev_counters)
        .unwrap_or((0.0, 0.0));

    IspInfo {
        name: isp_name,
        online: wan.online,
        monthly_usage_gb: 0.0,
        download_bps,
        upload_bps,
    }
}

/// Compute the RX/TX rate for the single WAN interface identified by the routing table.
fn compute_wan_rate(
    wan: &WanInfo,
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
) -> Option<(f64, f64)> {
    let iface = wan.iface.as_ref()?;
    let prev = prev_counters?;
    let (prev_rx, prev_tx) = prev.get(&iface.name)?;
    let rx = parse_u64(&iface.rx_byte);
    let tx = parse_u64(&iface.tx_byte);
    let rx_diff = rx.saturating_sub(*prev_rx);
    let tx_diff = tx.saturating_sub(*prev_tx);
    Some((rx_diff as f64 * 8.0 / 3.0, tx_diff as f64 * 8.0 / 3.0))
}

fn extract_traffic(
    wan: &WanInfo,
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    now: &str,
) -> TrafficSnapshot {
    let (download_bps, upload_bps) = compute_wan_rate(wan, prev_counters)
        .unwrap_or((0.0, 0.0));

    debug!(
        "Traffic: down={:.1} Kbps, up={:.1} Kbps (wan={})",
        download_bps / 1000.0,
        upload_bps / 1000.0,
        wan.interface_name,
    );

    let points = if download_bps > 0.0 || upload_bps > 0.0 {
        vec![TrafficPoint {
            timestamp: now.to_string(),
            download_bps,
            upload_bps,
        }]
    } else {
        vec![]
    };

    TrafficSnapshot { points }
}

fn extract_wifi(
    wireless_regs: &[WirelessRegistration],
    arp: &[ArpEntry],
    leases: &[DhcpLease],
) -> WifiInfo {
    let client_count = wireless_regs.len() as u32;

    // Build device list from wireless registrations + ARP + DHCP leases
    let mut devices: Vec<Device> = Vec::new();

    // Start with wireless registrations (most accurate for WiFi clients)
    for reg in wireless_regs {
        // Find matching DHCP lease
        let lease = leases.iter().find(|l| {
            l.active_mac_address.to_lowercase() == reg.mac_address.to_lowercase()
                || l.mac_address.to_lowercase() == reg.mac_address.to_lowercase()
        });

        let hostname = lease
            .map(|l| {
                if l.host_name.is_empty() { "Unknown" } else { &l.host_name }
            })
            .unwrap_or("Unknown");

        // Find matching ARP entry
        let arp_entry = arp
            .iter()
            .find(|a| a.mac_address.to_lowercase() == reg.mac_address.to_lowercase());

        let ip = arp_entry
            .map(|a| a.address.clone())
            .unwrap_or_else(|| "—".to_string());

        let signal = reg.signal_strength.parse::<i32>().ok();

        devices.push(Device {
            mac: reg.mac_address.clone(),
            hostname: hostname.to_string(),
            ip,
            device_type: infer_device_type(hostname, &reg.mac_address),
            signal,
            connected_duration: parse_routeros_uptime_to_seconds(&reg.uptime),
            dhcp_status: lease.map(|l| l.status.clone()).filter(|s| !s.is_empty()),
            dhcp_expires: lease.map(|l| l.expires_after.clone()).filter(|s| !s.is_empty()),
            interface: arp_entry.map(|a| a.interface.clone()).filter(|s| !s.is_empty()),
            arp_status: arp_entry.map(|a| a.status.clone()).filter(|s| !s.is_empty()),
            custom_name: None,
            custom_type: None,
        });
    }

    // Also include wired ARP entries (devices on LAN ports)
    let wifi_macs: Vec<String> = wireless_regs.iter().map(|r| r.mac_address.to_lowercase()).collect();

    for entry in arp.iter().filter(|a| {
        LIVE_ARP_STATES.contains(&a.status.as_str())
            && a.disabled != "true"
            && !a.mac_address.is_empty()
            && !wifi_macs.contains(&a.mac_address.to_lowercase())
    }) {
        let lease = leases.iter().find(|l| {
            l.active_mac_address.to_lowercase() == entry.mac_address.to_lowercase()
                || l.mac_address.to_lowercase() == entry.mac_address.to_lowercase()
        });

        let hostname = lease
            .map(|l| {
                if l.host_name.is_empty() { "Unknown" } else { &l.host_name }
            })
            .unwrap_or("Unknown");

        devices.push(Device {
            mac: entry.mac_address.clone(),
            hostname: hostname.to_string(),
            ip: entry.address.clone(),
            device_type: infer_device_type(hostname, &entry.mac_address),
            signal: None,
            connected_duration: 0,
            dhcp_status: lease.map(|l| l.status.clone()).filter(|s| !s.is_empty()),
            dhcp_expires: lease.map(|l| l.expires_after.clone()).filter(|s| !s.is_empty()),
            interface: Some(entry.interface.clone()).filter(|s| !s.is_empty()),
            arp_status: Some(entry.status.clone()).filter(|s| !s.is_empty()),
            custom_name: None,
            custom_type: None,
        });
    }

    WifiInfo {
        interface_count: 0,
        client_count,
        packet_loss_pct: 0.0,
        retransmit_pct: 0.0,
        devices,
    }
}

// ── Utility Functions ────────────────────────────────────────

/// Parse a RouterOS uptime string like "2d20h12m20s" into human-readable form.
fn parse_routeros_uptime(raw: &str) -> String {
    let total_secs = parse_routeros_uptime_to_seconds(raw);
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;

    if days > 0 {
        format!("{}天{}小时", days, hours)
    } else if hours > 0 {
        format!("{}小时{}分钟", hours, mins)
    } else {
        format!("{}分钟", mins)
    }
}

/// Parse RouterOS uptime string to total seconds.
fn parse_routeros_uptime_to_seconds(raw: &str) -> u64 {
    let raw = raw.to_lowercase();
    let mut total = 0u64;

    let mut current = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if ch.is_ascii_alphabetic() {
            let val: u64 = current.parse().unwrap_or(0);
            match ch {
                'w' => total += val * 604800,
                'd' => total += val * 86400,
                'h' => total += val * 3600,
                'm' => total += val * 60,
                's' => total += val,
                _ => {}
            }
            current.clear();
        }
    }
    total
}

/// Extract IP address from CIDR notation (e.g., "192.168.1.1/24" → "192.168.1.1").
fn extract_ip_from_cidr(cidr: &str) -> String {
    cidr.split('/').next().unwrap_or(cidr).to_string()
}

/// Extract first IP in subnet (network address + 1) — used only in fallback path.
fn extract_first_ip_in_subnet(cidr: &str) -> String {
    let ip_str = extract_ip_from_cidr(cidr);
    let parts: Vec<&str> = ip_str.split('.').collect();
    if parts.len() == 4 {
        if let Ok(_last) = parts[3].parse::<u8>() {
            return format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], 1u8);
        }
    }
    ip_str
}

/// Infer device type from hostname and MAC address.
fn infer_device_type(hostname: &str, mac: &str) -> String {
    let h = hostname.to_lowercase();

    if h.contains("iphone") || h.contains("android") || h.contains("phone") || h.contains("mobile")
    {
        return "phone".to_string();
    }
    if h.contains("ipad") || h.contains("tablet") {
        return "tablet".to_string();
    }
    if h.contains("macbook") || h.contains("laptop") || h.contains("notebook") || h.contains("thinkpad")
    {
        return "laptop".to_string();
    }
    if h.contains("raspberry") || h.contains("rpi") || h.contains("pi-hole") {
        return "iot".to_string();
    }
    if h.contains("router") || h.contains("mikrotik") || h.contains("rb") {
        return "router".to_string();
    }
    if h.contains("switch") {
        return "switch".to_string();
    }
    if h.contains("tv") || h.contains("apple tv") || h.contains("roku") || h.contains("chromecast")
    {
        return "media".to_string();
    }
    if h.contains("camera") || h.contains("cam") || h.contains("nest") {
        return "camera".to_string();
    }
    if h.contains("printer") {
        return "printer".to_string();
    }

    // Fallback: check MAC OUI for known manufacturers
    let mac_prefix = mac[..8].to_lowercase();
    if mac_prefix.starts_with("dc:a6:32") || mac_prefix.starts_with("e4:5f:01") {
        // Raspberry Pi
        return "iot".to_string();
    }
    if mac_prefix.starts_with("f0:18:98") || mac_prefix.starts_with("a4:d1:d2") {
        // Apple
        return "apple".to_string();
    }

    "desktop".to_string()
}

/// Create a default set of latency probes for well-known DNS/CDN targets.
pub fn default_latency_probe_targets(dns_servers: &[String]) -> Vec<(String, String, String)> {
    let mut targets: Vec<(String, String, String)> = Vec::new();

    // Category: public DNS
    targets.push(("Cloudflare DNS".into(), "1.1.1.1".into(), "dns".into()));
    targets.push(("Google DNS".into(), "8.8.8.8".into(), "dns".into()));
    targets.push(("Quad9 DNS".into(), "9.9.9.9".into(), "dns".into()));
    targets.push(("AliDNS".into(), "223.5.5.5".into(), "dns".into()));
    targets.push(("DNSPod".into(), "119.29.29.29".into(), "dns".into()));

    // Category: cloud
    targets.push(("AWS".into(), "amazon.com".into(), "cloud".into()));
    targets.push(("Azure".into(), "azure.microsoft.com".into(), "cloud".into()));
    targets.push(("Alibaba Cloud".into(), "aliyun.com".into(), "cloud".into()));
    targets.push(("Tencent Cloud".into(), "cloud.tencent.com".into(), "cloud".into()));

    // Category: CDN
    targets.push(("Cloudflare".into(), "cloudflare.com".into(), "cdn".into()));
    targets.push(("Akamai".into(), "akamai.com".into(), "cdn".into()));
    targets.push(("Fastly".into(), "fastly.com".into(), "cdn".into()));

    // Category: repo
    targets.push(("GitHub".into(), "github.com".into(), "repo".into()));
    targets.push(("Docker Hub".into(), "hub.docker.com".into(), "repo".into()));
    targets.push(("npm Registry".into(), "registry.npmjs.org".into(), "repo".into()));
    targets.push(("crates.io".into(), "crates.io".into(), "repo".into()));

    // User-configured DNS servers from RouterOS
    for (i, server) in dns_servers.iter().enumerate() {
        targets.push((
            format!("ISP DNS {}", i + 1),
            server.clone(),
            "isp".into(),
        ));
    }

    targets
}

fn parse_f64(s: &str) -> f64 {
    s.parse().unwrap_or(0.0)
}

fn parse_u64(s: &str) -> u64 {
    s.parse().unwrap_or(0)
}
