use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tracing::debug;

use crate::backends::*;
use crate::db::TrafficDb;
use crate::error::AppError;
use crate::ws::protocol::*;

/// Neighbor states that represent a currently-connected device.
/// RouterOS ARP / IPv6 neighbor statuses: permanent, reachable, stale, delay, probe,
/// failed, incomplete. We exclude "failed" (DHCP conflict / unreachable) and
/// "incomplete" (unresolved).
const LIVE_NEIGHBOR_STATES: &[&str] = &["permanent", "reachable", "stale", "delay", "probe"];

/// Transforms vendor-neutral `RouterData` into the dashboard-friendly
/// `DashboardSnapshot` structure.
///
/// This function is the bridge between the typed, normalized data from
/// any router backend and the format the frontend expects.
pub fn to_dashboard_snapshot(
    data: RouterData,
    prev_counters: Option<&HashMap<String, (u64, u64)>>, // (rx_bytes, tx_bytes) from last tick
    latency_results: Vec<LatencyProbe>,
    stability: IspStability,
    traffic_db: &TrafficDb,
    poll_interval_secs: f64,
) -> Result<DashboardSnapshot, AppError> {
    let now = chrono::Utc::now().to_rfc3339();

    // ── Find all WANs from the routing table ──────────────
    let all_wans = resolve_all_wans(&data.ip_addresses, &data.interfaces, &data.routes, &data.ipv6_addresses, &data.ipv6_routes);
    let primary_wan = all_wans
        .first()
        .cloned()
        .unwrap_or_else(|| fallback_wan(&data.ip_addresses, &data.interfaces, &data.ipv6_addresses));

    // ── System Info ───────────────────────────────────────
    let system = extract_system_info(&data.system);

    // ── Gateway Info (primary + all WAN entries) ──────────
    let gateway = extract_gateway(&primary_wan, &all_wans, &data.dhcp_leases, prev_counters, poll_interval_secs);

    // ── Interface Summary ─────────────────────────────────
    let interface_summary = extract_interface_summary(&data.interfaces, &data.arp_entries, &data.ipv6_neighbors);

    // ── ISP Info (primary + per-WAN) ──────────────────────
    let total_connection_count = data.connection_count + data.ipv6_connection_count;
    let ipv6_conn_count = data.ipv6_connection_count;
    // Only surface the v6 connection count when the primary WAN actually has a GUA.
    let connection_count_ipv6 = if primary_wan.ipv6_address.is_some() {
        Some(ipv6_conn_count)
    } else {
        None
    };
    let isp = extract_isp(&data.identity, &primary_wan, &all_wans, prev_counters, traffic_db, poll_interval_secs, total_connection_count, connection_count_ipv6);

    // ── Traffic (aggregate + per-WAN points) ───────────────
    let traffic = extract_traffic(&all_wans, prev_counters, &now, poll_interval_secs);

    // ── WiFi Info ─────────────────────────────────────────
    let wifi = extract_wifi(&data.wireless_clients, &data.arp_entries, &data.dhcp_leases, &data.ipv6_neighbors);

    // ── Per-interface status with rates ───────────────────
    let interface_statuses = extract_interface_statuses(&data.interfaces, prev_counters, &all_wans, poll_interval_secs);

    // ── Build per-WAN snapshot fields ─────────────────────
    let wans: Vec<WanEntry> = build_wan_entries(&all_wans, prev_counters, poll_interval_secs);
    let wans_isp: Vec<WanIspInfo> = build_wan_isp_entries(&all_wans, &data.identity);
    let wan_traffic_points: Vec<TrafficPoint> = build_wan_traffic_points(&all_wans, prev_counters, &now, poll_interval_secs);

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
        wans,
        wans_isp,
        wan_traffic_points,
    })
}

// ── WAN Resolution ───────────────────────────────────────────────

/// The resolved WAN — derived from the default route in the routing table.
#[derive(Clone)]
struct WanInfo {
    /// Interface name of the default-route egress
    interface_name: String,
    /// The IP address assigned to that interface
    ip_address: String,
    /// The gateway address from the routing table
    gateway: String,
    /// Whether the interface is running
    online: bool,
    /// Matching InterfaceEntry (for RX/TX byte counters)
    iface: Option<InterfaceEntry>,
    /// IPv6 address on this WAN interface, if any (non-link-local)
    ipv6_address: Option<String>,
    /// IPv6 gateway from the default IPv6 route, if any
    ipv6_gateway: Option<String>,
}

/// Collect ALL active default routes from the routing table (both IPv4 and IPv6).
/// Each distinct (gateway, interface_name) pair becomes one WanInfo.
fn resolve_all_wans(
    ips: &[IpAddrEntry],
    interfaces: &[InterfaceEntry],
    routes: &[RouteEntry],
    ipv6_ips: &[Ipv6AddrEntry],
    ipv6_routes: &[RouteEntry],
) -> Vec<WanInfo> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut wans: Vec<WanInfo> = Vec::new();

    // ── Build an IPv6 address lookup map keyed by interface name ──
    let ipv6_addr_map = build_ipv6_addr_map(ipv6_ips);

    // ── Build a set of interface names that have an IPv6 default route ──
    let ipv6_default_ifaces = build_ipv6_default_iface_set(ipv6_routes);

    // Collect and sort: reachable gateways first
    let mut default_routes: Vec<&RouteEntry> = routes
        .iter()
        .filter(|r| {
            r.dst_address == "0.0.0.0/0"
                && r.active
                && !r.disabled
                && !r.gateway.is_empty()
        })
        .collect();

    default_routes.sort_by_key(|r| {
        if r.gateway_status == "reachable" { 0u8 } else { 1u8 }
    });

    for route in &default_routes {
        // RouterOS PPPoE/PPTP/L2TP: the route's `gateway` field contains the
        // virtual interface name (e.g. "pppoe-cntelecom") and `interface` is empty.
        let route_iface_name = if route.interface.is_empty()
            && route.gateway.parse::<IpAddr>().is_err()
        {
            route.gateway.clone()
        } else {
            route.interface.clone()
        };

        let key = (route.gateway.clone(), route_iface_name.clone());
        if !seen.insert(key) {
            continue;
        }

        let ip_entry = ips
            .iter()
            .filter(|ip| !ip.disabled)
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

        let iface = interfaces
            .iter()
            .find(|i| i.name == route_iface_name)
            .cloned();

        let online = iface
            .as_ref()
            .map(|i| i.running)
            .unwrap_or(false);

        // ── IPv6: look up address and gateway for this interface ──
        let ipv6_address = route_ipv6_addr(&route_iface_name, &ipv6_addr_map);
        let ipv6_gateway = ipv6_address.as_ref().and_then(|_| {
            if ipv6_default_ifaces.contains(&route_iface_name) {
                resolve_ipv6_gateway(&route_iface_name, ipv6_routes)
            } else {
                None
            }
        });

        wans.push(WanInfo {
            interface_name: route_iface_name,
            ip_address,
            gateway: route.gateway.clone(),
            online,
            iface,
            ipv6_address,
            ipv6_gateway,
        });
    }

    // ── IPv6-only WANs: IPv6 default routes whose interfaces aren't already in the list ──
    let seen_ifaces: HashSet<String> = wans.iter().map(|w| w.interface_name.clone()).collect();

    let mut v6_only_routes: Vec<&RouteEntry> = ipv6_routes
        .iter()
        .filter(|r| {
            r.dst_address == "::/0"
                && r.active
                && !r.disabled
                && !r.gateway.is_empty()
        })
        .collect();

    v6_only_routes.sort_by_key(|r| {
        if r.gateway_status == "reachable" { 0u8 } else { 1u8 }
    });

    for v6route in &v6_only_routes {
        let iface_name = resolve_ipv6_route_iface(v6route);

        let key = (v6route.gateway.clone(), iface_name.clone());
        if !seen.insert(key) || seen_ifaces.contains(&iface_name) {
            continue;
        }

        let ipv6_address = route_ipv6_addr(&iface_name, &ipv6_addr_map);
        let ipv6_gateway = ipv6_address.as_ref().map(|_| {
            if v6route.gateway.parse::<IpAddr>().is_ok() {
                v6route.gateway.clone()
            } else {
                v6route.gateway.clone()
            }
        });

        let iface = interfaces
            .iter()
            .find(|i| i.name == iface_name)
            .cloned();

        let online = iface
            .as_ref()
            .map(|i| i.running)
            .unwrap_or(false);

        wans.push(WanInfo {
            interface_name: iface_name,
            ip_address: "—".to_string(),
            gateway: "—".to_string(),
            online,
            iface,
            ipv6_address,
            ipv6_gateway,
        });
    }

    debug!(
        "resolve_all_wans: found {} WAN(s) from {} IPv4 + {} IPv6 default route(s)",
        wans.len(),
        default_routes.len(),
        v6_only_routes.len(),
    );

    wans
}

/// Pick the primary WAN from the resolved list (first reachable, or fallback).
fn resolve_wan(
    ips: &[IpAddrEntry],
    interfaces: &[InterfaceEntry],
    routes: &[RouteEntry],
    ipv6_ips: &[Ipv6AddrEntry],
    ipv6_routes: &[RouteEntry],
) -> WanInfo {
    let all = resolve_all_wans(ips, interfaces, routes, ipv6_ips, ipv6_routes);

    if let Some(wan) = all.into_iter().find(|w| w.online) {
        return wan;
    }

    fallback_wan(ips, interfaces, ipv6_ips)
}

/// Fallback when no default route exists.
fn fallback_wan(ips: &[IpAddrEntry], interfaces: &[InterfaceEntry], ipv6_ips: &[Ipv6AddrEntry]) -> WanInfo {
    let ipv6_addr_map = build_ipv6_addr_map(ipv6_ips);

    for iface in interfaces
        .iter()
        .filter(|i| i.running && !i.disabled)
    {
        if let Some(ip) = ips.iter().find(|ip| {
            let ifname = if ip.actual_interface.is_empty() {
                &ip.interface
            } else {
                &ip.actual_interface
            };
            ifname == &iface.name && !ip.disabled
        }) {
            let ip_addr = extract_ip_from_cidr(&ip.address);
            let gateway = extract_first_ip_in_subnet(&ip.address);
            let ipv6_address = ipv6_addr_map.get(&iface.name).cloned();
            return WanInfo {
                interface_name: iface.name.clone(),
                ip_address: ip_addr,
                gateway,
                online: true,
                iface: Some(iface.clone()),
                ipv6_address,
                ipv6_gateway: None,
            };
        }
    }

    WanInfo {
        interface_name: "—".into(),
        ip_address: "—".into(),
        gateway: "—".into(),
        online: false,
        iface: None,
        ipv6_address: None,
        ipv6_gateway: None,
    }
}

// ── Extraction Helpers ───────────────────────────────────────

fn extract_system_info(sys: &SystemData) -> SystemInfo {
    let uptime_str = parse_routeros_uptime(&sys.uptime);
    let uptime_seconds = sys.uptime_seconds;

    SystemInfo {
        model: sys.board_name.clone(),
        version: sys.version.clone(),
        uptime: uptime_str,
        uptime_seconds,
        cpu_load: sys.cpu_load,
        free_memory: sys.free_memory,
        total_memory: sys.total_memory,
        total_hdd: sys.total_hdd,
        free_hdd: sys.free_hdd,
        architecture: sys.architecture_name.clone(),
        board_name: sys.board_name.clone(),
    }
}

fn extract_gateway(
    primary: &WanInfo,
    all_wans: &[WanInfo],
    leases: &[DhcpLeaseEntry],
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    poll_interval_secs: f64,
) -> GatewayInfo {
    let ip_allocations = leases
        .iter()
        .filter(|l| l.status == "bound")
        .count() as u32;

    GatewayInfo {
        wan_interface: primary.interface_name.clone(),
        wan_ip: primary.ip_address.clone(),
        gateway_ip: primary.gateway.clone(),
        wan_online: all_wans.iter().any(|w| w.online),
        ip_allocations,
        wans: build_wan_entries(all_wans, prev_counters, poll_interval_secs),
        wan_ipv6: primary.ipv6_address.clone(),
        gateway_ipv6: primary.ipv6_gateway.clone(),
    }
}

fn extract_interface_summary(interfaces: &[InterfaceEntry], arp: &[NeighborEntry], ipv6_neighbors: &[NeighborEntry]) -> InterfaceSummary {
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

    let mut connected_macs: HashSet<String> = HashSet::new();

    for a in arp.iter().filter(|a| {
        LIVE_NEIGHBOR_STATES.contains(&a.status.as_str())
            && !a.disabled
            && !a.mac_address.is_empty()
    }) {
        connected_macs.insert(a.mac_address.to_lowercase());
    }

    for n in ipv6_neighbors.iter().filter(|n| {
        LIVE_NEIGHBOR_STATES.contains(&n.status.as_str())
            && !n.disabled
            && !n.mac_address.is_empty()
    }) {
        connected_macs.insert(n.mac_address.to_lowercase());
    }

    let connected_devices = connected_macs.len() as u32;

    let wifi_online = interfaces
        .iter()
        .any(|i| {
            (i.iface_type == "wlan" || i.iface_type == "wifi")
                && i.running
        });

    InterfaceSummary {
        ethernet_count,
        wifi_count,
        connected_devices,
        wifi_online,
    }
}

/// Build per-interface status with real-time RX/TX rates.
/// WAN interfaces are tagged with `is_wan` and `wan_name` for UI highlighting.
fn extract_interface_statuses(
    interfaces: &[InterfaceEntry],
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    all_wans: &[WanInfo],
    poll_interval_secs: f64,
) -> Vec<InterfaceStatus> {
    // Build a set of WAN interface names for fast lookup
    let wan_names: HashSet<&str> = all_wans.iter().map(|w| w.interface_name.as_str()).collect();

    let mut statuses: Vec<InterfaceStatus> = interfaces
        .iter()
        .filter(|i| i.default_name != "lo" && i.name != "lo") // skip loopback
        .filter_map(|iface| {
            let (rx_bps, tx_bps) = prev_counters
                .and_then(|prev| prev.get(&iface.name))
                .map(|(prev_rx, prev_tx)| {
                    let rx_diff = iface.rx_byte.saturating_sub(*prev_rx);
                    let tx_diff = iface.tx_byte.saturating_sub(*prev_tx);
                    (rx_diff as f64 * 8.0 / poll_interval_secs, tx_diff as f64 * 8.0 / poll_interval_secs)
                })
                .unwrap_or((0.0, 0.0));

            let is_wan = wan_names.contains(iface.name.as_str());

            Some(InterfaceStatus {
                name: iface.name.clone(),
                iface_type: iface.iface_type.clone(),
                running: iface.running,
                rx_bps,
                tx_bps,
                is_wan: if is_wan { Some(true) } else { None },
                wan_name: if is_wan { Some(iface.name.clone()) } else { None },
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
    identity: &IdentityData,
    primary: &WanInfo,
    all_wans: &[WanInfo],
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    traffic_db: &TrafficDb,
    poll_interval_secs: f64,
    connection_count: u32,
    connection_count_ipv6: Option<u32>,
) -> IspInfo {
    let isp_name = if identity.name.is_empty() {
        "Unknown ISP".to_string()
    } else {
        identity.name.clone()
    };

    let (download_bps, upload_bps) = compute_wan_rate(primary, prev_counters, poll_interval_secs)
        .unwrap_or((0.0, 0.0));

    let (dl_gb, ul_gb) = traffic_db.monthly_usage_gb(poll_interval_secs);

    IspInfo {
        name: isp_name,
        online: all_wans.iter().any(|w| w.online),
        monthly_usage_gb: dl_gb + ul_gb,
        download_bps,
        upload_bps,
        connection_count,
        connection_count_ipv6,
        wans: build_wan_isp_entries(all_wans, identity),
    }
}

/// Compute the RX/TX rate for the single WAN interface identified by the routing table.
fn compute_wan_rate(
    wan: &WanInfo,
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    poll_interval_secs: f64,
) -> Option<(f64, f64)> {
    let iface = wan.iface.as_ref()?;
    let prev = prev_counters?;
    let (prev_rx, prev_tx) = prev.get(&iface.name)?;
    let rx_diff = iface.rx_byte.saturating_sub(*prev_rx);
    let tx_diff = iface.tx_byte.saturating_sub(*prev_tx);
    Some((
        rx_diff as f64 * 8.0 / poll_interval_secs,
        tx_diff as f64 * 8.0 / poll_interval_secs,
    ))
}

// ── Multi-WAN Builder Helpers ────────────────────────────────────

/// Build `Vec<WanEntry>` from resolved WANs with real-time rate data.
fn build_wan_entries(
    all_wans: &[WanInfo],
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    poll_interval_secs: f64,
) -> Vec<WanEntry> {
    all_wans
        .iter()
        .enumerate()
        .map(|(i, wan)| {
            let (download_bps, upload_bps) =
                compute_wan_rate(wan, prev_counters, poll_interval_secs).unwrap_or((0.0, 0.0));
            WanEntry {
                wan_name: wan.interface_name.clone(),
                wan_ip: wan.ip_address.clone(),
                gateway_ip: wan.gateway.clone(),
                online: wan.online,
                download_bps,
                upload_bps,
                is_primary: i == 0, // first reachable WAN is primary
                wan_ipv6: wan.ipv6_address.clone(),
                gateway_ipv6: wan.ipv6_gateway.clone(),
            }
        })
        .collect()
}

/// Build `Vec<WanIspInfo>` from resolved WANs.
fn build_wan_isp_entries(
    all_wans: &[WanInfo],
    identity: &IdentityData,
) -> Vec<WanIspInfo> {
    let isp_name = if identity.name.is_empty() {
        "Unknown ISP".to_string()
    } else {
        identity.name.clone()
    };

    all_wans
        .iter()
        .map(|wan| WanIspInfo {
            wan_name: wan.interface_name.clone(),
            name: isp_name.clone(),
            online: wan.online,
            download_bps: 0.0, // filled by per-WAN rate elsewhere
            upload_bps: 0.0,
        })
        .collect()
}

/// Build per-WAN traffic points for the current poll tick.
fn build_wan_traffic_points(
    all_wans: &[WanInfo],
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    now: &str,
    poll_interval_secs: f64,
) -> Vec<TrafficPoint> {
    all_wans
        .iter()
        .filter_map(|wan| {
            let (download_bps, upload_bps) =
                compute_wan_rate(wan, prev_counters, poll_interval_secs).unwrap_or((0.0, 0.0));
            if download_bps > 0.0 || upload_bps > 0.0 {
                Some(TrafficPoint {
                    timestamp: now.to_string(),
                    download_bps,
                    upload_bps,
                    wan_name: Some(wan.interface_name.clone()),
                })
            } else {
                None
            }
        })
        .collect()
}

fn extract_traffic(
    all_wans: &[WanInfo],
    prev_counters: Option<&HashMap<String, (u64, u64)>>,
    now: &str,
    poll_interval_secs: f64,
) -> TrafficSnapshot {
    // Sum download/upload across all WANs for the aggregate traffic point
    let (download_bps, upload_bps) = all_wans
        .iter()
        .fold((0.0f64, 0.0f64), |(dl, ul), wan| {
            if let Some((wdl, wul)) = compute_wan_rate(wan, prev_counters, poll_interval_secs) {
                (dl + wdl, ul + wul)
            } else {
                (dl, ul)
            }
        });

    debug!(
        "Traffic ({} WANs): down={:.1} Kbps, up={:.1} Kbps",
        all_wans.len(),
        download_bps / 1000.0,
        upload_bps / 1000.0,
    );

    let points = if download_bps > 0.0 || upload_bps > 0.0 {
        vec![TrafficPoint {
            timestamp: now.to_string(),
            download_bps,
            upload_bps,
            wan_name: None, // aggregate
        }]
    } else {
        vec![]
    };

    TrafficSnapshot { points }
}

fn extract_wifi(
    wireless_clients: &[WirelessClientEntry],
    arp: &[NeighborEntry],
    leases: &[DhcpLeaseEntry],
    ipv6_neighbors: &[NeighborEntry],
) -> WifiInfo {
    let client_count = wireless_clients.len() as u32;

    // Build device list from wireless registrations + ARP + DHCP leases
    let mut devices: Vec<Device> = Vec::new();

    // Start with wireless registrations (most accurate for WiFi clients)
    for reg in wireless_clients {
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

        devices.push(Device {
            mac: reg.mac_address.clone(),
            hostname: hostname.to_string(),
            ip,
            device_type: infer_device_type(hostname, &reg.mac_address),
            signal: reg.signal_strength,
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
    let mut wifi_macs: HashSet<String> = wireless_clients.iter().map(|r| r.mac_address.to_lowercase()).collect();

    // Collect matching ARP entries first to avoid borrowing wifi_macs in the loop
    let arp_devices: Vec<&NeighborEntry> = arp.iter().filter(|a| {
        LIVE_NEIGHBOR_STATES.contains(&a.status.as_str())
            && !a.disabled
            && !a.mac_address.is_empty()
            && !wifi_macs.contains(&a.mac_address.to_lowercase())
    }).collect();

    for entry in arp_devices {
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

        wifi_macs.insert(entry.mac_address.to_lowercase());
    }

    // ── IPv6 neighbors ── discover devices from the IPv6 neighbor table.
    // Deduplicate by MAC — a dual-stack device may appear in both ARP and
    // the IPv6 neighbor table with different addresses but the same MAC.
    let ipv6_devices: Vec<&NeighborEntry> = ipv6_neighbors.iter().filter(|n| {
        LIVE_NEIGHBOR_STATES.contains(&n.status.as_str())
            && !n.disabled
            && !n.mac_address.is_empty()
            && !wifi_macs.contains(&n.mac_address.to_lowercase())
    }).collect();

    for entry in ipv6_devices {
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

        wifi_macs.insert(entry.mac_address.to_lowercase());
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

/// Extract first usable IP in subnet — a best-effort gateway guess for the
/// fallback WAN path. Handles both IPv4 and IPv6 CIDR notation.
///
/// If a prefix length is present (e.g. `192.168.1.10/24`), the function
/// computes the network address and returns network+1 as the likely gateway.
/// For bare IPs, the last octet (IPv4) or last hextet (IPv6) is replaced
/// with 1 as a heuristic.
fn extract_first_ip_in_subnet(cidr: &str) -> String {
    // ── Case 1: CIDR with prefix length → proper subnet math ──
    if let Some((ip_str, prefix_len_str)) = cidr.split_once('/') {
        if let (Ok(prefix_len), Ok(ip)) = (
            prefix_len_str.parse::<u8>(),
            ip_str.parse::<IpAddr>(),
        ) {
            match ip {
                IpAddr::V4(v4) if prefix_len <= 32 => {
                    let net = u32::from(v4) & ipv4_netmask(prefix_len);
                    return Ipv4Addr::from(net.saturating_add(1)).to_string();
                }
                IpAddr::V6(v6) if prefix_len <= 128 => {
                    let net = u128::from(v6) & ipv6_netmask(prefix_len);
                    return Ipv6Addr::from(net.saturating_add(1)).to_string();
                }
                _ => {}
            }
        }
    }

    // ── Case 2: bare IP (no prefix) → replace last unit with 1 ──
    if let Ok(ip) = extract_ip_from_cidr(cidr).parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let mut o = v4.octets();
                o[3] = 1;
                return Ipv4Addr::from(o).to_string();
            }
            IpAddr::V6(v6) => {
                let mut s = v6.segments();
                s[7] = s[7].max(1); // ::0 → ::1, leave existing non-zero alone
                return Ipv6Addr::from(s).to_string();
            }
        }
    }

    // ── Couldn't parse as IP at all — return raw IP portion ──
    extract_ip_from_cidr(cidr)
}

fn ipv4_netmask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }
    (!0u32) << (32 - prefix_len)
}

fn ipv6_netmask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    (!0u128) << (128 - prefix_len)
}

/// Extract IP address from CIDR notation (e.g., "192.168.1.1/24" → "192.168.1.1").
fn extract_ip_from_cidr(cidr: &str) -> String {
    cidr.split('/').next().unwrap_or(cidr).to_string()
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

    // Category: public DNS (IPv6)
    targets.push(("Cloudflare DNS v6".into(), "2606:4700:4700::1111".into(), "dns".into()));
    targets.push(("Google DNS v6".into(), "2001:4860:4860::8888".into(), "dns".into()));
    targets.push(("Quad9 DNS v6".into(), "2620:fe::fe".into(), "dns".into()));

    targets
}

// ── IPv6 WAN resolution helpers ───────────────────────────────

/// Build a HashMap of interface_name → best IPv6 address.
///
/// Filters out disabled, link-local (`fe80::`), and ULA addresses
/// (`fc00::/7`, `fd00::/8`).  Only global unicast (2000::/3) is kept — if an
/// interface has no GUA the egress is treated as having no public IPv6.
fn build_ipv6_addr_map(ipv6_ips: &[Ipv6AddrEntry]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for a in ipv6_ips.iter().filter(|a| !a.disabled) {
        let ifname = if a.actual_interface.is_empty() {
            &a.interface
        } else {
            &a.actual_interface
        };
        let ip = extract_ip_from_cidr(&a.address);
        if ip.to_lowercase().starts_with("fe80:") {
            continue;
        }
        // Only keep global unicast (2000::/3)
        if !ip.starts_with('2') && !ip.starts_with('3') {
            continue;
        }
        map.entry(ifname.to_string()).or_insert(ip);
    }
    map
}

/// Build a set of interface names that have an active IPv6 default route.
fn build_ipv6_default_iface_set(ipv6_routes: &[RouteEntry]) -> HashSet<String> {
    ipv6_routes
        .iter()
        .filter(|r| {
            r.dst_address == "::/0"
                && r.active
                && !r.disabled
                && !r.gateway.is_empty()
        })
        .map(|r| resolve_ipv6_route_iface(r))
        .collect()
}

/// Resolve the egress interface name for an IPv6 route.
///
/// Uses the same PPPoE-detection logic as IPv4: if `interface` is empty and
/// `gateway` is not a parseable IP address, the gateway field IS the interface
/// name (e.g. "pppoe-cntelecom").
fn resolve_ipv6_route_iface(route: &RouteEntry) -> String {
    if route.interface.is_empty() && route.gateway.parse::<std::net::IpAddr>().is_err() {
        route.gateway.clone()
    } else {
        route.interface.clone()
    }
}

/// Look up the IPv6 address for a given interface from the pre-built map.
/// If the WAN interface has no GUA (common with PPPoE where the GUA is only on
/// the LAN bridge), falls back to the first GUA found on any LAN interface.
fn route_ipv6_addr(iface_name: &str, map: &HashMap<String, String>) -> Option<String> {
    // Direct match on the WAN interface
    if let Some(addr) = map.get(iface_name) {
        return Some(addr.clone());
    }
    // Fallback: pick the first GUA from any other interface (typically the LAN bridge)
    map.iter()
        .filter(|(name, _)| *name != iface_name)
        .map(|(_, addr)| addr.clone())
        .next()
}

/// Resolve the IPv6 gateway for a given interface from IPv6 default routes.
fn resolve_ipv6_gateway(iface_name: &str, ipv6_routes: &[RouteEntry]) -> Option<String> {
    ipv6_routes
        .iter()
        .filter(|r| {
            r.dst_address == "::/0"
                && r.active
                && !r.disabled
                && !r.gateway.is_empty()
        })
        .find(|r| resolve_ipv6_route_iface(r) == iface_name)
        .map(|r| r.gateway.clone())
}
