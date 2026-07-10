use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use tracing::debug;

use crate::backends::*;
use crate::error::AppError;
use crate::ws::protocol::*;

/// Neighbor states that represent a currently-connected device.
/// RouterOS ARP / IPv6 neighbor statuses: permanent, reachable, stale, delay, probe,
/// failed, incomplete. We exclude "failed" (DHCP conflict / unreachable) and
/// "incomplete" (unresolved).
const LIVE_NEIGHBOR_STATES: &[&str] = &["permanent", "reachable", "stale", "delay", "probe"];

/// How a monotonically increasing byte counter changed between two samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CounterTransition {
    Initial,
    Advanced,
    Wrapped,
    Rebooted,
    Reset,
    InvalidElapsed,
}

/// A calculated rate plus the counter transition that produced it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CounterRate {
    pub delta_bytes: Option<u64>,
    pub bits_per_second: Option<f64>,
    pub transition: CounterTransition,
}

/// Baseline paired with the elapsed time between two successful samples.
pub(crate) struct PreviousCounterSample<'a> {
    pub counters: &'a HashMap<String, (u64, u64)>,
    pub uptime_seconds: Option<u64>,
    pub elapsed_secs: f64,
}

struct RateContext<'a> {
    previous_counters: Option<&'a HashMap<String, (u64, u64)>>,
    previous_uptime_seconds: Option<u64>,
    current_uptime_seconds: Option<u64>,
    elapsed_secs: Option<f64>,
}

/// Calculate a rate without interpreting a lower counter as negative traffic.
///
/// A lower value after uptime decreased is a reboot. Values crossing the
/// RouterOS 64-bit boundary are wraps; other decreases are resets.
pub(crate) fn calculate_counter_rate(
    previous: Option<u64>,
    current: u64,
    previous_uptime_seconds: Option<u64>,
    current_uptime_seconds: Option<u64>,
    elapsed_secs: Option<f64>,
) -> CounterRate {
    let Some(previous) = previous else {
        return CounterRate {
            delta_bytes: None,
            bits_per_second: None,
            transition: CounterTransition::Initial,
        };
    };

    if previous_uptime_seconds
        .zip(current_uptime_seconds)
        .is_some_and(|(previous, current)| current < previous)
    {
        return CounterRate {
            delta_bytes: None,
            bits_per_second: None,
            transition: CounterTransition::Rebooted,
        };
    }

    let (delta, transition) = if current >= previous {
        (current - previous, CounterTransition::Advanced)
    } else if let Some(delta) = wrapped_counter_delta(previous, current) {
        (delta, CounterTransition::Wrapped)
    } else {
        return CounterRate {
            delta_bytes: None,
            bits_per_second: None,
            transition: CounterTransition::Reset,
        };
    };

    let Some(elapsed_secs) = elapsed_secs.filter(|elapsed| elapsed.is_finite() && *elapsed > 0.0)
    else {
        return CounterRate {
            delta_bytes: Some(delta),
            bits_per_second: None,
            transition: CounterTransition::InvalidElapsed,
        };
    };

    CounterRate {
        delta_bytes: Some(delta),
        bits_per_second: Some(delta as f64 * 8.0 / elapsed_secs),
        transition,
    }
}

fn wrapped_counter_delta(previous: u64, current: u64) -> Option<u64> {
    if previous <= u64::MAX / 4 * 3 || current >= u64::MAX / 4 {
        return None;
    }

    Some(
        (u64::MAX - previous)
            .saturating_add(current)
            .saturating_add(1),
    )
}

fn calculate_interface_rates(iface: &InterfaceEntry, context: &RateContext<'_>) -> (f64, f64) {
    let previous = context
        .previous_counters
        .and_then(|counters| counters.get(&iface.name));
    let rx = iface.rx_byte.map(|current| {
        calculate_counter_rate(
            previous.map(|values| values.0),
            current,
            context.previous_uptime_seconds,
            context.current_uptime_seconds,
            context.elapsed_secs,
        )
    });
    let tx = iface.tx_byte.map(|current| {
        calculate_counter_rate(
            previous.map(|values| values.1),
            current,
            context.previous_uptime_seconds,
            context.current_uptime_seconds,
            context.elapsed_secs,
        )
    });
    (
        rx.and_then(|rate| rate.bits_per_second).unwrap_or(0.0),
        tx.and_then(|rate| rate.bits_per_second).unwrap_or(0.0),
    )
}

/// Transforms vendor-neutral `RouterData` into the dashboard-friendly
/// `DashboardSnapshot` structure.
///
/// This function is the bridge between the typed, normalized data from
/// any router backend and the format the frontend expects.
pub fn to_dashboard_snapshot(
    data: RouterData,
    previous_sample: Option<PreviousCounterSample<'_>>,
    latency_results: Vec<LatencyProbe>,
    stability: IspStability,
    monthly_usage_gb: f64,
) -> Result<DashboardSnapshot, AppError> {
    let now = chrono::Utc::now().to_rfc3339();
    let rate_context = RateContext {
        previous_counters: previous_sample.as_ref().map(|sample| sample.counters),
        previous_uptime_seconds: previous_sample
            .as_ref()
            .and_then(|sample| sample.uptime_seconds),
        current_uptime_seconds: data.system.uptime_seconds,
        elapsed_secs: previous_sample.as_ref().map(|sample| sample.elapsed_secs),
    };

    // ── Find all WANs from the routing table ──────────────
    let all_wans = resolve_all_wans(
        &data.ip_addresses,
        &data.interfaces,
        &data.routes,
        &data.ipv6_addresses,
        &data.ipv6_routes,
    );
    let primary_wan = all_wans
        .iter()
        .find(|wan| wan.is_primary)
        .cloned()
        .unwrap_or_else(empty_wan);

    // ── System Info ───────────────────────────────────────
    let system = extract_system_info(&data.system);

    // ── Gateway Info (primary + all WAN entries) ──────────
    let gateway = extract_gateway(&primary_wan, &all_wans, &data.dhcp_leases, &rate_context);

    // ── Interface Summary ─────────────────────────────────
    let interface_summary =
        extract_interface_summary(&data.interfaces, &data.arp_entries, &data.ipv6_neighbors);

    // ── ISP Info (primary + per-WAN) ──────────────────────
    let total_connection_count = data
        .connection_count
        .saturating_add(data.ipv6_connection_count);
    let ipv6_conn_count = data.ipv6_connection_count;
    // Only surface the v6 connection count when the primary WAN actually has a GUA.
    let connection_count_ipv6 = if primary_wan.ipv6_address.is_some() {
        Some(ipv6_conn_count)
    } else {
        None
    };
    let isp = extract_isp(
        &data.identity,
        &primary_wan,
        &all_wans,
        &rate_context,
        monthly_usage_gb,
        (total_connection_count, connection_count_ipv6),
    );

    // ── Traffic (aggregate + per-WAN points) ───────────────
    let traffic = extract_traffic(&all_wans, &rate_context, &now);

    // ── WiFi Info ─────────────────────────────────────────
    let wifi = extract_wifi(
        &data.wireless_clients,
        &data.arp_entries,
        &data.dhcp_leases,
        &data.ipv6_neighbors,
    );

    // ── Per-interface status with rates ───────────────────
    let interface_statuses = extract_interface_statuses(&data.interfaces, &rate_context, &all_wans);

    // ── Build per-WAN snapshot fields ─────────────────────
    let wans: Vec<WanEntry> = build_wan_entries(&all_wans, &rate_context);
    let wans_isp: Vec<WanIspInfo> = build_wan_isp_entries(&all_wans, &data.identity);
    let wan_traffic_points: Vec<TrafficPoint> =
        build_wan_traffic_points(&all_wans, &rate_context, &now);

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
#[derive(Clone, Debug)]
struct WanInfo {
    /// Interface name of the default-route egress
    interface_name: String,
    /// The IP address assigned to that interface
    ip_address: String,
    /// The gateway address from the routing table
    gateway: String,
    /// Whether the interface is running
    online: bool,
    /// Whether this is the reachable active route with the lowest distance.
    is_primary: bool,
    /// Whether RouterOS installed this default route as active.
    route_active: bool,
    /// Whether RouterOS reports the route gateway as reachable.
    route_reachable: bool,
    /// Administrative distance from the default route.
    distance: u32,
    /// Matching InterfaceEntry (for RX/TX byte counters)
    iface: Option<InterfaceEntry>,
    /// IPv6 address on this WAN interface, if any (non-link-local)
    ipv6_address: Option<String>,
    /// IPv6 gateway from the default IPv6 route, if any
    ipv6_gateway: Option<String>,
}

/// Return the concrete interface names that participate in enabled default routes.
/// The poller uses this same resolution path for durable per-WAN counter storage,
/// keeping persistence and the dashboard's WAN model in sync.
pub(crate) fn wan_interface_names(data: &RouterData) -> Vec<String> {
    let mut names: Vec<String> = resolve_all_wans(
        &data.ip_addresses,
        &data.interfaces,
        &data.routes,
        &data.ipv6_addresses,
        &data.ipv6_routes,
    )
    .into_iter()
    .filter_map(|wan| wan.iface.map(|interface| interface.name))
    .collect();
    names.sort();
    names.dedup();
    names
}

/// Collect all enabled default routes from the routing table (both IPv4 and IPv6).
/// Each distinct (gateway, interface_name) pair becomes one WanInfo.
fn resolve_all_wans(
    ips: &[IpAddrEntry],
    interfaces: &[InterfaceEntry],
    routes: &[RouteEntry],
    ipv6_ips: &[Ipv6AddrEntry],
    ipv6_routes: &[RouteEntry],
) -> Vec<WanInfo> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut wans: Vec<WanInfo> = Vec::new();

    // ── Build an IPv6 address lookup map keyed by interface name ──
    let ipv6_addr_map = build_ipv6_addr_map(ipv6_ips);

    // ── Build a set of interface names that have an IPv6 default route ──
    let ipv6_default_ifaces = build_ipv6_default_iface_set(ipv6_routes);

    // Keep inactive and unreachable routes so standby and down WANs remain visible.
    let mut default_routes: Vec<&RouteEntry> = routes
        .iter()
        .filter(|r| r.dst_address == "0.0.0.0/0" && !r.disabled && !r.gateway.is_empty())
        .collect();

    default_routes.sort_by_key(|r| route_sort_key(r));

    for route in &default_routes {
        // RouterOS PPPoE/PPTP/L2TP: the route's `gateway` field contains the
        // virtual interface name (e.g. "pppoe-cntelecom") and `interface` is empty.
        let route_iface_name =
            if route.interface.is_empty() && route.gateway.parse::<IpAddr>().is_err() {
                route.gateway.clone()
            } else {
                route.interface.clone()
            };

        let key = if route_iface_name.is_empty() {
            format!("gateway:{}", route.gateway)
        } else {
            format!("interface:{route_iface_name}")
        };
        if !seen.insert(key) {
            continue;
        }

        let ip_entry = ips.iter().filter(|ip| !ip.disabled).find(|ip| {
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

        let online =
            route_is_reachable(route) && iface.as_ref().map(|i| i.running).unwrap_or(false);

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
            is_primary: false,
            route_active: route.active,
            route_reachable: route_is_reachable(route),
            distance: route.distance,
            iface,
            ipv6_address,
            ipv6_gateway,
        });
    }

    // ── IPv6-only WANs, or IPv6 state merged into an existing dual-stack WAN ──
    let mut v6_only_routes: Vec<&RouteEntry> = ipv6_routes
        .iter()
        .filter(|r| r.dst_address == "::/0" && !r.disabled && !r.gateway.is_empty())
        .collect();

    v6_only_routes.sort_by_key(|r| route_sort_key(r));

    for v6route in &v6_only_routes {
        let iface_name = resolve_ipv6_route_iface(v6route);

        if let Some(existing) = wans.iter_mut().find(|wan| wan.interface_name == iface_name) {
            let candidate_rank = route_sort_key(v6route);
            let existing_rank = (
                route_state_rank(existing.route_active, existing.route_reachable),
                existing.distance,
                "",
            );
            if candidate_rank < existing_rank {
                existing.route_active = v6route.active;
                existing.route_reachable = route_is_reachable(v6route);
                existing.distance = v6route.distance;
            }
            existing.online |= route_is_reachable(v6route)
                && existing.iface.as_ref().is_some_and(|iface| iface.running);
            continue;
        }

        let key = if iface_name.is_empty() {
            format!("gateway:{}", v6route.gateway)
        } else {
            format!("interface:{iface_name}")
        };
        if !seen.insert(key) {
            continue;
        }

        let ipv6_address = route_ipv6_addr(&iface_name, &ipv6_addr_map);
        let ipv6_gateway = ipv6_address.as_ref().map(|_| v6route.gateway.clone());

        let iface = interfaces.iter().find(|i| i.name == iface_name).cloned();

        let online =
            route_is_reachable(v6route) && iface.as_ref().map(|i| i.running).unwrap_or(false);

        wans.push(WanInfo {
            interface_name: iface_name,
            ip_address: "—".to_string(),
            gateway: "—".to_string(),
            online,
            is_primary: false,
            route_active: v6route.active,
            route_reachable: route_is_reachable(v6route),
            distance: v6route.distance,
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

    if let Some((primary_index, _)) = wans
        .iter()
        .enumerate()
        .filter(|(_, wan)| wan.route_active && wan.route_reachable && wan.online)
        .min_by_key(|(_, wan)| (wan.distance, wan.interface_name.as_str()))
    {
        wans[primary_index].is_primary = true;
    }

    wans.sort_by_key(|wan| {
        (
            if wan.is_primary {
                0u8
            } else if wan.online {
                1
            } else {
                2
            },
            wan.distance,
            wan.interface_name.clone(),
        )
    });

    wans
}

fn route_sort_key(route: &RouteEntry) -> (u8, u32, &str) {
    (
        route_state_rank(route.active, route_is_reachable(route)),
        route.distance,
        route.id.as_str(),
    )
}

fn route_state_rank(active: bool, reachable: bool) -> u8 {
    if active && reachable {
        0
    } else if reachable {
        1
    } else {
        2
    }
}

fn route_is_reachable(route: &RouteEntry) -> bool {
    route
        .gateway_status
        .split(|character: char| !character.is_ascii_alphabetic())
        .any(|word| word.eq_ignore_ascii_case("reachable"))
}

fn empty_wan() -> WanInfo {
    WanInfo {
        interface_name: "—".into(),
        ip_address: "—".into(),
        gateway: "—".into(),
        online: false,
        is_primary: false,
        route_active: false,
        route_reachable: false,
        distance: u32::MAX,
        iface: None,
        ipv6_address: None,
        ipv6_gateway: None,
    }
}

// ── Extraction Helpers ───────────────────────────────────────

fn extract_system_info(sys: &SystemData) -> SystemInfo {
    let uptime_str = parse_routeros_uptime(&sys.uptime);
    let uptime_seconds = sys.uptime_seconds.unwrap_or(0);

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
    rate_context: &RateContext<'_>,
) -> GatewayInfo {
    let ip_allocations = leases.iter().filter(|l| l.status == "bound").count() as u32;

    GatewayInfo {
        wan_interface: primary.interface_name.clone(),
        wan_ip: primary.ip_address.clone(),
        gateway_ip: primary.gateway.clone(),
        wan_online: all_wans.iter().any(|wan| wan.is_primary),
        ip_allocations,
        wans: build_wan_entries(all_wans, rate_context),
        wan_ipv6: primary.ipv6_address.clone(),
        gateway_ipv6: primary.ipv6_gateway.clone(),
    }
}

fn extract_interface_summary(
    interfaces: &[InterfaceEntry],
    arp: &[NeighborEntry],
    ipv6_neighbors: &[NeighborEntry],
) -> InterfaceSummary {
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
        .any(|i| (i.iface_type == "wlan" || i.iface_type == "wifi") && i.running);

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
    rate_context: &RateContext<'_>,
    all_wans: &[WanInfo],
) -> Vec<InterfaceStatus> {
    // Build a set of WAN interface names for fast lookup
    let wan_names: HashSet<&str> = all_wans.iter().map(|w| w.interface_name.as_str()).collect();

    let mut statuses: Vec<InterfaceStatus> = interfaces
        .iter()
        .filter(|i| i.default_name != "lo" && i.name != "lo") // skip loopback
        .map(|iface| {
            let (rx_bps, tx_bps) = calculate_interface_rates(iface, rate_context);

            let is_wan = wan_names.contains(iface.name.as_str());

            InterfaceStatus {
                name: iface.name.clone(),
                iface_type: iface.iface_type.clone(),
                running: iface.running,
                rx_bps,
                tx_bps,
                is_wan: if is_wan { Some(true) } else { None },
                wan_name: if is_wan {
                    Some(iface.name.clone())
                } else {
                    None
                },
            }
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
    rate_context: &RateContext<'_>,
    monthly_usage_gb: f64,
    connection_counts: (u32, Option<u32>),
) -> IspInfo {
    let isp_name = if identity.name.is_empty() {
        "Unknown ISP".to_string()
    } else {
        identity.name.clone()
    };

    let (download_bps, upload_bps) = compute_wan_rate(primary, rate_context).unwrap_or((0.0, 0.0));

    IspInfo {
        name: isp_name,
        online: all_wans.iter().any(|wan| wan.is_primary),
        monthly_usage_gb,
        download_bps,
        upload_bps,
        connection_count: connection_counts.0,
        connection_count_ipv6: connection_counts.1,
        wans: build_wan_isp_entries(all_wans, identity),
    }
}

/// Compute the RX/TX rate for the single WAN interface identified by the routing table.
fn compute_wan_rate(wan: &WanInfo, rate_context: &RateContext<'_>) -> Option<(f64, f64)> {
    let iface = wan.iface.as_ref()?;
    Some(calculate_interface_rates(iface, rate_context))
}

// ── Multi-WAN Builder Helpers ────────────────────────────────────

/// Build `Vec<WanEntry>` from resolved WANs with real-time rate data.
fn build_wan_entries(all_wans: &[WanInfo], rate_context: &RateContext<'_>) -> Vec<WanEntry> {
    all_wans
        .iter()
        .map(|wan| {
            let (download_bps, upload_bps) =
                compute_wan_rate(wan, rate_context).unwrap_or((0.0, 0.0));
            WanEntry {
                wan_name: wan.interface_name.clone(),
                wan_ip: wan.ip_address.clone(),
                gateway_ip: wan.gateway.clone(),
                online: wan.online,
                download_bps,
                upload_bps,
                is_primary: wan.is_primary,
                wan_ipv6: wan.ipv6_address.clone(),
                gateway_ipv6: wan.ipv6_gateway.clone(),
            }
        })
        .collect()
}

/// Build `Vec<WanIspInfo>` from resolved WANs.
fn build_wan_isp_entries(all_wans: &[WanInfo], identity: &IdentityData) -> Vec<WanIspInfo> {
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
    rate_context: &RateContext<'_>,
    now: &str,
) -> Vec<TrafficPoint> {
    all_wans
        .iter()
        .filter_map(|wan| {
            let (download_bps, upload_bps) =
                compute_wan_rate(wan, rate_context).unwrap_or((0.0, 0.0));
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
    rate_context: &RateContext<'_>,
    now: &str,
) -> TrafficSnapshot {
    // Sum download/upload across all WANs for the aggregate traffic point
    let (download_bps, upload_bps) = all_wans.iter().fold((0.0f64, 0.0f64), |(dl, ul), wan| {
        if let Some((wdl, wul)) = compute_wan_rate(wan, rate_context) {
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
                if l.host_name.is_empty() {
                    "Unknown"
                } else {
                    &l.host_name
                }
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
            dhcp_expires: lease
                .map(|l| l.expires_after.clone())
                .filter(|s| !s.is_empty()),
            interface: arp_entry
                .map(|a| a.interface.clone())
                .filter(|s| !s.is_empty()),
            arp_status: arp_entry
                .map(|a| a.status.clone())
                .filter(|s| !s.is_empty()),
            custom_name: None,
            custom_type: None,
        });
    }

    // Also include wired ARP entries (devices on LAN ports)
    let mut wifi_macs: HashSet<String> = wireless_clients
        .iter()
        .map(|r| r.mac_address.to_lowercase())
        .collect();

    // Collect matching ARP entries first to avoid borrowing wifi_macs in the loop
    let arp_devices: Vec<&NeighborEntry> = arp
        .iter()
        .filter(|a| {
            LIVE_NEIGHBOR_STATES.contains(&a.status.as_str())
                && !a.disabled
                && !a.mac_address.is_empty()
                && !wifi_macs.contains(&a.mac_address.to_lowercase())
        })
        .collect();

    for entry in arp_devices {
        let lease = leases.iter().find(|l| {
            l.active_mac_address.to_lowercase() == entry.mac_address.to_lowercase()
                || l.mac_address.to_lowercase() == entry.mac_address.to_lowercase()
        });

        let hostname = lease
            .map(|l| {
                if l.host_name.is_empty() {
                    "Unknown"
                } else {
                    &l.host_name
                }
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
            dhcp_expires: lease
                .map(|l| l.expires_after.clone())
                .filter(|s| !s.is_empty()),
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
    let ipv6_devices: Vec<&NeighborEntry> = ipv6_neighbors
        .iter()
        .filter(|n| {
            LIVE_NEIGHBOR_STATES.contains(&n.status.as_str())
                && !n.disabled
                && !n.mac_address.is_empty()
                && !wifi_macs.contains(&n.mac_address.to_lowercase())
        })
        .collect();

    for entry in ipv6_devices {
        let lease = leases.iter().find(|l| {
            l.active_mac_address.to_lowercase() == entry.mac_address.to_lowercase()
                || l.mac_address.to_lowercase() == entry.mac_address.to_lowercase()
        });

        let hostname = lease
            .map(|l| {
                if l.host_name.is_empty() {
                    "Unknown"
                } else {
                    &l.host_name
                }
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
            dhcp_expires: lease
                .map(|l| l.expires_after.clone())
                .filter(|s| !s.is_empty()),
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
    if h.contains("macbook")
        || h.contains("laptop")
        || h.contains("notebook")
        || h.contains("thinkpad")
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
    let mac_prefix = mac.get(..8).unwrap_or(mac).to_lowercase();
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
    let mut targets: Vec<(String, String, String)> = vec![
        ("Cloudflare DNS".into(), "1.1.1.1".into(), "dns".into()),
        ("Google DNS".into(), "8.8.8.8".into(), "dns".into()),
        ("Quad9 DNS".into(), "9.9.9.9".into(), "dns".into()),
        ("AliDNS".into(), "223.5.5.5".into(), "dns".into()),
        ("DNSPod".into(), "119.29.29.29".into(), "dns".into()),
        ("AWS".into(), "amazon.com".into(), "cloud".into()),
        ("Azure".into(), "azure.microsoft.com".into(), "cloud".into()),
        ("Alibaba Cloud".into(), "aliyun.com".into(), "cloud".into()),
        (
            "Tencent Cloud".into(),
            "cloud.tencent.com".into(),
            "cloud".into(),
        ),
        ("Cloudflare".into(), "cloudflare.com".into(), "cdn".into()),
        ("Akamai".into(), "akamai.com".into(), "cdn".into()),
        ("Fastly".into(), "fastly.com".into(), "cdn".into()),
        ("GitHub".into(), "github.com".into(), "repo".into()),
        ("Docker Hub".into(), "hub.docker.com".into(), "repo".into()),
        (
            "npm Registry".into(),
            "registry.npmjs.org".into(),
            "repo".into(),
        ),
        ("crates.io".into(), "crates.io".into(), "repo".into()),
    ];

    // User-configured DNS servers from RouterOS
    for (i, server) in dns_servers.iter().enumerate() {
        targets.push((format!("ISP DNS {}", i + 1), server.clone(), "isp".into()));
    }

    // Category: public DNS (IPv6)
    targets.push((
        "Cloudflare DNS v6".into(),
        "2606:4700:4700::1111".into(),
        "dns".into(),
    ));
    targets.push((
        "Google DNS v6".into(),
        "2001:4860:4860::8888".into(),
        "dns".into(),
    ));
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

/// Build a set of interface names that have an enabled IPv6 default route.
fn build_ipv6_default_iface_set(ipv6_routes: &[RouteEntry]) -> HashSet<String> {
    ipv6_routes
        .iter()
        .filter(|r| r.dst_address == "::/0" && !r.disabled && !r.gateway.is_empty())
        .map(resolve_ipv6_route_iface)
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

/// Look up the IPv6 address assigned directly to this WAN interface.
fn route_ipv6_addr(iface_name: &str, map: &HashMap<String, String>) -> Option<String> {
    map.get(iface_name).cloned()
}

/// Resolve the IPv6 gateway for a given interface from IPv6 default routes.
fn resolve_ipv6_gateway(iface_name: &str, ipv6_routes: &[RouteEntry]) -> Option<String> {
    ipv6_routes
        .iter()
        .filter(|r| {
            r.dst_address == "::/0"
                && r.active
                && route_is_reachable(r)
                && !r.disabled
                && !r.gateway.is_empty()
        })
        .filter(|r| resolve_ipv6_route_iface(r) == iface_name)
        .min_by_key(|r| r.distance)
        .map(|r| r.gateway.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, running: bool) -> InterfaceEntry {
        InterfaceEntry {
            id: format!("*{name}"),
            name: name.to_string(),
            iface_type: "ether".to_string(),
            mac_address: String::new(),
            running,
            rx_byte: Some(0),
            tx_byte: Some(0),
            default_name: name.to_string(),
        }
    }

    fn ipv4_address(address: &str, interface: &str) -> IpAddrEntry {
        IpAddrEntry {
            address: address.to_string(),
            interface: interface.to_string(),
            actual_interface: String::new(),
            disabled: false,
        }
    }

    fn ipv6_address(address: &str, interface: &str) -> Ipv6AddrEntry {
        Ipv6AddrEntry {
            address: address.to_string(),
            interface: interface.to_string(),
            actual_interface: String::new(),
            disabled: false,
        }
    }

    fn route(
        id: &str,
        destination: &str,
        gateway: &str,
        interface: &str,
        active: bool,
        gateway_status: &str,
        distance: u32,
    ) -> RouteEntry {
        RouteEntry {
            id: id.to_string(),
            dst_address: destination.to_string(),
            gateway: gateway.to_string(),
            gateway_status: gateway_status.to_string(),
            interface: interface.to_string(),
            active,
            disabled: false,
            distance,
        }
    }

    #[test]
    fn selects_lowest_distance_reachable_active_ipv4_route() {
        let interfaces = vec![
            interface("wan-primary", true),
            interface("wan-active-backup", true),
            interface("wan-standby", true),
            interface("wan-down", true),
        ];
        let addresses = vec![
            ipv4_address("198.51.100.2/24", "wan-primary"),
            ipv4_address("192.0.2.2/24", "wan-active-backup"),
            ipv4_address("203.0.113.2/24", "wan-standby"),
            ipv4_address("198.18.0.2/24", "wan-down"),
        ];
        let routes = vec![
            route(
                "down",
                "0.0.0.0/0",
                "198.18.0.1",
                "wan-down",
                true,
                "unreachable",
                1,
            ),
            route(
                "backup",
                "0.0.0.0/0",
                "192.0.2.1",
                "wan-active-backup",
                true,
                "reachable",
                20,
            ),
            route(
                "standby",
                "0.0.0.0/0",
                "203.0.113.1",
                "wan-standby",
                false,
                "reachable",
                2,
            ),
            route(
                "primary",
                "0.0.0.0/0",
                "198.51.100.1",
                "wan-primary",
                true,
                "reachable",
                10,
            ),
        ];

        let wans = resolve_all_wans(&addresses, &interfaces, &routes, &[], &[]);

        assert_eq!(wans.len(), 4);
        assert_eq!(wans[0].interface_name, "wan-primary");
        assert!(wans[0].is_primary);
        assert!(wans
            .iter()
            .any(|wan| { wan.interface_name == "wan-standby" && wan.online && !wan.is_primary }));
        assert!(wans
            .iter()
            .any(|wan| wan.interface_name == "wan-down" && !wan.online));
    }

    #[test]
    fn resolves_ipv6_only_default_route() {
        let interfaces = vec![interface("sfp-wan", true)];
        let addresses = vec![ipv6_address("2001:db8:1::2/64", "sfp-wan")];
        let routes = vec![route(
            "v6-default",
            "::/0",
            "fe80::1",
            "sfp-wan",
            true,
            "reachable",
            1,
        )];

        let wans = resolve_all_wans(&[], &interfaces, &[], &addresses, &routes);

        assert_eq!(wans.len(), 1);
        assert_eq!(wans[0].interface_name, "sfp-wan");
        assert_eq!(wans[0].ipv6_address.as_deref(), Some("2001:db8:1::2"));
        assert_eq!(wans[0].ipv6_gateway.as_deref(), Some("fe80::1"));
        assert!(wans[0].is_primary);
    }

    #[test]
    fn active_ipv6_route_can_promote_an_existing_dual_stack_wan() {
        let interfaces = vec![interface("ether1", true)];
        let ipv4_addresses = vec![ipv4_address("192.0.2.2/24", "ether1")];
        let ipv6_addresses = vec![ipv6_address("2001:db8:1::2/64", "ether1")];
        let ipv4_routes = vec![route(
            "v4-down",
            "0.0.0.0/0",
            "192.0.2.1",
            "ether1",
            false,
            "unreachable",
            10,
        )];
        let ipv6_routes = vec![route(
            "v6-active",
            "::/0",
            "fe80::1",
            "ether1",
            true,
            "reachable",
            1,
        )];

        let wans = resolve_all_wans(
            &ipv4_addresses,
            &interfaces,
            &ipv4_routes,
            &ipv6_addresses,
            &ipv6_routes,
        );

        assert_eq!(wans.len(), 1);
        assert!(wans[0].is_primary);
        assert!(wans[0].online);
        assert_eq!(wans[0].distance, 1);
        assert_eq!(wans[0].ipv6_gateway.as_deref(), Some("fe80::1"));
    }

    #[test]
    fn resolves_pppoe_interface_from_gateway_name() {
        let interfaces = vec![interface("pppoe-out1", true)];
        let addresses = vec![ipv4_address("100.64.0.2/32", "pppoe-out1")];
        let routes = vec![route(
            "pppoe-default",
            "0.0.0.0/0",
            "pppoe-out1",
            "",
            true,
            "reachable",
            1,
        )];

        let wans = resolve_all_wans(&addresses, &interfaces, &routes, &[], &[]);

        assert_eq!(wans.len(), 1);
        assert_eq!(wans[0].interface_name, "pppoe-out1");
        assert_eq!(wans[0].ip_address, "100.64.0.2");
        assert!(wans[0].online);
    }

    #[test]
    fn does_not_count_multiple_default_routes_on_one_interface_twice() {
        let interfaces = vec![interface("ether1", true)];
        let addresses = vec![ipv4_address("192.0.2.2/24", "ether1")];
        let routes = vec![
            route(
                "preferred",
                "0.0.0.0/0",
                "192.0.2.1",
                "ether1",
                true,
                "192.0.2.1 reachable via ether1",
                1,
            ),
            route(
                "alternate",
                "0.0.0.0/0",
                "192.0.2.254",
                "ether1",
                false,
                "reachable",
                10,
            ),
        ];

        let wans = resolve_all_wans(&addresses, &interfaces, &routes, &[], &[]);

        assert_eq!(wans.len(), 1);
        assert!(wans[0].is_primary);
        assert_eq!(wans[0].gateway, "192.0.2.1");
    }

    #[test]
    fn no_default_route_never_promotes_a_lan_interface() {
        let interfaces = vec![interface("bridge-lan", true)];
        let addresses = vec![ipv4_address("192.168.88.1/24", "bridge-lan")];
        let ipv6_addresses = vec![ipv6_address("2001:db8:88::1/64", "bridge-lan")];

        let wans = resolve_all_wans(&addresses, &interfaces, &[], &ipv6_addresses, &[]);

        assert!(wans.is_empty());
        let empty = empty_wan();
        assert_eq!(empty.interface_name, "—");
        assert!(!empty.online);
    }

    #[test]
    fn does_not_borrow_a_lan_ipv6_address_for_a_wan() {
        let interfaces = vec![interface("ether1", true), interface("bridge-lan", true)];
        let ipv6_addresses = vec![ipv6_address("2001:db8:88::1/64", "bridge-lan")];
        let ipv6_routes = vec![route(
            "v6-default",
            "::/0",
            "fe80::1",
            "ether1",
            true,
            "reachable",
            1,
        )];

        let wans = resolve_all_wans(&[], &interfaces, &[], &ipv6_addresses, &ipv6_routes);

        assert_eq!(wans.len(), 1);
        assert_eq!(wans[0].interface_name, "ether1");
        assert_eq!(wans[0].ipv6_address, None);
        assert_eq!(wans[0].ipv6_gateway, None);
    }

    #[test]
    fn calculates_rate_from_actual_elapsed_time() {
        let rate = calculate_counter_rate(Some(100), 300, Some(1000), Some(1004), Some(4.0));

        assert_eq!(rate.transition, CounterTransition::Advanced);
        assert_eq!(rate.delta_bytes, Some(200));
        assert_eq!(rate.bits_per_second, Some(400.0));
    }

    #[test]
    fn classifies_counter_reset_without_emitting_a_rate() {
        let rate = calculate_counter_rate(Some(1000), 5, Some(1000), Some(1005), Some(5.0));

        assert_eq!(rate.transition, CounterTransition::Reset);
        assert_eq!(rate.delta_bytes, None);
        assert_eq!(rate.bits_per_second, None);
    }

    #[test]
    fn classifies_reboot_before_counter_wrap() {
        let rate = calculate_counter_rate(Some(u64::MAX - 4), 5, Some(1000), Some(10), Some(2.0));

        assert_eq!(rate.transition, CounterTransition::Rebooted);
        assert_eq!(rate.delta_bytes, None);
        assert_eq!(rate.bits_per_second, None);
    }

    #[test]
    fn classifies_reboot_even_when_counter_has_already_exceeded_previous_value() {
        let rate = calculate_counter_rate(Some(100), 200, Some(1000), Some(10), Some(2.0));

        assert_eq!(rate.transition, CounterTransition::Rebooted);
        assert_eq!(rate.delta_bytes, None);
        assert_eq!(rate.bits_per_second, None);
    }

    #[test]
    fn inactive_standby_does_not_replace_a_down_active_route_as_primary() {
        let interfaces = vec![interface("active-down", false), interface("standby", true)];
        let addresses = vec![
            ipv4_address("192.0.2.2/24", "active-down"),
            ipv4_address("198.51.100.2/24", "standby"),
        ];
        let routes = vec![
            route(
                "active",
                "0.0.0.0/0",
                "192.0.2.1",
                "active-down",
                true,
                "reachable",
                1,
            ),
            route(
                "standby",
                "0.0.0.0/0",
                "198.51.100.1",
                "standby",
                false,
                "reachable",
                2,
            ),
        ];

        let wans = resolve_all_wans(&addresses, &interfaces, &routes, &[], &[]);

        assert!(wans.iter().all(|wan| !wan.is_primary));
        assert!(wans
            .iter()
            .any(|wan| wan.interface_name == "standby" && wan.online));
    }

    #[test]
    fn calculates_wrapped_counter_without_overflow() {
        let rate = calculate_counter_rate(Some(u64::MAX - 4), 5, Some(1000), Some(1002), Some(2.0));

        assert_eq!(rate.transition, CounterTransition::Wrapped);
        assert_eq!(rate.delta_bytes, Some(10));
        assert_eq!(rate.bits_per_second, Some(40.0));
    }

    #[test]
    fn does_not_guess_a_32_bit_wrap_for_routeros_64_bit_counters() {
        let rate = calculate_counter_rate(
            Some(u32::MAX as u64 - 4),
            5,
            Some(1000),
            Some(1002),
            Some(2.0),
        );

        assert_eq!(rate.transition, CounterTransition::Reset);
        assert_eq!(rate.delta_bytes, None);
        assert_eq!(rate.bits_per_second, None);
    }

    #[test]
    fn rejects_non_positive_elapsed_time() {
        let rate = calculate_counter_rate(Some(100), 200, Some(10), Some(10), Some(0.0));

        assert_eq!(rate.transition, CounterTransition::InvalidElapsed);
        assert_eq!(rate.delta_bytes, Some(100));
        assert_eq!(rate.bits_per_second, None);
    }

    #[test]
    fn device_inference_accepts_missing_or_short_mac_addresses() {
        assert_eq!(infer_device_type("unknown", ""), "desktop");
        assert_eq!(infer_device_type("unknown", "aa:bb"), "desktop");
    }
}
