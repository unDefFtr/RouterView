use crate::backends::routeros::models::*;
/// Converts raw RouterOS REST API response types into the vendor-neutral
/// `RouterData` struct used by the transform layer.
///
/// This module handles all RouterOS-specific string → typed parsing
/// (e.g., `"true"/"false"` → `bool`, numeric strings → `u64`/`f64`).
/// The main `poller::transform` module then works purely with typed data.
use crate::backends::*;

pub(crate) struct RouterOsSnapshot {
    pub counter_sample_time: CounterSampleTime,
    pub system: SystemResource,
    pub hardware_identity: Option<String>,
    pub identity: SystemIdentity,
    pub ip_addresses: Vec<IpAddress>,
    pub interfaces: Vec<Interface>,
    pub arp_entries: Vec<ArpEntry>,
    pub dhcp_leases: Vec<DhcpLease>,
    pub wireless_registrations: Vec<WirelessRegistration>,
    pub routes: Vec<Route>,
    pub connection_count: u32,
    pub ipv6_addresses: Vec<Ipv6Address>,
    pub ipv6_routes: Vec<Ipv6Route>,
    pub ipv6_neighbors: Vec<Ipv6Neighbor>,
    pub ipv6_connection_count: u32,
}

pub(crate) fn routeros_to_router_data(snapshot: RouterOsSnapshot) -> RouterData {
    let RouterOsSnapshot {
        counter_sample_time,
        system: sys,
        hardware_identity,
        identity,
        ip_addresses: ips,
        interfaces,
        arp_entries: arp,
        dhcp_leases: leases,
        wireless_registrations: wireless_regs,
        routes,
        connection_count,
        ipv6_addresses: ipv6_ips,
        ipv6_routes,
        ipv6_neighbors,
        ipv6_connection_count,
    } = snapshot;

    RouterData {
        counter_sample_time,
        system: SystemData {
            hardware_identity,
            uptime: sys.uptime.clone(),
            uptime_seconds: parse_u64_optional(&sys.uptime_seconds)
                .into_iter()
                .chain(parse_uptime_seconds(&sys.uptime))
                .max(),
            cpu_load: parse_f64(&sys.cpu_load),
            free_memory: parse_u64(&sys.free_memory),
            total_memory: parse_u64(&sys.total_memory),
            free_hdd: parse_u64(&sys.free_hdd),
            total_hdd: parse_u64(&sys.total_hdd),
            architecture_name: sys.architecture_name.clone(),
            board_name: sys.board_name.clone(),
            version: sys.version.clone(),
        },

        identity: IdentityData {
            name: identity.name.clone(),
        },

        ip_addresses: ips
            .iter()
            .map(|ip| IpAddrEntry {
                address: ip.address.clone(),
                interface: ip.interface.clone(),
                actual_interface: ip.actual_interface.clone(),
                disabled: ip.disabled == "true",
            })
            .collect(),

        ipv6_addresses: ipv6_ips
            .iter()
            .map(|ip| Ipv6AddrEntry {
                address: ip.address.clone(),
                interface: ip.interface.clone(),
                actual_interface: ip.actual_interface.clone(),
                disabled: ip.disabled == "true",
            })
            .collect(),

        interfaces: interfaces
            .iter()
            .map(|iface| InterfaceEntry {
                id: iface.id.clone(),
                name: iface.name.clone(),
                iface_type: iface.iface_type.clone(),
                mac_address: iface.mac_address.clone(),
                running: iface.running == "true",
                rx_byte: parse_u64_optional(&iface.rx_byte),
                tx_byte: parse_u64_optional(&iface.tx_byte),
                default_name: iface.default_name.clone(),
            })
            .collect(),

        routes: routes
            .iter()
            .map(|r| RouteEntry {
                id: r.id.clone(),
                dst_address: r.dst_address.clone(),
                gateway: r.gateway.clone(),
                gateway_status: normalize_gateway_status(r),
                interface: route_interface(r),
                active: r.active == "true",
                disabled: r.disabled == "true",
                distance: parse_route_distance(&r.distance),
            })
            .collect(),

        ipv6_routes: ipv6_routes
            .iter()
            .map(|r| RouteEntry {
                id: r.id.clone(),
                dst_address: r.dst_address.clone(),
                gateway: r.gateway.clone(),
                gateway_status: normalize_ipv6_gateway_status(r),
                interface: ipv6_route_interface(r),
                active: r.active == "true",
                disabled: r.disabled == "true",
                distance: parse_route_distance(&r.distance),
            })
            .collect(),

        arp_entries: arp
            .iter()
            .map(|a| NeighborEntry {
                address: a.address.clone(),
                mac_address: a.mac_address.clone(),
                interface: a.interface.clone(),
                status: a.status.clone(),
                disabled: a.disabled == "true",
            })
            .collect(),

        ipv6_neighbors: ipv6_neighbors
            .iter()
            .map(|n| NeighborEntry {
                address: n.address.clone(),
                mac_address: n.mac_address.clone(),
                interface: n.interface.clone(),
                status: n.status.clone(),
                disabled: n.disabled == "true",
            })
            .collect(),

        dhcp_leases: leases
            .iter()
            .map(|l| DhcpLeaseEntry {
                mac_address: l.mac_address.clone(),
                host_name: l.host_name.clone(),
                status: l.status.clone(),
                expires_after: l.expires_after.clone(),
                active_mac_address: l.active_mac_address.clone(),
            })
            .collect(),

        wireless_clients: wireless_regs
            .iter()
            .map(|w| WirelessClientEntry {
                mac_address: w.mac_address.clone(),
                signal_strength: w.signal_strength.parse::<i32>().ok(),
                uptime: w.uptime.clone(),
            })
            .collect(),

        connection_count,
        ipv6_connection_count,
    }
}

fn route_interface(route: &Route) -> String {
    normalized_route_interface(&route.interface, &route.immediate_gateway)
}

fn ipv6_route_interface(route: &Ipv6Route) -> String {
    normalized_route_interface(&route.interface, &route.immediate_gateway)
}

fn normalized_route_interface(explicit: &str, immediate_gateway: &str) -> String {
    let explicit = explicit.trim();
    if explicit.is_empty() {
        interface_from_immediate_gateway(immediate_gateway)
    } else {
        explicit.to_string()
    }
}

fn interface_from_immediate_gateway(value: &str) -> String {
    value
        .rsplit_once('%')
        .map(|(_, interface)| interface.trim().to_string())
        .unwrap_or_default()
}

fn normalize_gateway_status(route: &Route) -> String {
    if !route.gateway_status.trim().is_empty() {
        route.gateway_status.trim().to_ascii_lowercase()
    } else if !route.immediate_gateway.trim().is_empty() {
        "reachable".to_string()
    } else {
        String::new()
    }
}

fn normalize_ipv6_gateway_status(route: &Ipv6Route) -> String {
    if !route.gateway_status.trim().is_empty() {
        route.gateway_status.trim().to_ascii_lowercase()
    } else if !route.immediate_gateway.trim().is_empty() {
        "reachable".to_string()
    } else {
        String::new()
    }
}

// ── Parse helpers ──────────────────────────────────────────────

fn parse_f64(s: &str) -> f64 {
    s.parse().unwrap_or(0.0)
}

fn parse_u64(s: &str) -> u64 {
    s.parse().unwrap_or(0)
}

fn parse_u64_optional(value: &str) -> Option<u64> {
    value.trim().parse().ok()
}

fn parse_route_distance(value: &str) -> u32 {
    parse_u64_optional(value)
        .and_then(|distance| u32::try_from(distance).ok())
        .unwrap_or(u32::MAX)
}

fn parse_uptime_seconds(value: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut digits = String::new();
    let mut saw_unit = false;
    for unit in value.chars() {
        if unit.is_ascii_digit() {
            digits.push(unit);
            continue;
        }
        let amount = digits.parse::<u64>().ok()?;
        let seconds = match unit.to_ascii_lowercase() {
            'w' => amount.saturating_mul(7 * 24 * 60 * 60),
            'd' => amount.saturating_mul(24 * 60 * 60),
            'h' => amount.saturating_mul(60 * 60),
            'm' => amount.saturating_mul(60),
            's' => amount,
            _ => return None,
        };
        total = total.saturating_add(seconds);
        saw_unit = true;
        digits.clear();
    }
    if !digits.is_empty() {
        return None;
    }
    saw_unit.then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn carries_hardware_identity_and_parses_routeros_uptime() {
        let system: SystemResource = serde_json::from_value(json!({
            "uptime": "1w2d3h4m5s"
        }))
        .unwrap();
        let identity: SystemIdentity = serde_json::from_value(json!({})).unwrap();
        let route: Route = serde_json::from_value(json!({
            ".id": "*1",
            "dst-address": "0.0.0.0/0",
            "gateway": "192.0.2.1",
            "immediate-gw": "192.0.2.1%ether1",
            "active": "true",
            "distance": "invalid"
        }))
        .unwrap();
        let interface: Interface = serde_json::from_value(json!({
            ".id": "*2",
            "name": "ether1",
            "rx-byte": "invalid"
        }))
        .unwrap();

        let data = routeros_to_router_data(RouterOsSnapshot {
            counter_sample_time: CounterSampleTime {
                monotonic: std::time::Instant::now(),
                unix_ms: 1_000,
            },
            system,
            hardware_identity: Some("ABC123".to_string()),
            identity,
            ip_addresses: Vec::new(),
            interfaces: vec![interface],
            arp_entries: Vec::new(),
            dhcp_leases: Vec::new(),
            wireless_registrations: Vec::new(),
            routes: vec![route],
            connection_count: 12,
            ipv6_addresses: Vec::new(),
            ipv6_routes: Vec::new(),
            ipv6_neighbors: Vec::new(),
            ipv6_connection_count: 3,
        });

        assert_eq!(data.system.hardware_identity.as_deref(), Some("ABC123"));
        assert_eq!(data.system.uptime_seconds, Some(788_645));
        assert_eq!(data.connection_count, 12);
        assert_eq!(data.ipv6_connection_count, 3);
        assert_eq!(data.routes[0].interface, "ether1");
        assert_eq!(data.routes[0].gateway_status, "reachable");
        assert!(data.routes[0].active);
        assert_eq!(data.routes[0].distance, u32::MAX);
        assert_eq!(data.interfaces[0].rx_byte, None);
        assert_eq!(data.interfaces[0].tx_byte, None);
    }
}
