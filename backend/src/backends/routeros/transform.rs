/// Converts raw RouterOS REST API response types into the vendor-neutral
/// `RouterData` struct used by the transform layer.
///
/// This module handles all RouterOS-specific string → typed parsing
/// (e.g., `"true"/"false"` → `bool`, numeric strings → `u64`/`f64`).
/// The main `poller::transform` module then works purely with typed data.

use crate::backends::*;
use crate::backends::routeros::models::*;

pub fn routeros_to_router_data(
    sys: SystemResource,
    identity: SystemIdentity,
    ips: Vec<IpAddress>,
    interfaces: Vec<Interface>,
    arp: Vec<ArpEntry>,
    dns: DnsConfig,
    leases: Vec<DhcpLease>,
    wireless_regs: Vec<WirelessRegistration>,
    routes: Vec<Route>,
    connections: Vec<ConnectionEntry>,
    ipv6_ips: Vec<Ipv6Address>,
    ipv6_routes: Vec<Ipv6Route>,
    ipv6_neighbors: Vec<Ipv6Neighbor>,
    ipv6_connections: Vec<Ipv6ConnectionEntry>,
) -> RouterData {
    RouterData {
        system: SystemData {
            uptime: sys.uptime.clone(),
            uptime_seconds: parse_u64(&sys.uptime_seconds),
            cpu_load: parse_f64(&sys.cpu_load),
            free_memory: parse_u64(&sys.free_memory),
            total_memory: parse_u64(&sys.total_memory),
            free_hdd: parse_u64(&sys.free_hdd),
            total_hdd: parse_u64(&sys.total_hdd),
            cpu_count: parse_u64(&sys.cpu_count) as u32,
            cpu_frequency: sys.cpu_frequency.clone(),
            architecture_name: sys.architecture_name.clone(),
            board_name: sys.board_name.clone(),
            version: sys.version.clone(),
            platform: sys.platform.clone(),
        },

        identity: IdentityData {
            name: identity.name.clone(),
        },

        ip_addresses: ips
            .iter()
            .map(|ip| IpAddrEntry {
                id: ip.id.clone(),
                address: ip.address.clone(),
                network: ip.network.clone(),
                interface: ip.interface.clone(),
                actual_interface: ip.actual_interface.clone(),
                disabled: ip.disabled == "true",
                dynamic: ip.dynamic == "true",
                comment: ip.comment.clone(),
            })
            .collect(),

        ipv6_addresses: ipv6_ips
            .iter()
            .map(|ip| Ipv6AddrEntry {
                id: ip.id.clone(),
                address: ip.address.clone(),
                network: ip.network.clone(),
                interface: ip.interface.clone(),
                actual_interface: ip.actual_interface.clone(),
                disabled: ip.disabled == "true",
                dynamic: ip.dynamic == "true",
                comment: ip.comment.clone(),
                advertise: ip.advertise == "true",
                eui_64: ip.eui_64 == "true",
                from_pool: ip.from_pool == "true",
                no_dad: ip.no_dad == "true",
            })
            .collect(),

        interfaces: interfaces
            .iter()
            .map(|iface| InterfaceEntry {
                id: iface.id.clone(),
                name: iface.name.clone(),
                iface_type: iface.iface_type.clone(),
                mtu: parse_u64(&iface.mtu),
                mac_address: iface.mac_address.clone(),
                running: iface.running == "true",
                disabled: iface.disabled == "true",
                rx_byte: parse_u64(&iface.rx_byte),
                tx_byte: parse_u64(&iface.tx_byte),
                rx_packet: parse_u64(&iface.rx_packet),
                tx_packet: parse_u64(&iface.tx_packet),
                rx_drop: parse_u64(&iface.rx_drop),
                tx_drop: parse_u64(&iface.tx_drop),
                tx_queue_drop: parse_u64(&iface.tx_queue_drop),
                last_link_up_time: iface.last_link_up_time.clone(),
                comment: iface.comment.clone(),
                default_name: iface.default_name.clone(),
            })
            .collect(),

        routes: routes
            .iter()
            .map(|r| RouteEntry {
                id: r.id.clone(),
                dst_address: r.dst_address.clone(),
                gateway: r.gateway.clone(),
                gateway_status: r.gateway_status.clone(),
                interface: r.interface.clone(),
                active: r.active != "false",
                disabled: r.disabled == "true",
                distance: parse_u64(&r.distance) as u32,
                comment: r.comment.clone(),
            })
            .collect(),

        ipv6_routes: ipv6_routes
            .iter()
            .map(|r| RouteEntry {
                id: r.id.clone(),
                dst_address: r.dst_address.clone(),
                gateway: r.gateway.clone(),
                gateway_status: r.gateway_status.clone(),
                interface: r.interface.clone(),
                active: r.active != "false",
                disabled: r.disabled == "true",
                distance: parse_u64(&r.distance) as u32,
                comment: r.comment.clone(),
            })
            .collect(),

        arp_entries: arp
            .iter()
            .map(|a| NeighborEntry {
                id: a.id.clone(),
                address: a.address.clone(),
                mac_address: a.mac_address.clone(),
                interface: a.interface.clone(),
                status: a.status.clone(),
                dynamic: a.dynamic == "true",
                disabled: a.disabled == "true",
                comment: a.comment.clone(),
                dhcp_name: a.dhcp_name.clone(),
            })
            .collect(),

        ipv6_neighbors: ipv6_neighbors
            .iter()
            .map(|n| NeighborEntry {
                id: n.id.clone(),
                address: n.address.clone(),
                mac_address: n.mac_address.clone(),
                interface: n.interface.clone(),
                status: n.status.clone(),
                dynamic: n.dynamic == "true",
                disabled: n.disabled == "true",
                comment: n.comment.clone(),
                dhcp_name: String::new(), // IPv6 neighbors don't have DHCP names
            })
            .collect(),

        dns_servers: extract_dns_servers(&dns.servers),

        dhcp_leases: leases
            .iter()
            .map(|l| DhcpLeaseEntry {
                id: l.id.clone(),
                address: l.address.clone(),
                mac_address: l.mac_address.clone(),
                host_name: l.host_name.clone(),
                server: l.server.clone(),
                status: l.status.clone(),
                expires_after: l.expires_after.clone(),
                active_mac_address: l.active_mac_address.clone(),
                active_address: l.active_address.clone(),
                active_server: l.active_server.clone(),
            })
            .collect(),

        wireless_clients: wireless_regs
            .iter()
            .map(|w| WirelessClientEntry {
                id: w.id.clone(),
                interface: w.interface.clone(),
                mac_address: w.mac_address.clone(),
                ap: w.ap.clone(),
                signal_strength: w.signal_strength.parse::<i32>().ok(),
                signal_to_noise: w.signal_to_noise.parse::<i32>().ok(),
                tx_rate: parse_i64(&w.tx_rate),
                rx_rate: parse_i64(&w.rx_rate),
                uptime: w.uptime.clone(),
                tx_ccq: parse_u64(&w.tx_ccq) as i32,
                rx_ccq: parse_u64(&w.rx_ccq) as i32,
            })
            .collect(),

        connection_count: connections.len() as u32,
        ipv6_connection_count: ipv6_connections.len() as u32,
    }
}

/// Extract DNS server IPs from the comma-separated RouterOS format.
fn extract_dns_servers(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ── Parse helpers ──────────────────────────────────────────────

fn parse_f64(s: &str) -> f64 {
    s.parse().unwrap_or(0.0)
}

fn parse_u64(s: &str) -> u64 {
    s.parse().unwrap_or(0)
}

fn parse_i64(s: &str) -> i64 {
    s.parse().unwrap_or(0)
}
