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
    #[serde(default, rename = "architecture-name")]
    pub architecture_name: String,
    #[serde(default, rename = "board-name")]
    pub board_name: String,
    #[serde(default)]
    pub version: String,
}

/// Raw response from `/rest/system/identity`.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemIdentity {
    #[serde(default)]
    pub name: String,
}

/// Optional raw response from `/rest/system/routerboard`.
#[derive(Debug, Clone, Deserialize)]
pub struct RouterboardInfo {
    #[serde(default, rename = "serial-number")]
    pub serial_number: String,
}

/// Raw response from `/rest/ip/address`.
#[derive(Debug, Clone, Deserialize)]
pub struct IpAddress {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default, rename = "actual-interface")]
    pub actual_interface: String,
    #[serde(default)]
    pub disabled: String,
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
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default)]
    pub running: String,
    #[serde(default, rename = "rx-byte")]
    pub rx_byte: String,
    #[serde(default, rename = "tx-byte")]
    pub tx_byte: String,
    #[serde(default, rename = "default-name")]
    pub default_name: String,
}

/// Raw response from `/rest/ip/arp`.
#[derive(Debug, Clone, Deserialize)]
pub struct ArpEntry {
    #[serde(default)]
    pub address: String,
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub disabled: String,
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
    #[serde(default, rename = "immediate-gw")]
    pub immediate_gateway: String,
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
}

/// Raw response from `/rest/ip/dhcp-server/lease`.
#[derive(Debug, Clone, Deserialize)]
pub struct DhcpLease {
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default, rename = "host-name")]
    pub host_name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, rename = "expires-after")]
    pub expires_after: String,
    #[serde(default, rename = "active-mac-address")]
    pub active_mac_address: String,
}

/// Raw response from `/rest/interface/wireless/registration-table`
/// (if WiFi interfaces exist).
#[derive(Debug, Clone, Deserialize)]
pub struct WirelessRegistration {
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default, rename = "signal-strength")]
    pub signal_strength: String,
    #[serde(default)]
    pub uptime: String,
}

/// Raw response from `/rest/ip/firewall/connection`.
///
/// Minimal representation — we only count the entries for the dashboard.
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionEntry {
    #[serde(rename = ".id")]
    pub _id: String,
}

// ═══════════════════════════════════════════════════════════════════
// IPv6 models — mirroring the IPv4 structures above
// ═══════════════════════════════════════════════════════════════════

/// Raw response from `/rest/ipv6/address`.
#[derive(Debug, Clone, Deserialize)]
pub struct Ipv6Address {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default, rename = "actual-interface")]
    pub actual_interface: String,
    #[serde(default)]
    pub disabled: String,
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
    #[serde(default, rename = "immediate-gw")]
    pub immediate_gateway: String,
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
}

/// Raw response from `/rest/ipv6/neighbor`.
#[derive(Debug, Clone, Deserialize)]
pub struct Ipv6Neighbor {
    #[serde(default)]
    pub address: String,
    #[serde(default, rename = "mac-address")]
    pub mac_address: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub disabled: String,
}

/// Raw response from `/rest/ipv6/firewall/connection`.
///
/// Minimal representation — we only count the entries for the dashboard.
#[derive(Debug, Clone, Deserialize)]
pub struct Ipv6ConnectionEntry {
    #[serde(rename = ".id")]
    pub _id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deserializes_hyphenated_routeros_properties() {
        let interface: Interface = serde_json::from_value(json!({
            ".id": "*1",
            "mac-address": "00:11:22:33:44:55",
            "default-name": "ether1"
        }))
        .unwrap();
        let address: IpAddress = serde_json::from_value(json!({
            "actual-interface": "pppoe-out1"
        }))
        .unwrap();
        let routerboard: RouterboardInfo = serde_json::from_value(json!({
            "serial-number": "ABC123"
        }))
        .unwrap();
        let route: Route = serde_json::from_value(json!({
            ".id": "*3",
            "immediate-gw": "192.0.2.1%ether1"
        }))
        .unwrap();

        assert_eq!(interface.mac_address, "00:11:22:33:44:55");
        assert_eq!(interface.default_name, "ether1");
        assert_eq!(address.actual_interface, "pppoe-out1");
        assert_eq!(routerboard.serial_number, "ABC123");
        assert_eq!(route.immediate_gateway, "192.0.2.1%ether1");
    }
}
