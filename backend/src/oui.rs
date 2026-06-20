use std::collections::HashMap;
use std::sync::OnceLock;

/// Global OUI lookup table — loaded once on first access.
static OUI_DB: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Load the pre-processed OUI JSON (bundled at build time).
fn load_oui_db() -> &'static HashMap<String, String> {
    OUI_DB.get_or_init(|| {
        let json_bytes = include_bytes!("oui_data.json");
        serde_json::from_slice::<HashMap<String, String>>(json_bytes)
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to load OUI database: {e}");
                HashMap::new()
            })
    })
}

/// Normalise a MAC address (any format) to an uppercased 6-char hex prefix.
///
/// Accepts `DC:A6:32:ab:cd:ef`, `dca632abcdef`, `DC-A6-32-ab-cd-ef`, etc.
pub fn mac_prefix(mac: &str) -> String {
    mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Look up the vendor for a MAC address.
///
/// Returns `None` if the MAC is invalid or the OUI is not in the database.
pub fn vendor_for(mac: &str) -> Option<&'static str> {
    let prefix = mac_prefix(mac);
    if prefix.len() < 6 {
        return None;
    }
    load_oui_db().get(&prefix).map(|s| s.as_str())
}
