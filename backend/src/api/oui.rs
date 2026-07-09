use std::sync::Arc;

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::error::{ApiQuery, AppError};
use crate::state::AppState;

/// Query parameters for GET /api/oui/lookup (batch).
#[derive(Deserialize)]
pub struct OuiLookupParams {
    /// Comma-separated list of MAC addresses to look up.
    pub macs: String,
}

/// A single OUI lookup result.
#[derive(Serialize)]
pub struct OuiLookupEntry {
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
}

/// Response for the OUI lookup API.
#[derive(Serialize)]
pub struct OuiLookupResponse {
    pub entries: Vec<OuiLookupEntry>,
}

/// Batch OUI vendor lookup.
///
/// GET /api/oui/lookup?macs=DC:A6:32:ab:cd:ef,A4:D1:D2:12:34:56
///
/// Each MAC is normalised to its 6-hex-char OUI prefix and looked up
/// in the embedded IEEE OUI database. Returns one entry per MAC with
/// the vendor name (or null if unknown).
pub async fn lookup_oui(
    _state: State<Arc<AppState>>,
    ApiQuery(params): ApiQuery<OuiLookupParams>,
) -> Result<Json<OuiLookupResponse>, AppError> {
    let entries: Vec<OuiLookupEntry> = params
        .macs
        .split(',')
        .map(|mac| mac.trim())
        .filter(|mac| !mac.is_empty())
        .map(|mac| OuiLookupEntry {
            vendor: crate::oui::vendor_for(mac).map(|s| s.to_string()),
            mac: mac.to_string(),
        })
        .collect();

    Ok(Json(OuiLookupResponse { entries }))
}
