use std::sync::Arc;

use axum::{Json, extract::{Query, State}};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;

/// Query parameters for GET /api/traffic.
#[derive(Deserialize)]
pub struct TrafficQueryParams {
    pub start: i64,  // unix milliseconds, inclusive
    pub end: i64,    // unix milliseconds, exclusive
}

/// A single traffic data point in the API response.
#[derive(Serialize)]
pub struct TrafficPointResponse {
    pub timestamp_ms: i64,
    pub download_bps: f64,
    pub upload_bps: f64,
}

/// Response for GET /api/traffic.
#[derive(Serialize)]
pub struct TrafficResponse {
    pub points: Vec<TrafficPointResponse>,
    /// Approximate interval between points in seconds.
    pub interval_secs: u32,
}

/// Query historical traffic data.
///
/// GET /api/traffic?start=<unix_ms>&end=<unix_ms>
///
/// Returns traffic points between `start` (inclusive) and `end` (exclusive),
/// ordered by timestamp ascending. For data within 7 days the interval is
/// ~5 seconds (raw); older data is 1-minute averages.
pub async fn query_traffic(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TrafficQueryParams>,
) -> Result<Json<TrafficResponse>, AppError> {
    // Validate
    if params.end <= params.start {
        return Err(AppError::InvalidData(
            "end must be greater than start".into(),
        ));
    }

    let max_range_ms = 90 * 86400 * 1000i64;
    if params.end - params.start > max_range_ms {
        return Err(AppError::InvalidData(
            "time range exceeds 90 days".into(),
        ));
    }

    let records = state.traffic_db.query(params.start, params.end);

    // Determine interval: if all points are <7 days old it's ~5s, otherwise ~60s
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let raw_cutoff = now_ms - 7 * 86400 * 1000;
    let interval_secs = if params.start >= raw_cutoff { 5 } else { 60 };

    let points: Vec<TrafficPointResponse> = records
        .into_iter()
        .map(|r| TrafficPointResponse {
            timestamp_ms: r.timestamp_ms,
            download_bps: r.download_bps,
            upload_bps: r.upload_bps,
        })
        .collect();

    Ok(Json(TrafficResponse {
        points,
        interval_secs,
    }))
}
