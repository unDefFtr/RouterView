use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::db::{
    DatabaseError, RouterInterfaceRecord, RouterRecord, TrafficBucket, TrafficCoverage,
    TrafficQuery, TrafficQueryResult, TrafficTotals,
};
use crate::error::{ApiQuery, AppError};
use crate::state::AppState;

const DEFAULT_MAX_POINTS: usize = 1_200;
const MAX_POINTS: usize = 5_000;
const MAX_RANGE_MS: i64 = 90 * 86_400 * 1_000;

fn default_max_points() -> usize {
    DEFAULT_MAX_POINTS
}

/// Query parameters for GET /api/traffic.
#[derive(Debug, Deserialize)]
pub struct TrafficQueryParams {
    pub start: i64,
    pub end: i64,
    /// Omit to query the synthetic all-WAN aggregate interface.
    #[serde(default)]
    pub wan_name: Option<String>,
    /// Canonical stable interface key. Takes the place of `wan_name` for
    /// interfaces that were recreated with the same display name.
    #[serde(default)]
    pub interface_id: Option<String>,
    /// Upper bound for downsampled points returned by the database query.
    #[serde(default = "default_max_points")]
    pub max_points: usize,
}

#[derive(Debug, Serialize)]
pub struct RouterMetadataResponse {
    /// Stable database-independent router identity.
    pub id: String,
    pub hardware_identity: Option<String>,
    pub fallback_target: String,
    pub identity_source: String,
    pub first_seen_at_ms: i64,
    pub last_seen_at_ms: i64,
}

#[derive(Debug, Serialize)]
pub struct InterfaceMetadataResponse {
    /// Stable interface key within this router (RouterOS `.id` when available).
    pub id: String,
    pub name: String,
    pub kind: String,
    pub hardware_id: Option<String>,
    pub aggregate: bool,
    pub first_seen_at_ms: i64,
    pub last_seen_at_ms: i64,
}

/// A downsampled traffic bucket. Byte values are decimal strings so JSON
/// consumers never lose integer precision.
#[derive(Debug, Serialize)]
pub struct TrafficPointResponse {
    /// Compatibility alias for the bucket start used by the existing chart.
    pub timestamp_ms: i64,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    /// Duration with observed traffic coverage, excluding gaps.
    pub duration_ms: i64,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub download_bytes: String,
    pub upload_bytes: String,
    pub exact_download_bytes: String,
    pub exact_upload_bytes: String,
    pub estimated_download_bytes: String,
    pub estimated_upload_bytes: String,
    pub exact_duration_ms: i64,
    pub estimated_duration_ms: i64,
    pub sample_count: i64,
    pub estimated: bool,
    pub complete: bool,
    pub wan_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrafficTotalsResponse {
    pub download_bytes: String,
    pub upload_bytes: String,
    pub exact_download_bytes: String,
    pub exact_upload_bytes: String,
    pub estimated_download_bytes: String,
    pub estimated_upload_bytes: String,
    /// Compatibility fields consumed by the current frontend totals helper.
    pub estimated: bool,
    pub complete: bool,
    pub coverage_ratio: f64,
}

/// Response for GET /api/traffic backed exclusively by schema-v4 traffic
/// primitives. One response always represents exactly one router interface.
#[derive(Debug, Serialize)]
pub struct TrafficResponse {
    pub schema_version: u8,
    pub router: RouterMetadataResponse,
    pub interface: InterfaceMetadataResponse,
    pub wan_interfaces: Vec<InterfaceMetadataResponse>,
    /// Compatibility selector field used by the existing frontend.
    pub wan_names: Vec<String>,
    pub points: Vec<TrafficPointResponse>,
    pub totals: TrafficTotalsResponse,
    pub coverage: TrafficCoverage,
    pub bucket_size_ms: i64,
    /// Rounded-up compatibility alias for `bucket_size_ms`.
    pub interval_secs: u32,
}

/// Query exact and estimated traffic history for one interface.
///
/// GET /api/traffic?start=<unix_ms>&end=<unix_ms>&wan_name=<optional>
pub async fn query_traffic(
    State(state): State<Arc<AppState>>,
    ApiQuery(params): ApiQuery<TrafficQueryParams>,
) -> Result<Json<TrafficResponse>, AppError> {
    let range_ms = params
        .end
        .checked_sub(params.start)
        .ok_or_else(|| AppError::InvalidData("traffic time range cannot be represented".into()))?;
    if range_ms <= 0 {
        return Err(AppError::InvalidData(
            "end must be greater than start".into(),
        ));
    }
    if range_ms > MAX_RANGE_MS {
        return Err(AppError::InvalidData("time range exceeds 90 days".into()));
    }
    if !(1..=MAX_POINTS).contains(&params.max_points) {
        return Err(AppError::InvalidData(format!(
            "max_points must be between 1 and {MAX_POINTS}"
        )));
    }

    let wan_name = params.wan_name.as_deref().map(str::trim);
    let interface_id = params.interface_id.as_deref().map(str::trim);
    if wan_name.is_some() && interface_id.is_some() {
        return Err(AppError::InvalidData(
            "wan_name and interface_id cannot be combined".into(),
        ));
    }
    if wan_name.is_some_and(|name| name.is_empty() || name.len() > 255) {
        return Err(AppError::InvalidData(
            "wan_name must contain between 1 and 255 characters".into(),
        ));
    }
    if interface_id.is_some_and(|value| value.is_empty() || value.len() > 255) {
        return Err(AppError::InvalidData(
            "interface_id must contain between 1 and 255 characters".into(),
        ));
    }

    let fallback_target = { state.config.read().await.router_host.clone() };
    let permit = state
        .traffic_query_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::RateLimited {
            retry_after_secs: 1,
        })?;
    let traffic_db = state.traffic_db.clone();
    let wan_name = wan_name.map(str::to_string);
    let interface_id = interface_id.map(str::to_string);
    let start = params.start;
    let end = params.end;
    let max_points = params.max_points;
    let response =
        spawn_blocking_with_permit(permit, move || -> Result<TrafficResponse, AppError> {
            let router = traffic_db
                .current_router_for_target(&fallback_target)
                .map_err(map_database_error)?
                .ok_or_else(|| traffic_not_found("traffic history has not been initialized"))?;
            let interface = match interface_id.as_deref() {
                Some(interface_id) => traffic_db
                    .traffic_interface_by_key(router.id, interface_id)
                    .map_err(map_database_error)?,
                None => traffic_db
                    .traffic_interface_for_query(router.id, wan_name.as_deref())
                    .map_err(map_database_error)?,
            }
            .ok_or_else(|| {
                let message = if let Some(interface_id) = interface_id.as_deref() {
                    format!("interface '{interface_id}' has no traffic history")
                } else if let Some(name) = wan_name.as_deref() {
                    format!("WAN interface '{name}' has no traffic history")
                } else {
                    "aggregate traffic history has not been initialized".into()
                };
                traffic_not_found(message)
            })?;
            let wan_interfaces = traffic_db
                .router_wan_interfaces(router.id)
                .map_err(map_database_error)?;
            let result = traffic_db
                .query_traffic_v4(&TrafficQuery {
                    router_id: router.id,
                    interface_id: interface.id,
                    from_ms: start,
                    to_ms: end,
                    max_points,
                })
                .map_err(map_database_error)?;
            build_traffic_response(router, interface, wan_interfaces, result)
        })
        .await
        .map_err(|error| AppError::Internal(format!("traffic query task failed: {error}")))??;

    Ok(Json(response))
}

async fn spawn_blocking_with_permit<F, T>(
    permit: tokio::sync::OwnedSemaphorePermit,
    task: F,
) -> Result<T, tokio::task::JoinError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        task()
    })
    .await
}

fn build_traffic_response(
    router: RouterRecord,
    interface: RouterInterfaceRecord,
    wan_interfaces: Vec<RouterInterfaceRecord>,
    result: TrafficQueryResult,
) -> Result<TrafficResponse, AppError> {
    let selected_wan_name = (interface.kind != "aggregate").then(|| interface.name.clone());
    let mut wan_names = wan_interfaces
        .iter()
        .map(|candidate| candidate.name.clone())
        .collect::<Vec<_>>();
    wan_names.sort();
    wan_names.dedup();

    let TrafficQueryResult {
        bucket_size_ms,
        points,
        totals,
        coverage,
    } = result;
    let points = points
        .into_iter()
        .map(|point| traffic_point_response(point, selected_wan_name.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    let totals = traffic_totals_response(totals, &coverage);
    let interval_secs = u32::try_from(bucket_size_ms.saturating_add(999) / 1_000)
        .map_err(|_| AppError::Internal("traffic bucket size exceeds API limits".into()))?
        .max(1);

    Ok(TrafficResponse {
        schema_version: 4,
        router: RouterMetadataResponse {
            id: router.internal_uuid,
            hardware_identity: router.hardware_identity,
            fallback_target: router.fallback_target,
            identity_source: router.identity_source,
            first_seen_at_ms: router.first_seen_at_ms,
            last_seen_at_ms: router.last_seen_at_ms,
        },
        interface: interface_metadata_response(interface),
        wan_interfaces: wan_interfaces
            .into_iter()
            .map(interface_metadata_response)
            .collect(),
        wan_names,
        points,
        totals,
        coverage,
        bucket_size_ms,
        interval_secs,
    })
}

fn traffic_point_response(
    point: TrafficBucket,
    wan_name: Option<String>,
) -> Result<TrafficPointResponse, AppError> {
    let download_bytes =
        add_decimal_bytes(&point.exact_download_bytes, &point.estimated_download_bytes)?;
    let upload_bytes = add_decimal_bytes(&point.exact_upload_bytes, &point.estimated_upload_bytes)?;
    let duration_ms = point
        .exact_duration_ms
        .saturating_add(point.estimated_duration_ms);
    let bucket_duration_ms = point.ended_at_ms.saturating_sub(point.started_at_ms);
    let estimated = point.estimated_duration_ms > 0
        || point.estimated_download_bytes != "0"
        || point.estimated_upload_bytes != "0";

    Ok(TrafficPointResponse {
        timestamp_ms: point.started_at_ms,
        started_at_ms: point.started_at_ms,
        ended_at_ms: point.ended_at_ms,
        duration_ms,
        download_bps: point.download_bps,
        upload_bps: point.upload_bps,
        download_bytes,
        upload_bytes,
        exact_download_bytes: point.exact_download_bytes,
        exact_upload_bytes: point.exact_upload_bytes,
        estimated_download_bytes: point.estimated_download_bytes,
        estimated_upload_bytes: point.estimated_upload_bytes,
        exact_duration_ms: point.exact_duration_ms,
        estimated_duration_ms: point.estimated_duration_ms,
        sample_count: point.sample_count,
        estimated,
        complete: duration_ms == bucket_duration_ms,
        wan_name,
    })
}

fn traffic_totals_response(
    totals: TrafficTotals,
    coverage: &TrafficCoverage,
) -> TrafficTotalsResponse {
    TrafficTotalsResponse {
        download_bytes: totals.download_bytes,
        upload_bytes: totals.upload_bytes,
        exact_download_bytes: totals.exact_download_bytes,
        exact_upload_bytes: totals.exact_upload_bytes,
        estimated_download_bytes: totals.estimated_download_bytes.clone(),
        estimated_upload_bytes: totals.estimated_upload_bytes.clone(),
        estimated: coverage.estimated_duration_ms > 0
            || totals.estimated_download_bytes != "0"
            || totals.estimated_upload_bytes != "0",
        complete: coverage.covered_duration_ms == coverage.requested_duration_ms,
        coverage_ratio: coverage.completeness,
    }
}

fn interface_metadata_response(interface: RouterInterfaceRecord) -> InterfaceMetadataResponse {
    InterfaceMetadataResponse {
        id: interface.interface_key,
        name: interface.name,
        aggregate: interface.kind == "aggregate",
        kind: interface.kind,
        hardware_id: interface.hardware_id,
        first_seen_at_ms: interface.first_seen_at_ms,
        last_seen_at_ms: interface.last_seen_at_ms,
    }
}

fn add_decimal_bytes(left: &str, right: &str) -> Result<String, AppError> {
    let left = left
        .parse::<u128>()
        .map_err(|_| AppError::Internal("database returned an invalid byte total".into()))?;
    let right = right
        .parse::<u128>()
        .map_err(|_| AppError::Internal("database returned an invalid byte total".into()))?;
    left.checked_add(right)
        .map(|total| total.to_string())
        .ok_or_else(|| AppError::Internal("traffic byte total overflowed".into()))
}

fn traffic_not_found(message: impl Into<String>) -> AppError {
    AppError::InvalidRequest {
        status: StatusCode::NOT_FOUND,
        code: "traffic_history_not_found",
        message: message.into(),
    }
}

fn map_database_error(error: DatabaseError) -> AppError {
    match error {
        DatabaseError::Sqlite(error) => AppError::Database(error),
        DatabaseError::InvalidCommand(message) => AppError::InvalidData(message),
        other => AppError::Internal(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_query_keeps_permit_after_waiter_is_cancelled() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let waiter = tokio::spawn(spawn_blocking_with_permit(permit, move || {
            let _ = started_tx.send(());
            release_rx.recv().unwrap();
        }));
        started_rx.await.unwrap();
        waiter.abort();
        let _ = waiter.await;

        let permit_was_held = semaphore.clone().try_acquire_owned().is_err();
        release_tx.send(()).unwrap();
        let reacquired = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(reacquired);

        assert!(permit_was_held);
    }

    #[test]
    fn v4_response_preserves_decimal_bytes_and_coverage_metadata() {
        let response = build_traffic_response(
            RouterRecord {
                id: 1,
                internal_uuid: "router-uuid".into(),
                hardware_identity: Some("serial-a".into()),
                fallback_target: "192.0.2.1".into(),
                identity_source: "hardware".into(),
                first_seen_at_ms: 10,
                last_seen_at_ms: 20,
            },
            RouterInterfaceRecord {
                id: 2,
                router_id: 1,
                interface_key: "__aggregate__".into(),
                name: "Aggregate".into(),
                kind: "aggregate".into(),
                hardware_id: None,
                first_seen_at_ms: 10,
                last_seen_at_ms: 20,
            },
            vec![
                RouterInterfaceRecord {
                    id: 3,
                    router_id: 1,
                    interface_key: "*1".into(),
                    name: "ether1".into(),
                    kind: "wan".into(),
                    hardware_id: Some("aa:bb:cc:dd:ee:ff".into()),
                    first_seen_at_ms: 10,
                    last_seen_at_ms: 20,
                },
                RouterInterfaceRecord {
                    id: 4,
                    router_id: 1,
                    interface_key: "*2".into(),
                    name: "ether1".into(),
                    kind: "wan".into(),
                    hardware_id: None,
                    first_seen_at_ms: 10,
                    last_seen_at_ms: 15,
                },
            ],
            TrafficQueryResult {
                bucket_size_ms: 1_500,
                points: vec![TrafficBucket {
                    started_at_ms: 1_000,
                    ended_at_ms: 2_500,
                    download_bps: 80.0,
                    upload_bps: 40.0,
                    exact_download_bytes: "9007199254740993".into(),
                    exact_upload_bytes: "4".into(),
                    estimated_download_bytes: "7".into(),
                    estimated_upload_bytes: "1".into(),
                    exact_duration_ms: 1_000,
                    estimated_duration_ms: 250,
                    sample_count: 2,
                }],
                totals: TrafficTotals {
                    download_bytes: "9007199254741000".into(),
                    upload_bytes: "5".into(),
                    exact_download_bytes: "9007199254740993".into(),
                    exact_upload_bytes: "4".into(),
                    estimated_download_bytes: "7".into(),
                    estimated_upload_bytes: "1".into(),
                },
                coverage: TrafficCoverage {
                    requested_duration_ms: 1_500,
                    exact_duration_ms: 1_000,
                    estimated_duration_ms: 250,
                    covered_duration_ms: 1_250,
                    completeness: 5.0 / 6.0,
                    gap_count: 1,
                },
            },
        )
        .unwrap();

        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["schema_version"], 4);
        assert_eq!(json["interface"]["id"], "__aggregate__");
        assert_eq!(json["wan_names"], serde_json::json!(["ether1"]));
        assert_eq!(json["wan_interfaces"].as_array().unwrap().len(), 2);
        assert_eq!(json["bucket_size_ms"], 1_500);
        assert_eq!(json["interval_secs"], 2);
        assert_eq!(json["points"][0]["timestamp_ms"], 1_000);
        assert_eq!(json["points"][0]["duration_ms"], 1_250);
        assert_eq!(json["points"][0]["download_bytes"], "9007199254741000");
        assert_eq!(json["points"][0]["estimated"], true);
        assert_eq!(json["points"][0]["complete"], false);
        assert_eq!(json["points"][0]["wan_name"], serde_json::Value::Null);
        assert_eq!(json["totals"]["exact_download_bytes"], "9007199254740993");
        assert_eq!(json["totals"]["complete"], false);
        assert_eq!(json["coverage"]["gap_count"], 1);
    }
}
