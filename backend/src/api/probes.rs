use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::db::ProbeTargetRow;
use crate::error::AppError;
use crate::state::AppState;

/// Serialisable probe target for the API (mirrors ProbeTargetRow but
/// with optional id for create-friendly payloads).
#[derive(serde::Deserialize)]
pub(crate) struct ProbeTargetInput {
    #[serde(default)]
    id: Option<i64>,
    name: String,
    host: String,
    category: String,
    #[serde(default)]
    sort_order: Option<i64>,
}

/// GET /api/probes — list all probe targets.
pub async fn list_probes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let rows = state.traffic_db.get_all_probe_targets();
    let list: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "host": r.host,
                "category": r.category,
                "sort_order": r.sort_order,
            })
        })
        .collect();
    Ok(Json(json!({ "targets": list })))
}

/// PUT /api/probes — replace all probe targets.
pub async fn update_probes(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Vec<ProbeTargetInput>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let rows: Vec<ProbeTargetRow> = body
        .iter()
        .enumerate()
        .map(|(i, t)| ProbeTargetRow {
            id: t.id.unwrap_or(0),
            name: t.name.trim().to_string(),
            host: t.host.trim().to_string(),
            category: t.category.trim().to_string(),
            sort_order: t.sort_order.unwrap_or(i as i64),
        })
        .filter(|t| !t.name.is_empty() && !t.host.is_empty())
        .collect();

    if rows.is_empty() {
        return Err(AppError::InvalidData(
            "at least one target with non-empty name and host is required".into(),
        ));
    }

    // Persist
    state.traffic_db.replace_all_probe_targets(&rows);

    // Hot-reload into shared state
    reload_probe_targets(&state).await;

    let list = state.traffic_db.get_all_probe_targets();
    let targets: Vec<Value> = list
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "host": r.host,
                "category": r.category,
                "sort_order": r.sort_order,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(json!({ "targets": targets }))))
}

/// POST /api/probes/reset — reset probe targets to defaults.
pub async fn reset_probes(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    state.traffic_db.reset_probe_targets();

    // Hot-reload into shared state
    reload_probe_targets(&state).await;

    let list = state.traffic_db.get_all_probe_targets();
    let targets: Vec<Value> = list
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "host": r.host,
                "category": r.category,
                "sort_order": r.sort_order,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(json!({ "targets": targets }))))
}

/// Read DB rows and update the shared probe_targets lock for hot-reload.
async fn reload_probe_targets(state: &AppState) {
    let rows = state.traffic_db.get_all_probe_targets();
    let targets: Vec<(String, String, String)> = rows
        .iter()
        .map(|r| (r.name.clone(), r.host.clone(), r.category.clone()))
        .collect();
    *state.probe_targets.write().await = targets;
}
