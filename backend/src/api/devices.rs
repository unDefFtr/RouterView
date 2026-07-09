use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::db;
use crate::error::AppError;
use crate::state::AppState;
use crate::ws::protocol::{DashboardSnapshot, ServerMessage};

/// Request body for PUT /api/devices/:mac
#[derive(Deserialize)]
pub struct UpdateOverrideRequest {
    pub custom_name: Option<String>,
    pub custom_type: Option<String>,
}

/// Response item for GET /api/devices
#[derive(Serialize)]
pub struct DeviceOverrideResponse {
    pub mac: String,
    pub custom_name: Option<String>,
    pub custom_type: Option<String>,
    pub updated_at: i64,
}

/// GET /api/devices — list all device overrides.
pub async fn list_overrides(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DeviceOverrideResponse>>, AppError> {
    let overrides = state.traffic_db.get_all_device_overrides();
    Ok(Json(
        overrides
            .into_iter()
            .map(|o| DeviceOverrideResponse {
                mac: o.mac,
                custom_name: o.custom_name,
                custom_type: o.custom_type,
                updated_at: o.updated_at,
            })
            .collect(),
    ))
}

/// PUT /api/devices/:mac — update or delete a device override.
///
/// Saves the override to the database, then immediately reads the cached
/// snapshot, applies all overrides, and broadcasts the updated snapshot
/// so all connected clients see the change.
pub async fn update_override(
    State(state): State<Arc<AppState>>,
    Path(mac): Path<String>,
    Json(body): Json<UpdateOverrideRequest>,
) -> Result<Json<Vec<DeviceOverrideResponse>>, AppError> {
    // Store the override in the database
    state
        .traffic_db
        .upsert_device_override(
            &mac,
            body.custom_name.as_deref(),
            body.custom_type.as_deref(),
        )
        .map_err(|e| AppError::Database(e))?;

    // Re-read current snapshot, apply overrides, cache, and broadcast
    let updated_snapshot = {
        let lock = state.last_snapshot.read().await;
        match &*lock {
            Some(snapshot_arc) => {
                let mut snapshot: DashboardSnapshot = (**snapshot_arc).clone();
                db::apply_device_overrides(&mut snapshot.wifi, &state.traffic_db);
                Some(Arc::new(snapshot))
            }
            None => None,
        }
    };

    if let Some(new_snapshot_arc) = updated_snapshot {
        // Update the cache
        *state.last_snapshot.write().await = Some(new_snapshot_arc.clone());

        // Broadcast the updated snapshot to all connected clients
        let msg = Arc::new(ServerMessage::Snapshot {
            data: (*new_snapshot_arc).clone(),
        });
        let _ = state.broadcast_tx.send(msg);
    }

    // Return the full overrides list
    let overrides = state.traffic_db.get_all_device_overrides();
    Ok(Json(
        overrides
            .into_iter()
            .map(|o| DeviceOverrideResponse {
                mac: o.mac,
                custom_name: o.custom_name,
                custom_type: o.custom_type,
                updated_at: o.updated_at,
            })
            .collect(),
    ))
}
