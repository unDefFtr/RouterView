use axum::{
    extract::{
        ws::WebSocket,
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{debug, info};

use crate::state::AppState;
use crate::ws::session;

/// Axum handler for WebSocket upgrade requests.
///
/// Upgrades the connection and spawns a per-client session task.
pub async fn ws_upgrade(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    debug!("WebSocket upgrade request received");
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state))
}

/// Called after the WebSocket upgrade is complete.
async fn handle_ws_connection(socket: WebSocket, state: Arc<AppState>) {
    let conn_count = state
        .connection_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1;
    info!("WebSocket client connected (total: {conn_count})");

    // Run the session
    session::run_session(socket, state.clone()).await;

    // Decrement on disconnect
    let conn_count = state
        .connection_count
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed)
        - 1;
    info!("WebSocket client disconnected (total: {conn_count})");
}
