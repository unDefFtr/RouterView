use axum::{
    extract::{ws::WebSocket, ConnectInfo, State, WebSocketUpgrade},
    response::{IntoResponse, Response},
    Extension,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{debug, info};

use crate::auth::SessionContext;
use crate::error::AppError;
use crate::state::AppState;
use crate::ws::limits::WsConnectionPermit;
use crate::ws::session;

const MAX_CLIENT_FRAME_BYTES: usize = 4 * 1024;
const MAX_CLIENT_MESSAGE_BYTES: usize = 4 * 1024;

/// Axum handler for WebSocket upgrade requests.
///
/// Upgrades the connection and spawns a per-client session task.
pub async fn ws_upgrade(
    State(state): State<Arc<AppState>>,
    Extension(auth_session): Extension<SessionContext>,
    ConnectInfo(connection): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    debug!("WebSocket upgrade request received");
    let permit = state
        .ws_connections
        .try_acquire(&auth_session.id, connection.ip())
        .map_err(|limit| {
            debug!(?limit, "WebSocket connection limit reached");
            AppError::RateLimited {
                retry_after_secs: 1,
            }
        })?;
    Ok(ws
        .max_frame_size(MAX_CLIENT_FRAME_BYTES)
        .max_message_size(MAX_CLIENT_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_ws_connection(socket, state, auth_session, permit))
        .into_response())
}

/// Called after the WebSocket upgrade is complete.
async fn handle_ws_connection(
    socket: WebSocket,
    state: Arc<AppState>,
    auth_session: SessionContext,
    permit: WsConnectionPermit,
) {
    let conn_count = state.ws_connections.total();
    info!("WebSocket client connected (total: {conn_count})");

    // Run the session
    session::run_session(socket, state.clone(), auth_session).await;

    drop(permit);
    let conn_count = state.ws_connections.total();
    info!("WebSocket client disconnected (total: {conn_count})");
}
