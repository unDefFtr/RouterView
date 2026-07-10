use axum::{
    extract::{ws::WebSocket, ConnectInfo, State, WebSocketUpgrade},
    http::HeaderMap,
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
use crate::ws::tracker::WsSessionGuard;

const MAX_CLIENT_FRAME_BYTES: usize = 4 * 1024;
const MAX_CLIENT_MESSAGE_BYTES: usize = 4 * 1024;

/// Axum handler for WebSocket upgrade requests.
///
/// Upgrades the connection and spawns a per-client session task.
pub async fn ws_upgrade(
    State(state): State<Arc<AppState>>,
    Extension(auth_session): Extension<SessionContext>,
    ConnectInfo(connection): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    debug!("WebSocket upgrade request received");
    let source = state.auth_security.client_ip(connection.ip(), &headers)?;
    let permit = state
        .ws_connections
        .try_acquire(&auth_session.id, source)
        .map_err(|limit| {
            debug!(?limit, "WebSocket connection limit reached");
            AppError::RateLimited {
                retry_after_secs: 1,
            }
        })?;
    let session_guard =
        state
            .ws_sessions
            .try_register()
            .ok_or_else(|| AppError::InvalidRequest {
                status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
                code: "server_shutting_down",
                message: "Server is shutting down".to_string(),
            })?;
    Ok(ws
        .max_frame_size(MAX_CLIENT_FRAME_BYTES)
        .max_message_size(MAX_CLIENT_MESSAGE_BYTES)
        .on_upgrade(move |socket| {
            handle_ws_connection(socket, state, auth_session, permit, session_guard)
        })
        .into_response())
}

/// Called after the WebSocket upgrade is complete.
async fn handle_ws_connection(
    socket: WebSocket,
    state: Arc<AppState>,
    auth_session: SessionContext,
    permit: WsConnectionPermit,
    _session_guard: WsSessionGuard,
) {
    let conn_count = state.ws_connections.total();
    info!("WebSocket client connected (total: {conn_count})");

    // Run the session
    session::run_session(socket, state.clone(), auth_session).await;

    drop(permit);
    let conn_count = state.ws_connections.total();
    info!("WebSocket client disconnected (total: {conn_count})");
}
