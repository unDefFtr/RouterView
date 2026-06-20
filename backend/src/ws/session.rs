use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::state::AppState;
use crate::ws::protocol::ServerMessage;

/// Run a single WebSocket client session.
///
/// Subscribes to the broadcast channel and streams messages to the client.
/// The session ends when the client disconnects or the broadcast channel is closed.
pub async fn run_session(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to the broadcast channel
    let mut broadcast_rx = state.broadcast_tx.subscribe();

    // ── Send cached snapshot immediately so the client has full state ──
    if let Some(snapshot) = state.last_snapshot.read().await.as_ref() {
        let msg = ServerMessage::Snapshot {
            data: (**snapshot).clone(),
        };
        if let Ok(json) = serde_json::to_string(&msg) {
            debug!(
                "Sent cached snapshot to new client ({} bytes)",
                json.len()
            );
            let _ = sender.send(Message::Text(json.into())).await;
        }
    } else {
        // No snapshot yet — at least tell the client the state
        let connected_msg = ServerMessage::ConnectionStatus {
            routeros: false,
            last_poll: None,
        };
        if let Ok(json) = serde_json::to_string(&connected_msg) {
            let _ = sender.send(Message::Text(json.into())).await;
        }
    }

    loop {
        tokio::select! {
            // Incoming broadcast messages from the poll engine
            result = broadcast_rx.recv() => {
                match result {
                    Ok(msg_arc) => {
                        let msg: &ServerMessage = &msg_arc;
                        match serde_json::to_string(msg) {
                            Ok(json) => {
                                if let Err(e) = sender.send(Message::Text(json.into())).await {
                                    debug!("Failed to send WS message: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to serialize WS message: {e}");
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        debug!("WS client lagged by {} messages", n);
                        // Request a fresh snapshot via the cached one
                        if let Some(snapshot) = state.last_snapshot.read().await.as_ref() {
                            let msg = ServerMessage::Snapshot {
                                data: (**snapshot).clone(),
                            };
                            if let Ok(json) = serde_json::to_string(&msg) {
                                let _ = sender.send(Message::Text(json.into())).await;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("Broadcast channel closed");
                        break;
                    }
                }
            }

            // Client messages / disconnection
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("Client sent close frame");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // Respond to pings
                        let _ = sender.send(Message::Pong(data)).await;
                    }
                    Some(Err(e)) => {
                        debug!("WebSocket error: {e}");
                        break;
                    }
                    // Ignore other client messages
                    _ => {}
                }
            }
        }
    }
}
