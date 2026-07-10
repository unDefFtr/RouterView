use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::state::AppState;
use crate::ws::protocol::ServerMessage;
use crate::{auth, auth::SessionContext};

const SESSION_REVALIDATE_SECS: u64 = 30;

fn shutdown_close_frame() -> CloseFrame {
    CloseFrame {
        code: 1001,
        reason: "server shutting down".into(),
    }
}

/// Run a single WebSocket client session.
///
/// Subscribes to the broadcast channel and streams messages to the client.
/// The session ends when the client disconnects or the broadcast channel is closed.
pub async fn run_session(socket: WebSocket, state: Arc<AppState>, auth_session: SessionContext) {
    let (mut sender, mut receiver) = socket.split();

    if !auth::revalidate_session(&state.traffic_db, &auth_session).unwrap_or(false) {
        let _ = sender
            .send(Message::Close(Some(CloseFrame {
                code: 1008,
                reason: "session expired".into(),
            })))
            .await;
        return;
    }

    // Subscribe to the broadcast channel
    let mut broadcast_rx = state.broadcast_tx.subscribe();
    let mut shutdown_rx = state.shutdown_tx.subscribe();
    let mut session_check =
        tokio::time::interval(std::time::Duration::from_secs(SESSION_REVALIDATE_SECS));
    session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    session_check.tick().await;

    // ── Send cached snapshot immediately so the client has full state ──
    if let Some(snapshot) = state.last_snapshot.read().await.as_ref() {
        let msg = ServerMessage::Snapshot {
            data: (**snapshot).clone(),
        };
        if let Ok(json) = serde_json::to_string(&msg) {
            debug!("Sent cached snapshot to new client ({} bytes)", json.len());
            let _ = sender.send(Message::Text(json.into())).await;
        }
    } else {
        // No snapshot yet — at least tell the client the state
        let connected_msg = ServerMessage::ConnectionStatus {
            connected: false,
            last_poll: None,
        };
        if let Ok(json) = serde_json::to_string(&connected_msg) {
            let _ = sender.send(Message::Text(json.into())).await;
        }
    }

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    let _ = sender
                        .send(Message::Close(Some(shutdown_close_frame())))
                        .await;
                    break;
                }
            }

            _ = session_check.tick() => {
                if !auth::revalidate_session(&state.traffic_db, &auth_session).unwrap_or(false) {
                    let _ = sender
                        .send(Message::Close(Some(CloseFrame {
                            code: 1008,
                            reason: "session expired or revoked".into(),
                        })))
                        .await;
                    break;
                }
            }

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
                    Some(Ok(message)) if is_client_data_message(&message) => {
                        let _ = sender
                            .send(Message::Close(Some(CloseFrame {
                                code: 1008,
                                reason: "client data messages are not supported".into(),
                            })))
                            .await;
                        break;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        debug!("WebSocket error: {e}");
                        break;
                    }
                }
            }
        }
    }
}

fn is_client_data_message(message: &Message) -> bool {
    matches!(message, Message::Text(_) | Message::Binary(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_binary_client_messages_are_policy_violations() {
        assert!(is_client_data_message(&Message::Text("unexpected".into())));
        assert!(is_client_data_message(&Message::Binary(
            vec![1, 2, 3].into()
        )));
        assert!(!is_client_data_message(&Message::Ping(vec![].into())));
        assert!(!is_client_data_message(&Message::Pong(vec![].into())));
    }

    #[test]
    fn process_shutdown_uses_going_away_close_frame() {
        let frame = shutdown_close_frame();
        assert_eq!(frame.code, 1001);
        assert_eq!(frame.reason, "server shutting down");
    }
}
