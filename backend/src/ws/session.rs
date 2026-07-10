use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{broadcast, watch, RwLock};
use tracing::{debug, warn};

use crate::state::AppState;
use crate::ws::protocol::{DashboardSnapshot, ServerMessage};
use crate::{auth, auth::SessionContext};

const SESSION_REVALIDATE_SECS: u64 = 30;
const SESSION_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

enum SendAttempt<E> {
    Sent,
    Failed(E),
    Shutdown,
    TimedOut,
}

enum SnapshotRead {
    Ready(Option<Arc<DashboardSnapshot>>),
    Shutdown,
}

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
    let mut shutdown_rx = state.shutdown_tx.subscribe();

    if *shutdown_rx.borrow() {
        send_close(&mut sender, shutdown_close_frame()).await;
        return;
    }

    if !auth::revalidate_session(&state.traffic_db, &auth_session).unwrap_or(false) {
        send_close(
            &mut sender,
            CloseFrame {
                code: 1008,
                reason: "session expired".into(),
            },
        )
        .await;
        return;
    }

    // Subscribe to the broadcast channel
    let mut broadcast_rx = state.broadcast_tx.subscribe();
    let mut session_check =
        tokio::time::interval(std::time::Duration::from_secs(SESSION_REVALIDATE_SECS));
    session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    session_check.tick().await;

    // ── Send cached snapshot immediately so the client has full state ──
    let initial_snapshot =
        match read_snapshot_or_shutdown(&state.last_snapshot, &mut shutdown_rx).await {
            SnapshotRead::Ready(snapshot) => snapshot,
            SnapshotRead::Shutdown => {
                send_close(&mut sender, shutdown_close_frame()).await;
                return;
            }
        };
    if let Some(snapshot) = initial_snapshot {
        let msg = ServerMessage::Snapshot {
            data: (*snapshot).clone(),
        };
        if let Ok(json) = serde_json::to_string(&msg) {
            debug!("Sent cached snapshot to new client ({} bytes)", json.len());
            if !send_while_running(&mut sender, Message::Text(json.into()), &mut shutdown_rx).await
            {
                return;
            }
        }
    } else {
        // No snapshot yet — at least tell the client the state
        let connected_msg = ServerMessage::ConnectionStatus {
            connected: false,
            last_poll: None,
        };
        if let Ok(json) = serde_json::to_string(&connected_msg) {
            if !send_while_running(&mut sender, Message::Text(json.into()), &mut shutdown_rx).await
            {
                return;
            }
        }
    }

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    send_close(&mut sender, shutdown_close_frame()).await;
                    break;
                }
            }

            _ = session_check.tick() => {
                if !auth::revalidate_session(&state.traffic_db, &auth_session).unwrap_or(false) {
                    send_close(
                        &mut sender,
                        CloseFrame {
                            code: 1008,
                            reason: "session expired or revoked".into(),
                        },
                    )
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
                                if !send_while_running(
                                    &mut sender,
                                    Message::Text(json.into()),
                                    &mut shutdown_rx,
                                )
                                .await
                                {
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
                        let snapshot = match read_snapshot_or_shutdown(
                            &state.last_snapshot,
                            &mut shutdown_rx,
                        )
                        .await
                        {
                            SnapshotRead::Ready(snapshot) => snapshot,
                            SnapshotRead::Shutdown => {
                                send_close(&mut sender, shutdown_close_frame()).await;
                                break;
                            }
                        };
                        if let Some(snapshot) = snapshot {
                            let msg = ServerMessage::Snapshot {
                                data: (*snapshot).clone(),
                            };
                            if let Ok(json) = serde_json::to_string(&msg) {
                                if !send_while_running(
                                    &mut sender,
                                    Message::Text(json.into()),
                                    &mut shutdown_rx,
                                )
                                .await
                                {
                                    break;
                                }
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
                        if !send_while_running(
                            &mut sender,
                            Message::Pong(data),
                            &mut shutdown_rx,
                        )
                        .await
                        {
                            break;
                        }
                    }
                    Some(Ok(message)) if is_client_data_message(&message) => {
                        send_close(
                            &mut sender,
                            CloseFrame {
                                code: 1008,
                                reason: "client data messages are not supported".into(),
                            },
                        )
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

async fn read_snapshot_or_shutdown(
    snapshots: &RwLock<Option<Arc<DashboardSnapshot>>>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> SnapshotRead {
    if *shutdown_rx.borrow() {
        return SnapshotRead::Shutdown;
    }

    tokio::select! {
        biased;
        _ = wait_for_session_shutdown(shutdown_rx) => SnapshotRead::Shutdown,
        snapshot = snapshots.read() => SnapshotRead::Ready(snapshot.clone()),
    }
}

async fn send_while_running<S>(
    sender: &mut S,
    message: Message,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    match await_send_or_shutdown(sender.send(message), shutdown_rx, SESSION_SEND_TIMEOUT).await {
        SendAttempt::Sent => true,
        SendAttempt::Failed(error) => {
            debug!("Failed to send WS message: {error}");
            false
        }
        SendAttempt::Shutdown => {
            send_close(sender, shutdown_close_frame()).await;
            false
        }
        SendAttempt::TimedOut => {
            warn!("Timed out sending WebSocket message");
            false
        }
    }
}

async fn send_close<S>(sender: &mut S, frame: CloseFrame)
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Display,
{
    match tokio::time::timeout(
        SESSION_CLOSE_TIMEOUT,
        sender.send(Message::Close(Some(frame))),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => debug!("Failed to send WebSocket close frame: {error}"),
        Err(_) => warn!("Timed out sending WebSocket close frame"),
    }
}

async fn await_send_or_shutdown<F, E>(
    send: F,
    shutdown_rx: &mut watch::Receiver<bool>,
    timeout: Duration,
) -> SendAttempt<E>
where
    F: Future<Output = Result<(), E>>,
{
    if *shutdown_rx.borrow() {
        return SendAttempt::Shutdown;
    }

    tokio::select! {
        biased;
        _ = wait_for_session_shutdown(shutdown_rx) => SendAttempt::Shutdown,
        result = tokio::time::timeout(timeout, send) => match result {
            Ok(Ok(())) => SendAttempt::Sent,
            Ok(Err(error)) => SendAttempt::Failed(error),
            Err(_) => SendAttempt::TimedOut,
        },
    }
}

async fn wait_for_session_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
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

    #[tokio::test]
    async fn initial_send_observes_shutdown_that_was_already_requested() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx.send_replace(true);
        let mut shutdown_rx = shutdown_rx;

        let result = await_send_or_shutdown(
            std::future::ready(Ok::<(), ()>(())),
            &mut shutdown_rx,
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, SendAttempt::Shutdown));
    }

    #[tokio::test]
    async fn slow_initial_send_is_cancelled_by_shutdown() {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let send = async { std::future::pending::<Result<(), ()>>().await };
        let waiter = tokio::spawn(async move {
            await_send_or_shutdown(send, &mut shutdown_rx, Duration::from_secs(60)).await
        });
        tokio::task::yield_now().await;

        shutdown_tx.send_replace(true);
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, SendAttempt::Shutdown));
    }

    #[tokio::test]
    async fn initial_snapshot_lock_wait_is_cancelled_by_shutdown() {
        let snapshots = Arc::new(RwLock::new(None));
        let write_guard = snapshots.write().await;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let waiter = tokio::spawn({
            let snapshots = snapshots.clone();
            async move { read_snapshot_or_shutdown(&snapshots, &mut shutdown_rx).await }
        });
        tokio::task::yield_now().await;

        shutdown_tx.send_replace(true);
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, SnapshotRead::Shutdown));
        drop(write_guard);
    }
}
