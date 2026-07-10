use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

#[derive(Default)]
struct SessionState {
    accepting: bool,
    active: usize,
}

/// Tracks upgraded WebSocket tasks that outlive Axum's HTTP connection future.
pub struct WsSessionTracker {
    state: Mutex<SessionState>,
    empty: Notify,
}

impl WsSessionTracker {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SessionState {
                accepting: true,
                active: 0,
            }),
            empty: Notify::new(),
        }
    }

    pub fn try_register(self: &Arc<Self>) -> Option<WsSessionGuard> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.accepting {
            return None;
        }
        state.active += 1;
        Some(WsSessionGuard {
            tracker: self.clone(),
        })
    }

    pub fn stop_accepting(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.accepting = false;
        if state.active == 0 {
            self.empty.notify_one();
        }
    }

    pub fn active(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active
    }

    pub async fn wait_for_empty(&self) {
        loop {
            let notified = self.empty.notified();
            if self.active() == 0 {
                return;
            }
            notified.await;
        }
    }
}

pub struct WsSessionGuard {
    tracker: Arc<WsSessionTracker>,
}

impl Drop for WsSessionGuard {
    fn drop(&mut self) {
        let mut state = self
            .tracker
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.active = state.active.saturating_sub(1);
        if state.active == 0 {
            self.tracker.empty.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn shutdown_waits_for_every_registered_session() {
        let tracker = Arc::new(WsSessionTracker::new());
        let first = tracker.try_register().unwrap();
        let second = tracker.try_register().unwrap();
        tracker.stop_accepting();

        let waiter = tokio::spawn({
            let tracker = tracker.clone();
            async move { tracker.wait_for_empty().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(first);
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(second);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_latches_and_empty_wait_does_not_miss_notification() {
        let tracker = Arc::new(WsSessionTracker::new());
        tracker.stop_accepting();

        assert!(tracker.try_register().is_none());
        tokio::time::timeout(Duration::from_secs(1), tracker.wait_for_empty())
            .await
            .unwrap();
    }
}
