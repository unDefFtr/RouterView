use crate::config_store::MergedConfig;
use crate::db::TrafficDb;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::ws::protocol::{DashboardSnapshot, ServerMessage};

/// Shared application state accessible by all handlers.
pub struct AppState {
    /// Runtime configuration (env defaults + DB overrides), mutable for hot-reload.
    pub config: Arc<RwLock<MergedConfig>>,
    /// Broadcast channel sender for WebSocket fan-out.
    pub broadcast_tx: broadcast::Sender<Arc<ServerMessage>>,
    /// Number of currently connected WebSocket clients.
    pub connection_count: AtomicUsize,
    /// Latest dashboard snapshot, updated on every successful poll.
    pub last_snapshot: Arc<RwLock<Option<Arc<DashboardSnapshot>>>>,
    /// SQLite traffic history database.
    pub traffic_db: Arc<TrafficDb>,
    /// Shared probe target list — hot-reloaded on API changes, read by PollEngine.
    pub probe_targets: Arc<RwLock<Vec<(String, String, String)>>>,
}
