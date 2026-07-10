use crate::auth::AuthSecurity;
use crate::config_store::MergedConfig;
use crate::db::TrafficDb;
use crate::poller::engine::PollEngineControl;
use crate::secrets::SecretCipher;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, watch, RwLock, Semaphore};

use crate::ws::limits::WsConnectionLimiter;
use crate::ws::protocol::{DashboardSnapshot, ServerMessage};
use crate::ws::tracker::WsSessionTracker;

/// Shared application state accessible by all handlers.
pub struct AppState {
    /// Runtime configuration (env defaults + DB overrides), mutable for hot-reload.
    pub config: Arc<RwLock<MergedConfig>>,
    /// Broadcast channel sender for WebSocket fan-out.
    pub broadcast_tx: broadcast::Sender<Arc<ServerMessage>>,
    /// Global, per-session and per-source WebSocket connection accounting.
    pub ws_connections: Arc<WsConnectionLimiter>,
    /// Tracks upgraded WebSocket tasks so process shutdown can await them.
    pub ws_sessions: Arc<WsSessionTracker>,
    /// Latest dashboard snapshot, updated on every successful poll.
    pub last_snapshot: Arc<RwLock<Option<Arc<DashboardSnapshot>>>>,
    /// SQLite traffic history database.
    pub traffic_db: Arc<TrafficDb>,
    /// Shared probe target list — hot-reloaded on API changes, read by PollEngine.
    pub probe_targets: Arc<RwLock<Vec<(String, String, String)>>>,
    /// Credential encryption context loaded from the deployment secret.
    pub secret_cipher: Arc<SecretCipher>,
    /// Stable installation identifier used as AEAD context.
    pub instance_id: String,
    /// Exact browser origin accepted for WebSocket and mutating requests.
    pub public_origin: String,
    /// Process-wide limits and timing defenses for password authentication.
    pub auth_security: Arc<AuthSecurity>,
    /// Location of the one-time setup token delivered through the filesystem.
    pub setup_token_path: PathBuf,
    /// Poller readiness and shutdown control owned by the process supervisor.
    pub poller_control: PollEngineControl,
    /// Process-wide shutdown notification used by upgraded WebSocket sessions.
    pub shutdown_tx: watch::Sender<bool>,
    /// Bounds expensive historical traffic queries independently of request count.
    pub traffic_query_limit: Arc<Semaphore>,
}
