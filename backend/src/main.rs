mod config;
mod config_store;
mod db;
mod error;
mod oui;
mod router;
mod state;

mod api;
mod poller;
mod routeros;
mod ws;

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::Config;
use crate::config_store::ConfigStore;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("info,routerview_backend=debug")
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration from environment
    let env_config = Config::from_env()?;

    // Open SQLite traffic history database
    let db_path = std::path::PathBuf::from(&env_config.db_path);
    let traffic_db = Arc::new(db::TrafficDb::open(&db_path)?);

    // Merge env config with DB overrides
    let merged_config = ConfigStore::load(&traffic_db, &env_config);
    let config = Arc::new(tokio::sync::RwLock::new(merged_config));

    {
        let cfg = config.read().await;
        tracing::info!(
            "RouterOS host: {}:{}, poll interval: {}s, theme: {}",
            cfg.routeros_host,
            cfg.routeros_port,
            cfg.poll_interval_secs,
            cfg.theme,
        );
    }

    // ── Probe targets: load from DB, convert to engine format ──
    let probe_rows = traffic_db.get_all_probe_targets();
    tracing::info!("Loaded {} probe targets from DB", probe_rows.len());
    let probe_targets: Vec<(String, String, String)> = probe_rows
        .iter()
        .map(|r| (r.name.clone(), r.host.clone(), r.category.clone()))
        .collect();
    let probe_targets_arc: Arc<tokio::sync::RwLock<Vec<(String, String, String)>>> =
        Arc::new(tokio::sync::RwLock::new(probe_targets));

    // Create broadcast channel for WebSocket fan-out
    let (broadcast_tx, _) = broadcast::channel::<Arc<ws::protocol::ServerMessage>>(128);

    // Shared snapshot cache — poll engine writes, new WS clients read
    let snapshot_cache: Arc<tokio::sync::RwLock<Option<Arc<ws::protocol::DashboardSnapshot>>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    // Build shared application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        broadcast_tx: broadcast_tx.clone(),
        connection_count: std::sync::atomic::AtomicUsize::new(0),
        last_snapshot: snapshot_cache.clone(),
        traffic_db: traffic_db.clone(),
        probe_targets: probe_targets_arc.clone(),
    });

    // Start the poll engine in a background task
    {
        let state = app_state.clone();
        tokio::spawn(async move {
            poller::engine::PollEngine::new(
                state.config.clone(),
                state.broadcast_tx.clone(),
                snapshot_cache,
                traffic_db,
                state.probe_targets.clone(),
            )
            .await
            .run()
            .await;
        });
    }

    // Build the router
    let app = router::create_router(app_state);

    // Bind and serve
    let server_port = {
        let cfg = config.read().await;
        cfg.server_port
    };
    let addr = format!("0.0.0.0:{}", server_port);
    tracing::info!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
