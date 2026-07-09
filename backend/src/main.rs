mod config;
mod config_store;
mod db;
mod error;
mod oui;
mod router;
mod state;

mod api;
mod auth;
mod backends;
mod poller;
mod secrets;
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
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,routerview_backend=debug")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    if run_admin_cli()? {
        return Ok(());
    }

    // Load configuration from environment
    let env_config = Config::from_env()?;

    // Open SQLite traffic history database
    let db_path = std::path::PathBuf::from(&env_config.db_path);
    let traffic_db = Arc::new(db::TrafficDb::open(&db_path)?);

    let secret_cipher = Arc::new(secrets::SecretCipher::from_file(
        &env_config.master_key_file,
    )?);
    let instance_id = traffic_db.instance_id()?;

    // Merge env config with DB overrides
    let merged_config = ConfigStore::load(&traffic_db, &env_config, &secret_cipher)?;
    let config = Arc::new(tokio::sync::RwLock::new(merged_config));

    {
        let cfg = config.read().await;
        tracing::info!(
            "Router host: {}:{}, poll interval: {}s, theme: {}",
            cfg.router_host,
            cfg.router_port,
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
        ws_connections: Arc::new(ws::limits::WsConnectionLimiter::new(
            ws::limits::MAX_CONNECTIONS_GLOBAL,
            ws::limits::MAX_CONNECTIONS_PER_SESSION,
            ws::limits::MAX_CONNECTIONS_PER_SOURCE,
        )),
        last_snapshot: snapshot_cache.clone(),
        traffic_db: traffic_db.clone(),
        probe_targets: probe_targets_arc.clone(),
        secret_cipher,
        instance_id,
        public_origin: env_config.public_origin.clone(),
        auth_security: Arc::new(auth::AuthSecurity::new()?),
        setup_token_path: std::path::PathBuf::from(&env_config.setup_token_file),
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
    let app = router::create_router(app_state.clone());

    if auth::issue_setup_token(&app_state.traffic_db, &app_state.setup_token_path)? {
        let setup_addr = format!("127.0.0.1:{}", env_config.setup_port);
        let setup_listener = tokio::net::TcpListener::bind(&setup_addr).await?;
        let setup_app = router::create_setup_router(app_state.clone());
        tracing::warn!(
            "Initial setup required. Loopback setup token was written to {} (valid 15 minutes)",
            app_state.setup_token_path.display()
        );
        tracing::info!("Setup listener available at http://{setup_addr}/api/auth/setup");
        tokio::spawn(async move {
            if let Err(error) = axum::serve(setup_listener, setup_app).await {
                tracing::error!("setup listener failed: {error}");
            }
        });
        let setup_token_path = app_state.setup_token_path.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(auth::SETUP_TOKEN_TTL_SECS)).await;
            if let Err(error) = auth::remove_setup_token_file(&setup_token_path) {
                tracing::error!("failed to remove expired setup token file: {error}");
            }
        });
    }

    // Bind and serve
    let server_port = {
        let cfg = config.read().await;
        cfg.server_port
    };
    let addr = format!("0.0.0.0:{}", server_port);
    tracing::info!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn run_admin_cli() -> Result<bool, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("admin") {
        return Ok(false);
    }

    let command = args.get(2).map(String::as_str).unwrap_or("");
    if !matches!(command, "setup" | "reset-password") {
        return Err("usage: routerview-backend admin <setup|reset-password> [username]".into());
    }
    let username = args.get(3).map(String::as_str).unwrap_or("admin");
    let password = rpassword::prompt_password("Administrator password: ")?;
    let confirmation = rpassword::prompt_password("Confirm password: ")?;
    if password != confirmation {
        return Err("passwords do not match".into());
    }

    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "traffic.db".to_string());
    let database = db::TrafficDb::open(&std::path::PathBuf::from(db_path))?;
    auth::create_admin_from_cli(&database, username, &password, command == "reset-password")?;
    let setup_token_file = std::env::var("SETUP_TOKEN_FILE")
        .unwrap_or_else(|_| "/tmp/routerview-setup-token".to_string());
    if let Err(error) = auth::remove_setup_token_file(std::path::Path::new(&setup_token_file)) {
        tracing::error!(%error, "administrator updated but setup token cleanup failed");
    }
    println!("Administrator credentials updated successfully.");
    Ok(true)
}
