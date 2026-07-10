mod config;
mod config_store;
mod db;
mod error;
mod key_cli;
mod oui;
mod router;
mod state;

mod api;
mod auth;
mod backends;
mod poller;
mod secrets;
mod ws;

use std::future::{Future, IntoFuture};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use tokio::sync::{broadcast, watch};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::Config;
use crate::config_store::ConfigStore;
use crate::state::AppState;

const WS_SESSION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

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

    if key_cli::run_if_requested()? {
        return Ok(());
    }
    if run_admin_cli()? {
        return Ok(());
    }
    if run_database_cli()? {
        return Ok(());
    }

    // Load configuration from environment
    let env_config = Config::from_env()?;

    // Open SQLite traffic history database
    let db_path = std::path::PathBuf::from(&env_config.db_path);
    let traffic_db = Arc::new(db::TrafficDb::open_for_bootstrap(&db_path)?);

    let secret_cipher = Arc::new(secrets::SecretCipher::from_file(
        &env_config.master_key_file,
    )?);
    let instance_id = traffic_db.instance_id()?;

    // Merge env config with DB overrides
    let merged_config = ConfigStore::load(&traffic_db, &env_config, &secret_cipher)?;
    traffic_db.finish_migrations()?;
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

    // Construct the poller before spawning it so process supervision owns its
    // control handle and can expose readiness immediately.
    let poll_engine = poller::engine::PollEngine::new(
        config.clone(),
        broadcast_tx.clone(),
        snapshot_cache.clone(),
        traffic_db.clone(),
        probe_targets_arc.clone(),
    )
    .await;
    let poller_control = poll_engine.control();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Build shared application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        broadcast_tx: broadcast_tx.clone(),
        ws_connections: Arc::new(ws::limits::WsConnectionLimiter::new(
            ws::limits::MAX_CONNECTIONS_GLOBAL,
            ws::limits::MAX_CONNECTIONS_PER_SESSION,
            ws::limits::MAX_CONNECTIONS_PER_SOURCE,
        )),
        ws_sessions: Arc::new(ws::tracker::WsSessionTracker::new()),
        last_snapshot: snapshot_cache.clone(),
        traffic_db: traffic_db.clone(),
        probe_targets: probe_targets_arc.clone(),
        secret_cipher,
        instance_id,
        public_origin: env_config.public_origin.clone(),
        auth_security: Arc::new(auth::AuthSecurity::new(
            env_config.trusted_proxy_cidrs.clone(),
        )?),
        setup_token_path: std::path::PathBuf::from(&env_config.setup_token_file),
        poller_control: poller_control.clone(),
        shutdown_tx: shutdown_tx.clone(),
        traffic_query_limit: Arc::new(tokio::sync::Semaphore::new(2)),
    });

    // Build the router
    let app = router::create_router(app_state.clone());

    let server_port = {
        let cfg = config.read().await;
        cfg.server_port
    };
    let addr = format!("0.0.0.0:{server_port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    let mut setup_server = None;
    if app_state.traffic_db.admin()?.is_none() {
        let setup_addr = format!("127.0.0.1:{}", env_config.setup_port);
        let setup_listener = tokio::net::TcpListener::bind(&setup_addr).await?;
        if auth::issue_setup_token(&app_state.traffic_db, &app_state.setup_token_path)? {
            let setup_app = router::create_setup_router(app_state.clone());
            tracing::warn!(
                "Initial setup required. Loopback setup token was written to {} (valid 15 minutes)",
                app_state.setup_token_path.display()
            );
            tracing::info!("Setup listener available at http://{setup_addr}/api/auth/setup");
            setup_server = Some((setup_listener, setup_app));
        }
    } else {
        auth::issue_setup_token(&app_state.traffic_db, &app_state.setup_token_path)?;
    }

    let poller_supervisor = poller_control.clone();
    let mut poller_handle = tokio::spawn(async move {
        match AssertUnwindSafe(poll_engine.run()).catch_unwind().await {
            Ok(()) if poller_supervisor.shutdown_requested() => Ok(()),
            Ok(()) => {
                let message = "poller task exited unexpectedly".to_string();
                poller_supervisor.report_unexpected_exit(message.clone());
                Err(message)
            }
            Err(_) => {
                let message = "poller task panicked outside an isolated tick".to_string();
                poller_supervisor.report_unexpected_exit(message.clone());
                Err(message)
            }
        }
    });

    let (setup_shutdown_tx, setup_shutdown_rx) = watch::channel(false);
    let mut setup_handle = setup_server.map(|(listener, setup_app)| {
        let process_shutdown = shutdown_tx.subscribe();
        let setup_shutdown = setup_shutdown_rx;
        let failure_shutdown = shutdown_tx.clone();
        tokio::spawn(async move {
            let server = axum::serve(listener, setup_app)
                .with_graceful_shutdown(wait_for_either_shutdown(process_shutdown, setup_shutdown))
                .into_future();
            supervise_setup_server(server, failure_shutdown).await
        })
    });

    let mut setup_token_handle = if setup_handle.is_some() {
        let setup_token_path = app_state.setup_token_path.clone();
        let process_shutdown = shutdown_tx.subscribe();
        let setup_shutdown = setup_shutdown_tx.clone();
        Some(tokio::spawn(async move {
            let expires_at =
                tokio::time::Instant::now() + Duration::from_secs(auth::SETUP_TOKEN_TTL_SECS);
            let mut process_shutdown = process_shutdown;
            loop {
                if !setup_token_path.exists() || *process_shutdown.borrow() {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep_until(expires_at) => break,
                    changed = process_shutdown.changed() => {
                        if changed.is_err() || *process_shutdown.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
            if let Err(error) = auth::remove_setup_token_file(&setup_token_path) {
                tracing::error!("failed to remove setup token file: {error}");
            }
            setup_shutdown.send_replace(true);
        }))
    } else {
        None
    };

    let signal_shutdown = shutdown_tx.clone();
    let signal_poller = poller_control.clone();
    let mut signal_handle = tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("Shutdown signal received");
        signal_poller.request_shutdown();
        signal_shutdown.send_replace(true);
    });

    tracing::info!("Server listening on http://{addr}");
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
    .into_future();
    tokio::pin!(server);

    let mut poller_finished = false;
    let mut signal_finished = false;
    let mut supervision_error = None;
    let server_result = tokio::select! {
        result = &mut server => result,
        result = &mut poller_handle => {
            poller_finished = true;
            match result {
                Ok(Ok(())) if poller_control.shutdown_requested() => {}
                Ok(Ok(())) => supervision_error = Some("poller task stopped unexpectedly".to_string()),
                Ok(Err(error)) => supervision_error = Some(error),
                Err(error) => {
                    poller_control.report_unexpected_exit(format!("poller supervisor failed: {error}"));
                    supervision_error = Some(format!("poller supervisor failed: {error}"));
                }
            }
            shutdown_tx.send_replace(true);
            poller_control.request_shutdown();
            match tokio::time::timeout(Duration::from_secs(30), server.as_mut()).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!("HTTP graceful shutdown exceeded 30 seconds");
                    Ok(())
                }
            }
        },
        result = &mut signal_handle => {
            signal_finished = true;
            if let Err(error) = result {
                supervision_error = Some(format!("shutdown signal task failed: {error}"));
            }
            shutdown_tx.send_replace(true);
            setup_shutdown_tx.send_replace(true);
            poller_control.request_shutdown();
            match tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(server.as_mut(), &mut poller_handle)
            }).await {
                Ok((server_result, poller_result)) => {
                    poller_finished = true;
                    match poller_result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            supervision_error.get_or_insert(error);
                        }
                        Err(error) => {
                            supervision_error
                                .get_or_insert_with(|| format!("poller join failed: {error}"));
                        }
                    }
                    server_result
                }
                Err(_) => {
                    supervision_error
                        .get_or_insert_with(|| "graceful shutdown exceeded 30 seconds".to_string());
                    let _ = abort_and_wait(&mut poller_handle).await;
                    poller_finished = true;
                    Ok(())
                }
            }
        }
    };

    shutdown_tx.send_replace(true);
    setup_shutdown_tx.send_replace(true);
    poller_control.request_shutdown();
    if let Err(active) =
        shutdown_websocket_sessions(&app_state.ws_sessions, WS_SESSION_SHUTDOWN_TIMEOUT).await
    {
        let timeout_secs = WS_SESSION_SHUTDOWN_TIMEOUT.as_secs();
        tracing::error!(active, "WebSocket sessions did not stop before timeout");
        supervision_error.get_or_insert_with(|| {
            format!(
                "websocket shutdown exceeded {timeout_secs} seconds \
                 ({active} sessions still active)"
            )
        });
    }
    if !signal_finished {
        let _ = abort_and_wait(&mut signal_handle).await;
    }

    if !poller_finished {
        match tokio::time::timeout(Duration::from_secs(10), &mut poller_handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                supervision_error.get_or_insert(error);
            }
            Ok(Err(error)) => {
                supervision_error.get_or_insert_with(|| format!("poller join failed: {error}"));
            }
            Err(_) => {
                tracing::error!("Poller did not stop within 10 seconds; aborting task");
                let _ = abort_and_wait(&mut poller_handle).await;
                supervision_error
                    .get_or_insert_with(|| "poller shutdown exceeded 10 seconds".to_string());
            }
        }
    }

    if let Some(handle) = setup_handle.as_mut() {
        match tokio::time::timeout(Duration::from_secs(5), &mut *handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                supervision_error.get_or_insert(error);
            }
            Ok(Err(error)) => {
                supervision_error
                    .get_or_insert_with(|| format!("setup listener join failed: {error}"));
            }
            Err(_) => {
                let _ = abort_and_wait(handle).await;
                supervision_error
                    .get_or_insert_with(|| "setup listener shutdown timed out".to_string());
            }
        }
    }
    if let Some(handle) = setup_token_handle.as_mut() {
        match tokio::time::timeout(Duration::from_secs(5), &mut *handle).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                supervision_error
                    .get_or_insert_with(|| format!("setup token task failed: {error}"));
            }
            Err(_) => {
                let _ = abort_and_wait(handle).await;
                supervision_error
                    .get_or_insert_with(|| "setup token cleanup timed out".to_string());
            }
        }
    }

    server_result?;
    if let Some(error) = supervision_error {
        return Err(std::io::Error::other(error).into());
    }

    Ok(())
}

async fn supervise_setup_server<F, E>(
    server: F,
    failure_shutdown: watch::Sender<bool>,
) -> Result<(), String>
where
    F: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    match AssertUnwindSafe(server).catch_unwind().await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let message = format!("setup listener failed: {error}");
            failure_shutdown.send_replace(true);
            Err(message)
        }
        Err(_) => {
            let message = "setup listener panicked".to_string();
            failure_shutdown.send_replace(true);
            Err(message)
        }
    }
}

async fn abort_and_wait<T>(
    handle: &mut tokio::task::JoinHandle<T>,
) -> Result<T, tokio::task::JoinError> {
    handle.abort();
    handle.await
}

async fn shutdown_websocket_sessions(
    tracker: &ws::tracker::WsSessionTracker,
    timeout: Duration,
) -> Result<(), usize> {
    tracker.stop_accepting();
    tokio::time::timeout(timeout, tracker.wait_for_empty())
        .await
        .map_err(|_| tracker.active())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

async fn wait_for_either_shutdown(
    process_shutdown: watch::Receiver<bool>,
    setup_shutdown: watch::Receiver<bool>,
) {
    tokio::select! {
        _ = wait_for_shutdown(process_shutdown) => {}
        _ = wait_for_shutdown(setup_shutdown) => {}
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(error) => {
                tracing::error!("failed to install Ctrl+C handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!("failed to install SIGTERM handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
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

    let env_config = Config::from_env()?;
    let db_path = std::path::PathBuf::from(&env_config.db_path);
    let database = db::TrafficDb::open_for_bootstrap(&db_path)?;
    let secret_cipher = secrets::SecretCipher::from_file(&env_config.master_key_file)?;
    ConfigStore::load(&database, &env_config, &secret_cipher)?;
    database.finish_migrations()?;
    auth::create_admin_from_cli(&database, username, &password, command == "reset-password")?;
    let setup_token_file = std::env::var("SETUP_TOKEN_FILE")
        .unwrap_or_else(|_| "/tmp/routerview-setup-token".to_string());
    if let Err(error) = auth::remove_setup_token_file(std::path::Path::new(&setup_token_file)) {
        tracing::error!(%error, "administrator updated but setup token cleanup failed");
    }
    println!("Administrator credentials updated successfully.");
    Ok(true)
}

fn run_database_cli() -> Result<bool, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("db") {
        return Ok(false);
    }
    let command = args.get(2).map(String::as_str).unwrap_or("");
    let parsed = parse_database_cli_options(&args[3..])?;
    let database_path = parsed
        .database_path
        .unwrap_or_else(|| std::path::PathBuf::from(env_or("DB_PATH", "traffic.db")));

    match command {
        "check" => {
            require_positionals(command, &parsed.positionals, 0)?;
            let report = db::check_database(&database_path)?;
            println!(
                "database={} user_version={} integrity={} foreign_key_violations={}",
                report.path.display(),
                report.user_version,
                report.integrity,
                report.foreign_key_violations
            );
            for (table, count) in report.table_counts {
                println!("table={table} rows={count}");
            }
        }
        "migrate" => {
            require_positionals(command, &parsed.positionals, 0)?;
            let report = db::migrate_database(&database_path, parsed.backup_dir.as_deref())?;
            println!(
                "database={} migrated_from={} migrated_to={}",
                report.path.display(),
                report.from_version,
                report.to_version
            );
            if let Some(backup) = report.backup {
                print_backup(&backup);
            }
        }
        "backup" => {
            require_positionals(command, &parsed.positionals, 1)?;
            let backup = db::backup_database(
                &database_path,
                &std::path::PathBuf::from(&parsed.positionals[0]),
            )?;
            print_backup(&backup);
        }
        "restore" => {
            require_positionals(command, &parsed.positionals, 1)?;
            let report = db::restore_database(
                &database_path,
                &std::path::PathBuf::from(&parsed.positionals[0]),
                parsed.backup_dir.as_deref(),
            )?;
            println!(
                "database={} restored_from={}",
                report.path.display(),
                report.restored_from.display()
            );
            if let Some(backup) = &report.recovery_backup {
                println!("recovery_backup={}", backup.path.display());
                println!("recovery_backup_sha256={}", backup.sha256);
            }
            if let Some(quarantine) = &report.quarantine {
                println!("quarantine={}", quarantine.directory.display());
                println!("quarantine_manifest={}", quarantine.manifest_path.display());
                for (name, checksum) in &quarantine.file_checksums {
                    println!("quarantine_file={name} sha256={checksum}");
                }
            }
        }
        "export-legacy" => {
            require_positionals(command, &parsed.positionals, 1)?;
            let export = db::export_legacy(
                &database_path,
                &std::path::PathBuf::from(&parsed.positionals[0]),
            )?;
            println!("legacy_export={}", export.path.display());
            println!("legacy_export_sha256={}", export.sha256);
            println!("manifest={}", export.manifest_path.display());
        }
        _ => {
            return Err(
                "usage: routerview-backend db <check|migrate|backup|restore|export-legacy> \
                 [FILE] [--path DATABASE] [--backup-dir DIRECTORY]"
                    .into(),
            )
        }
    }
    Ok(true)
}

#[derive(Default)]
struct DatabaseCliOptions {
    database_path: Option<std::path::PathBuf>,
    backup_dir: Option<std::path::PathBuf>,
    positionals: Vec<String>,
}

fn parse_database_cli_options(
    args: &[String],
) -> Result<DatabaseCliOptions, Box<dyn std::error::Error>> {
    let mut parsed = DatabaseCliOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--path" => {
                index += 1;
                let value = args.get(index).ok_or("--path requires a value")?;
                if parsed.database_path.replace(value.into()).is_some() {
                    return Err("--path may only be specified once".into());
                }
            }
            "--backup-dir" => {
                index += 1;
                let value = args.get(index).ok_or("--backup-dir requires a value")?;
                if parsed.backup_dir.replace(value.into()).is_some() {
                    return Err("--backup-dir may only be specified once".into());
                }
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown database option: {value}").into());
            }
            value => parsed.positionals.push(value.to_string()),
        }
        index += 1;
    }
    Ok(parsed)
}

fn require_positionals(
    command: &str,
    positionals: &[String],
    expected: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if positionals.len() != expected {
        return Err(format!(
            "db {command} expects {expected} file argument(s), received {}",
            positionals.len()
        )
        .into());
    }
    Ok(())
}

fn print_backup(backup: &db::BackupArtifact) {
    println!("backup={}", backup.path.display());
    println!("sha256={}", backup.sha256);
    println!("manifest={}", backup.manifest_path.display());
    println!("user_version={}", backup.user_version);
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn setup_server_failure_and_panic_request_process_shutdown() {
        let (failure_tx, failure_rx) = watch::channel(false);
        let error = supervise_setup_server(
            async { Err(std::io::Error::other("listener error")) },
            failure_tx,
        )
        .await
        .unwrap_err();
        assert!(error.contains("listener error"));
        assert!(*failure_rx.borrow());

        let (panic_tx, panic_rx) = watch::channel(false);
        let error = supervise_setup_server(
            async {
                panic!("listener panic");
                #[allow(unreachable_code)]
                Ok::<(), std::io::Error>(())
            },
            panic_tx,
        )
        .await
        .unwrap_err();
        assert_eq!(error, "setup listener panicked");
        assert!(*panic_rx.borrow());
    }

    #[tokio::test]
    async fn process_and_setup_shutdown_watchers_return_promptly() {
        let (already_tx, already_rx) = watch::channel(false);
        already_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), wait_for_shutdown(already_rx))
            .await
            .unwrap();

        let (_process_tx, process_rx) = watch::channel(false);
        let (setup_tx, setup_rx) = watch::channel(false);
        let waiter = tokio::spawn(wait_for_either_shutdown(process_rx, setup_rx));
        setup_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn forced_abort_waits_for_task_cleanup() {
        struct CleanupSignal(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for CleanupSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
        let mut handle = tokio::spawn(async move {
            let _cleanup = CleanupSignal(Some(cleanup_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        let error = abort_and_wait(&mut handle).await.unwrap_err();
        assert!(error.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), cleanup_rx)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn supervisor_waits_for_upgraded_websocket_tasks() {
        let tracker = Arc::new(ws::tracker::WsSessionTracker::new());
        let session = tracker.try_register().unwrap();
        tracker.stop_accepting();
        let waiter = tokio::spawn({
            let tracker = tracker.clone();
            async move { shutdown_websocket_sessions(&tracker, Duration::from_secs(1)).await }
        });

        assert!(!waiter.is_finished());
        assert!(tracker.try_register().is_none());
        drop(session);
        assert_eq!(waiter.await.unwrap(), Ok(()));
    }
}
