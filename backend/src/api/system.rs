use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::config_store::{ConfigStore, MergedConfig};
use crate::error::AppError;
use crate::state::AppState;

/// Health check endpoint — returns server status.
pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<Value> {
    let connections = state.connection_count.load(std::sync::atomic::Ordering::Relaxed);

    Json(json!({
        "status": "ok",
        "uptime": "running",
        "ws_connections": connections,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// GET /api/config — returns current configuration including credentials
/// for the settings page. Password is returned as a masked placeholder if set.
pub async fn config_info(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    let cfg = state.config.read().await;
    // Show password only if configured; otherwise return empty so the UI
    // knows there's no password set yet.
    let password_hint = if cfg.routeros_password.is_empty() {
        ""
    } else {
        // Return a placeholder so the UI can show "已设置" but not the actual value.
        // The PUT endpoint accepts a new password to overwrite it.
        "••••••••"
    };

    // Check whether the welcome wizard has been completed.
    // This is stored as a key in the config table, separate from
    // the runtime MergedConfig struct.
    let wizard_completed = state
        .traffic_db
        .get_all_config()
        .get("wizard_completed")
        .map(|v| v == "true")
        .unwrap_or(false);

    let body = json!({
        "routeros_host": cfg.routeros_host,
        "routeros_port": cfg.routeros_port,
        "routeros_scheme": cfg.routeros_scheme,
        "routeros_username": cfg.routeros_username,
        "routeros_password": password_hint,
        "accept_invalid_certs": cfg.accept_invalid_certs,
        "poll_interval_secs": cfg.poll_interval_secs,
        "probe_interval_secs": cfg.probe_interval_secs,
        "db_raw_retention_days": cfg.db_raw_retention_days,
        "db_total_retention_days": cfg.db_total_retention_days,
        "latency_good_ms": cfg.latency_good_ms,
        "latency_poor_ms": cfg.latency_poor_ms,
        "theme": cfg.theme,
        "routeros_configured": cfg.has_connection_config(),
        "wizard_completed": wizard_completed,
    });
    (StatusCode::OK, Json(body))
}

/// PUT /api/config — partial config update.
///
/// Accepts a flat JSON object of key/value pairs. Keys matching known config
/// fields are written to the database. Returns two lists:
/// - `saved`: keys that were persisted
/// - `requires_restart`: keys that were saved but take effect on next restart
///
/// Hot-reloadable keys (applied immediately):
///   poll_interval_secs, probe_interval_secs, db_raw_retention_days,
///   db_total_retention_days, theme
///
/// Restart-required keys:
///   routeros_host, routeros_port, routeros_scheme, accept_invalid_certs,
///   routeros_username, routeros_password, server_port
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<HashMap<String, serde_json::Value>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let known_keys: &[&str] = &[
        "routeros_host",
        "routeros_port",
        "routeros_scheme",
        "routeros_username",
        "routeros_password",
        "accept_invalid_certs",
        "poll_interval_secs",
        "probe_interval_secs",
        "server_port",
        "db_raw_retention_days",
        "db_total_retention_days",
        "latency_good_ms",
        "latency_poor_ms",
        "theme",
        "wizard_completed",
    ];

    let requires_restart: &[&str] = &[
        "server_port",
    ];

    let mut saved: Vec<String> = Vec::new();
    let mut restart: Vec<String> = Vec::new();

    for (key, val) in &body {
        if !known_keys.contains(&key.as_str()) {
            continue;
        }
        let val_str = match val {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        ConfigStore::save(&state.traffic_db, key, &val_str);
        saved.push(key.clone());
        if requires_restart.contains(&key.as_str()) {
            restart.push(key.clone());
        }
    }

    // Hot-apply all saved keys to the in-memory config.
    // Connection params are applied immediately so the poll engine can
    // auto-reconnect on the next tick without requiring a full restart.
    {
        let mut cfg = state.config.write().await;
        for key in &saved {
            match key.as_str() {
                "routeros_host" => {
                    if let Some(v) = body.get(key).and_then(|v| v.as_str()) {
                        cfg.routeros_host = v.to_string();
                    }
                }
                "routeros_port" => {
                    if let Some(v) = body.get(key).and_then(|v| v.as_u64()) {
                        cfg.routeros_port = v as u16;
                    }
                }
                "routeros_scheme" => {
                    if let Some(v) = body.get(key).and_then(|v| v.as_str()) {
                        let s = v.to_lowercase();
                        if s == "http" || s == "https" {
                            cfg.routeros_scheme = s;
                        }
                    }
                }
                "accept_invalid_certs" => {
                    if let Some(v) = body.get(key) {
                        cfg.accept_invalid_certs = v.as_bool().unwrap_or(false)
                            || v.as_str() == Some("true");
                    }
                }
                "routeros_username" => {
                    if let Some(v) = body.get(key).and_then(|v| v.as_str()) {
                        cfg.routeros_username = v.to_string();
                    }
                }
                "routeros_password" => {
                    if let Some(v) = body.get(key).and_then(|v| v.as_str()) {
                        cfg.routeros_password = v.to_string();
                    }
                }
                "poll_interval_secs" => {
                    if let Some(n) = body.get(key).and_then(|v| v.as_u64()) {
                        cfg.poll_interval_secs = n;
                    }
                }
                "probe_interval_secs" => {
                    if let Some(n) = body.get(key).and_then(|v| v.as_u64()) {
                        cfg.probe_interval_secs = n;
                    }
                }
                "db_raw_retention_days" => {
                    if let Some(n) = body.get(key).and_then(|v| v.as_u64()) {
                        cfg.db_raw_retention_days = n;
                    }
                }
                "db_total_retention_days" => {
                    if let Some(n) = body.get(key).and_then(|v| v.as_u64()) {
                        cfg.db_total_retention_days = n;
                    }
                }
                "latency_good_ms" => {
                    if let Some(n) = body.get(key).and_then(|v| v.as_u64()) {
                        cfg.latency_good_ms = n;
                    }
                }
                "latency_poor_ms" => {
                    if let Some(n) = body.get(key).and_then(|v| v.as_u64()) {
                        cfg.latency_poor_ms = n;
                    }
                }
                "theme" => {
                    if let Some(v) = body.get(key).and_then(|v| v.as_str()) {
                        cfg.theme = v.to_string();
                    }
                }
                _ => {}
            }
        }
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "saved": saved,
            "requires_restart": restart,
        })),
    ))
}

/// POST /api/config/test-connection — test RouterOS connectivity.
///
/// Accepts optional connection params in the body (to test before saving).
/// If no params provided, uses the current in-memory config.
pub async fn test_connection(
    State(state): State<Arc<AppState>>,
    Json(body): Json<HashMap<String, serde_json::Value>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    // Build test config: start from current, overlay request values
    let cfg = state.config.read().await;

    let host = body
        .get("routeros_host")
        .and_then(|v| v.as_str())
        .unwrap_or(&cfg.routeros_host);
    let port = body
        .get("routeros_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(cfg.routeros_port as u64) as u16;
    let scheme = body
        .get("routeros_scheme")
        .and_then(|v| v.as_str())
        .unwrap_or(&cfg.routeros_scheme);
    let username = body
        .get("routeros_username")
        .and_then(|v| v.as_str())
        .unwrap_or(&cfg.routeros_username);
    let password = body
        .get("routeros_password")
        .and_then(|v| v.as_str())
        .unwrap_or(&cfg.routeros_password);
    let accept_invalid = body
        .get("accept_invalid_certs")
        .map(|v| v.as_bool().unwrap_or(false) || v.as_str() == Some("true"))
        .unwrap_or(cfg.accept_invalid_certs);

    let test_config = MergedConfig {
        routeros_host: host.to_string(),
        routeros_port: port,
        routeros_scheme: scheme.to_string(),
        routeros_username: username.to_string(),
        routeros_password: password.to_string(),
        accept_invalid_certs: accept_invalid,
        poll_interval_secs: cfg.poll_interval_secs,
        probe_interval_secs: cfg.probe_interval_secs,
        server_port: cfg.server_port,
        db_raw_retention_days: cfg.db_raw_retention_days,
        db_total_retention_days: cfg.db_total_retention_days,
        theme: cfg.theme.clone(),
        latency_good_ms: cfg.latency_good_ms,
        latency_poor_ms: cfg.latency_poor_ms,
    };

    let test_url = format!("{}/system/resource", test_config.routeros_base_url());

    let http_client = {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10));
        if test_config.is_tls() {
            builder = builder.danger_accept_invalid_certs(test_config.accept_invalid_certs);
        }
        builder.build().map_err(|e| AppError::Internal(e.to_string()))?
    };

    let auth_header = format!(
        "Basic {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{}:{}", test_config.routeros_username, test_config.routeros_password),
        )
    );

    match http_client
        .get(&test_url)
        .header(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&auth_header).map_err(|e| {
                AppError::Internal(format!("Invalid auth header: {e}"))
            })?,
        )
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            #[derive(Deserialize)]
            struct Resource {
                #[serde(default, rename = "board-name")]
                board_name: String,
                #[serde(default)]
                version: String,
            }
            let info = resp.json::<Vec<Resource>>().await.ok();
            let model = info.as_ref().and_then(|v| v.first()).map(|r| r.board_name.clone());
            let version = info.as_ref().and_then(|v| v.first()).map(|r| r.version.clone());

            Ok((
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "model": model,
                    "version": version,
                })),
            ))
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Ok((
                StatusCode::OK,
                Json(json!({
                    "success": false,
                    "error": format!("HTTP {status}: {body}"),
                })),
            ))
        }
        Err(e) => Ok((
            StatusCode::OK,
            Json(json!({
                "success": false,
                "error": e.to_string(),
            })),
        )),
    }
}
