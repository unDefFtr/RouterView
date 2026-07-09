use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::backends::{RouterBackend, RouterConnectionConfig, RouterType};
use crate::config_store::ConfigStore;
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
///
/// Emits `routeros_*` keys for frontend backward compatibility alongside
/// new `router_type` and `router_*` fields.
pub async fn config_info(State(state): State<Arc<AppState>>) -> (StatusCode, Json<Value>) {
    let cfg = state.config.read().await;
    let password_hint = if cfg.router_password.is_empty() {
        ""
    } else {
        "••••••••"
    };

    let wizard_completed = state
        .traffic_db
        .get_all_config()
        .get("wizard_completed")
        .map(|v| v == "true")
        .unwrap_or(false);

    let body = json!({
        "router_type": cfg.router_type,
        // Backward-compat keys for frontend:
        "routeros_host": cfg.router_host,
        "routeros_port": cfg.router_port,
        "routeros_scheme": cfg.router_scheme,
        "routeros_username": cfg.router_username,
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
/// Supports both new `router_*` and legacy `routeros_*` key names.
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<HashMap<String, serde_json::Value>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let known_keys: &[&str] = &[
        "router_type",
        "router_host", "routeros_host",
        "router_port", "routeros_port",
        "router_scheme", "routeros_scheme",
        "router_username", "routeros_username",
        "router_password", "routeros_password",
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
    {
        let mut cfg = state.config.write().await;
        for key in &saved {
            // Build a ResolvedBody that normalizes both new and legacy keys
            let val = ResolvedBody { body: &body, key };

            match key.as_str() {
                "router_type" => {
                    if let Some(v) = val.as_str() {
                        cfg.router_type = match v.to_lowercase().as_str() {
                            "routeros" => RouterType::RouterOs,
                            _ => continue,
                        };
                    }
                }
                "router_host" | "routeros_host" => {
                    if let Some(v) = val.as_str() {
                        cfg.router_host = v.to_string();
                    }
                }
                "router_port" | "routeros_port" => {
                    if let Some(v) = val.as_u64() {
                        cfg.router_port = v as u16;
                    }
                }
                "router_scheme" | "routeros_scheme" => {
                    if let Some(v) = val.as_str() {
                        let s = v.to_lowercase();
                        if s == "http" || s == "https" {
                            cfg.router_scheme = s;
                        }
                    }
                }
                "accept_invalid_certs" => {
                    if let Some(v) = val.as_bool() {
                        cfg.accept_invalid_certs = v;
                    }
                }
                "router_username" | "routeros_username" => {
                    if let Some(v) = val.as_str() {
                        cfg.router_username = v.to_string();
                    }
                }
                "router_password" | "routeros_password" => {
                    if let Some(v) = val.as_str() {
                        cfg.router_password = v.to_string();
                    }
                }
                "poll_interval_secs" => {
                    if let Some(n) = val.as_u64() {
                        cfg.poll_interval_secs = n;
                    }
                }
                "probe_interval_secs" => {
                    if let Some(n) = val.as_u64() {
                        cfg.probe_interval_secs = n;
                    }
                }
                "db_raw_retention_days" => {
                    if let Some(n) = val.as_u64() {
                        cfg.db_raw_retention_days = n;
                    }
                }
                "db_total_retention_days" => {
                    if let Some(n) = val.as_u64() {
                        cfg.db_total_retention_days = n;
                    }
                }
                "latency_good_ms" => {
                    if let Some(n) = val.as_u64() {
                        cfg.latency_good_ms = n;
                    }
                }
                "latency_poor_ms" => {
                    if let Some(n) = val.as_u64() {
                        cfg.latency_poor_ms = n;
                    }
                }
                "theme" => {
                    if let Some(v) = val.as_str() {
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

/// Helper to extract values from the request body, trying the actual key first,
/// then falling back to a related legacy key when applicable.
struct ResolvedBody<'a> {
    body: &'a HashMap<String, serde_json::Value>,
    key: &'a str,
}

impl<'a> ResolvedBody<'a> {
    fn as_str(&self) -> Option<&str> {
        self.body.get(self.key).and_then(|v| v.as_str())
    }

    fn as_u64(&self) -> Option<u64> {
        self.body.get(self.key).and_then(|v| v.as_u64())
    }

    fn as_bool(&self) -> Option<bool> {
        self.body.get(self.key).and_then(|v| {
            if v.is_boolean() {
                v.as_bool()
            } else if let Some(s) = v.as_str() {
                Some(s == "true" || s == "1")
            } else {
                None
            }
        })
    }
}

/// POST /api/config/test-connection — test router connectivity.
///
/// Accepts optional connection params in the body (to test before saving).
/// If no params provided, uses the current in-memory config.
/// Supports both new `router_*` and legacy `routeros_*` key names.
pub async fn test_connection(
    State(state): State<Arc<AppState>>,
    Json(body): Json<HashMap<String, serde_json::Value>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let cfg = state.config.read().await;

    let get_str = |key: &str, legacy_key: &str, fallback: &str| -> String {
        body.get(key)
            .and_then(|v| v.as_str())
            .or_else(|| body.get(legacy_key).and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback.to_string())
    };

    let router_type = body
        .get("router_type")
        .and_then(|v| v.as_str())
        .map(|s| match s.to_lowercase().as_str() {
            "routeros" => RouterType::RouterOs,
            _ => RouterType::default(),
        })
        .unwrap_or(cfg.router_type);

    let conn_config = RouterConnectionConfig {
        router_type,
        host: get_str("router_host", "routeros_host", &cfg.router_host),
        port: body.get("router_port")
            .or_else(|| body.get("routeros_port"))
            .and_then(|v| v.as_u64())
            .unwrap_or(cfg.router_port as u64) as u16,
        scheme: get_str("router_scheme", "routeros_scheme", &cfg.router_scheme),
        username: get_str("router_username", "routeros_username", &cfg.router_username),
        password: get_str("router_password", "routeros_password", &cfg.router_password),
        accept_invalid_certs: body.get("accept_invalid_certs")
            .map(|v| v.as_bool().unwrap_or(false) || v.as_str() == Some("true"))
            .unwrap_or(cfg.accept_invalid_certs),
    };

    // Dispatch to the appropriate backend's test_connection
    let result = match conn_config.router_type {
        RouterType::RouterOs => {
            crate::backends::routeros::client::RouterOsClient::test_connection(&conn_config).await?
        }
    };

    let mut response = json!({
        "success": result.success,
    });

    if let Some(model) = &result.model {
        response["model"] = json!(model);
    }
    if let Some(version) = &result.version {
        response["version"] = json!(version);
    }
    if let Some(error) = &result.error {
        response["error"] = json!(error);
    }

    Ok((StatusCode::OK, Json(response)))
}
