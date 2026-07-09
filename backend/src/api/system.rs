use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::backends::{RouterBackend, RouterConnectionConfig, RouterType};
use crate::error::{ApiJson, AppError};
use crate::state::AppState;

pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn config_info(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let cfg = state.config.read().await;
    let values = state.traffic_db.get_all_config()?;
    let wizard_completed = values
        .get("wizard_completed")
        .is_some_and(|value| value == "true");
    let password_set = cfg.has_connection_config();
    let password_hint = password_set.then_some("********").unwrap_or("");
    Ok((
        StatusCode::OK,
        Json(json!({
            "router_type": cfg.router_type,
            "revision": cfg.revision,
            "router_host": cfg.router_host,
            "router_port": cfg.router_port,
            "router_scheme": cfg.router_scheme,
            "router_username": cfg.router_username,
            "password_set": password_set,
            "router_configured": password_set,
            "routeros_host": cfg.router_host,
            "routeros_port": cfg.router_port,
            "routeros_scheme": cfg.router_scheme,
            "routeros_username": cfg.router_username,
            "routeros_password": password_hint,
            "routeros_configured": password_set,
            "accept_invalid_certs": cfg.accept_invalid_certs,
            "poll_interval_secs": cfg.poll_interval_secs,
            "probe_interval_secs": cfg.probe_interval_secs,
            "db_raw_retention_days": cfg.db_raw_retention_days,
            "db_total_retention_days": cfg.db_total_retention_days,
            "latency_good_ms": cfg.latency_good_ms,
            "latency_poor_ms": cfg.latency_poor_ms,
            "theme": cfg.theme,
            "wizard_completed": wizard_completed,
        })),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PasswordMode {
    Keep,
    Replace,
    Clear,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BoolValue {
    Bool(bool),
    Text(String),
}

impl BoolValue {
    fn get(&self, field: &str) -> Result<bool, AppError> {
        match self {
            Self::Bool(value) => Ok(*value),
            Self::Text(value) if value == "true" || value == "1" => Ok(true),
            Self::Text(value) if value == "false" || value == "0" => Ok(false),
            _ => Err(AppError::InvalidData(format!("{field} must be a boolean"))),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigUpdateRequest {
    expected_revision: Option<u64>,
    router_type: Option<RouterType>,
    #[serde(alias = "routeros_host")]
    router_host: Option<String>,
    #[serde(alias = "routeros_port")]
    router_port: Option<u16>,
    #[serde(alias = "routeros_scheme")]
    router_scheme: Option<String>,
    #[serde(alias = "routeros_username")]
    router_username: Option<String>,
    #[serde(alias = "routeros_password")]
    router_password: Option<String>,
    password_mode: Option<PasswordMode>,
    accept_invalid_certs: Option<BoolValue>,
    poll_interval_secs: Option<u64>,
    probe_interval_secs: Option<u64>,
    db_raw_retention_days: Option<u64>,
    db_total_retention_days: Option<u64>,
    latency_good_ms: Option<u64>,
    latency_poor_ms: Option<u64>,
    theme: Option<String>,
    wizard_completed: Option<BoolValue>,
}

pub async fn update_config(
    State(state): State<Arc<AppState>>,
    ApiJson(body): ApiJson<ConfigUpdateRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let current = state.config.read().await.clone();
    let expected_revision = body.expected_revision.ok_or_else(|| {
        AppError::InvalidData("expected_revision is required for configuration updates".into())
    })?;
    if expected_revision != current.revision {
        return Err(AppError::Conflict(format!(
            "configuration revision changed (expected {expected_revision}, current {})",
            current.revision
        )));
    }
    let mut next = current.clone();
    let mut saved = Vec::new();

    if let Some(value) = body.router_type {
        next.router_type = value;
        saved.push("router_type");
    }
    if let Some(value) = body.router_host.as_deref() {
        next.router_host = value.trim().to_string();
        saved.push("router_host");
    }
    if let Some(value) = body.router_port {
        next.router_port = value;
        saved.push("router_port");
    }
    if let Some(value) = body.router_scheme.as_deref() {
        next.router_scheme = value.to_ascii_lowercase();
        saved.push("router_scheme");
    }
    if let Some(value) = body.router_username.as_deref() {
        next.router_username = value.trim().to_string();
        saved.push("router_username");
    }
    if let Some(value) = body.accept_invalid_certs.as_ref() {
        next.accept_invalid_certs = value.get("accept_invalid_certs")?;
        saved.push("accept_invalid_certs");
    }
    if let Some(value) = body.poll_interval_secs {
        next.poll_interval_secs = value;
        saved.push("poll_interval_secs");
    }
    if let Some(value) = body.probe_interval_secs {
        next.probe_interval_secs = value;
        saved.push("probe_interval_secs");
    }
    if let Some(value) = body.db_raw_retention_days {
        next.db_raw_retention_days = value;
        saved.push("db_raw_retention_days");
    }
    if let Some(value) = body.db_total_retention_days {
        next.db_total_retention_days = value;
        saved.push("db_total_retention_days");
    }
    if let Some(value) = body.latency_good_ms {
        next.latency_good_ms = value;
        saved.push("latency_good_ms");
    }
    if let Some(value) = body.latency_poor_ms {
        next.latency_poor_ms = value;
        saved.push("latency_poor_ms");
    }
    if let Some(value) = body.theme.as_deref() {
        next.theme = value.to_ascii_lowercase();
        saved.push("theme");
    }

    let connection_changed = next.router_type != current.router_type
        || next.router_host != current.router_host
        || next.router_port != current.router_port
        || next.router_scheme != current.router_scheme
        || next.router_username != current.router_username
        || next.accept_invalid_certs != current.accept_invalid_certs;
    let password_mode = body.password_mode.unwrap_or_else(|| {
        if body
            .router_password
            .as_deref()
            .is_some_and(|value| !value.is_empty() && value != "********")
        {
            PasswordMode::Replace
        } else {
            PasswordMode::Keep
        }
    });

    let mut encrypted_password = None;
    let mut delete_password = false;
    match password_mode {
        PasswordMode::Keep => {
            if connection_changed {
                return Err(AppError::InvalidData(
                    "changing router connection fields requires password_mode=replace and a complete credential"
                        .into(),
                ));
            }
        }
        PasswordMode::Replace => {
            let password = body.router_password.as_deref().ok_or_else(|| {
                AppError::InvalidData(
                    "router_password is required when password_mode=replace".into(),
                )
            })?;
            if password.is_empty() || password.len() > 1024 || password == "********" {
                return Err(AppError::InvalidData(
                    "router_password must contain 1 to 1024 bytes".into(),
                ));
            }
            next.router_password = password.to_string();
            encrypted_password = Some(
                state
                    .secret_cipher
                    .encrypt(&state.instance_id, "router_password", password.as_bytes())
                    .map_err(|error| AppError::Secret(error.to_string()))?,
            );
            saved.push("router_password");
        }
        PasswordMode::Clear => {
            next.router_password.clear();
            delete_password = true;
            saved.push("router_password");
        }
    }

    next.validate()?;
    let mut persisted = vec![
        ("router_type".to_string(), "routeros".to_string()),
        ("router_host".to_string(), next.router_host.clone()),
        ("router_port".to_string(), next.router_port.to_string()),
        ("router_scheme".to_string(), next.router_scheme.clone()),
        ("router_username".to_string(), next.router_username.clone()),
        (
            "accept_invalid_certs".to_string(),
            next.accept_invalid_certs.to_string(),
        ),
        (
            "poll_interval_secs".to_string(),
            next.poll_interval_secs.to_string(),
        ),
        (
            "probe_interval_secs".to_string(),
            next.probe_interval_secs.to_string(),
        ),
        (
            "db_raw_retention_days".to_string(),
            next.db_raw_retention_days.to_string(),
        ),
        (
            "db_total_retention_days".to_string(),
            next.db_total_retention_days.to_string(),
        ),
        (
            "latency_good_ms".to_string(),
            next.latency_good_ms.to_string(),
        ),
        (
            "latency_poor_ms".to_string(),
            next.latency_poor_ms.to_string(),
        ),
        ("theme".to_string(), next.theme.clone()),
    ];
    if let Some(value) = body.wizard_completed.as_ref() {
        persisted.push((
            "wizard_completed".to_string(),
            value.get("wizard_completed")?.to_string(),
        ));
        saved.push("wizard_completed");
    }

    let saved_transaction = state.traffic_db.save_config_transaction(
        &persisted,
        encrypted_password
            .as_ref()
            .map(|encrypted| ("router_password", encrypted)),
        delete_password.then_some("router_password"),
        Some(expected_revision),
    )?;
    if !saved_transaction {
        return Err(AppError::Conflict(
            "configuration was modified by another request".into(),
        ));
    }
    next.revision = expected_revision.saturating_add(1);
    let revision = next.revision;
    *state.config.write().await = next;

    saved.sort_unstable();
    saved.dedup();
    Ok((
        StatusCode::OK,
        Json(json!({
            "saved": saved,
            "requires_restart": [],
            "revision": revision,
        })),
    ))
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDraft {
    router_type: Option<RouterType>,
    #[serde(alias = "routeros_host")]
    router_host: Option<String>,
    #[serde(alias = "routeros_port")]
    router_port: Option<u16>,
    #[serde(alias = "routeros_scheme")]
    router_scheme: Option<String>,
    #[serde(alias = "routeros_username")]
    router_username: Option<String>,
    #[serde(alias = "routeros_password")]
    router_password: Option<String>,
    accept_invalid_certs: Option<bool>,
}

impl ConnectionDraft {
    fn is_empty(&self) -> bool {
        self.router_type.is_none()
            && self.router_host.is_none()
            && self.router_port.is_none()
            && self.router_scheme.is_none()
            && self.router_username.is_none()
            && self.router_password.is_none()
            && self.accept_invalid_certs.is_none()
    }
}

pub async fn test_connection(
    State(state): State<Arc<AppState>>,
    ApiJson(body): ApiJson<ConnectionDraft>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let cfg = state.config.read().await;
    let conn_config = if body.is_empty() {
        RouterConnectionConfig {
            router_type: cfg.router_type,
            host: cfg.router_host.clone(),
            port: cfg.router_port,
            scheme: cfg.router_scheme.clone(),
            username: cfg.router_username.clone(),
            password: cfg.router_password.clone(),
            accept_invalid_certs: cfg.accept_invalid_certs,
            management_cidrs: cfg.router_management_cidrs.clone(),
            allow_insecure_http: cfg.allow_insecure_router_http,
        }
    } else {
        let required = |value: Option<String>, field: &str| {
            value
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    AppError::InvalidData(format!(
                        "{field} is required when testing a connection draft"
                    ))
                })
        };
        RouterConnectionConfig {
            router_type: body.router_type.unwrap_or(RouterType::RouterOs),
            host: required(body.router_host, "router_host")?,
            port: body.router_port.ok_or_else(|| {
                AppError::InvalidData(
                    "router_port is required when testing a connection draft".into(),
                )
            })?,
            scheme: required(body.router_scheme, "router_scheme")?.to_ascii_lowercase(),
            username: required(body.router_username, "router_username")?,
            password: required(body.router_password, "router_password")?,
            accept_invalid_certs: body.accept_invalid_certs.unwrap_or(false),
            management_cidrs: cfg.router_management_cidrs.clone(),
            allow_insecure_http: cfg.allow_insecure_router_http,
        }
    };
    drop(cfg);

    let result = match conn_config.router_type {
        RouterType::RouterOs => {
            crate::backends::routeros::client::RouterOsClient::test_connection(&conn_config).await?
        }
    };
    Ok((StatusCode::OK, Json(serde_json::to_value(result)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_connection_fields_deserialize_into_canonical_draft() {
        let draft: ConnectionDraft = serde_json::from_value(json!({
            "routeros_host": "192.168.88.1",
            "routeros_port": 443,
            "routeros_scheme": "https",
            "routeros_username": "admin",
            "routeros_password": "secret"
        }))
        .unwrap();
        assert_eq!(draft.router_host.as_deref(), Some("192.168.88.1"));
        assert_eq!(draft.router_port, Some(443));
    }

    #[test]
    fn rejects_unknown_config_keys() {
        let result = serde_json::from_value::<ConfigUpdateRequest>(json!({
            "server_port": 1
        }));
        assert!(result.is_err());
    }
}
