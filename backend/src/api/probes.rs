use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::db::ProbeTargetRow;
use crate::error::{ApiJson, AppError};
use crate::poller::engine::MAX_PROBE_TARGETS;
use crate::state::AppState;

const MAX_PROBE_NAME_CHARS: usize = 64;
const MAX_PROBE_HOST_BYTES: usize = 253;
const PROBE_CATEGORIES: &[&str] = &["dns", "cloud", "cdn", "repo", "isp", "custom"];

/// Serialisable probe target for the API (mirrors ProbeTargetRow but
/// with optional id for create-friendly payloads).
#[derive(serde::Deserialize)]
pub(crate) struct ProbeTargetInput {
    name: String,
    host: String,
    category: String,
}

/// GET /api/probes — list all probe targets.
pub async fn list_probes(State(state): State<Arc<AppState>>) -> Result<Json<Value>, AppError> {
    let rows = state.traffic_db.get_all_probe_targets()?;
    Ok(probe_targets_json(&rows))
}

/// PUT /api/probes — replace all probe targets.
pub async fn update_probes(
    State(state): State<Arc<AppState>>,
    ApiJson(body): ApiJson<Vec<ProbeTargetInput>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let rows = validate_probe_targets(body)?;
    // Serialize durable commits and live reloads so concurrent requests cannot apply out of order.
    let mut live_targets = state.probe_targets.write().await;
    let stored = state.traffic_db.replace_all_probe_targets(&rows)?;
    *live_targets = runtime_probe_targets(&stored);
    drop(live_targets);
    Ok((StatusCode::OK, probe_targets_json(&stored)))
}

/// POST /api/probes/reset — reset probe targets to defaults.
pub async fn reset_probes(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let mut live_targets = state.probe_targets.write().await;
    let stored = state.traffic_db.reset_probe_targets()?;
    *live_targets = runtime_probe_targets(&stored);
    drop(live_targets);
    Ok((StatusCode::OK, probe_targets_json(&stored)))
}

fn validate_probe_targets(targets: Vec<ProbeTargetInput>) -> Result<Vec<ProbeTargetRow>, AppError> {
    if targets.is_empty() {
        return Err(AppError::InvalidData(
            "at least one probe target is required".into(),
        ));
    }
    if targets.len() > MAX_PROBE_TARGETS {
        return Err(AppError::InvalidData(format!(
            "probe targets cannot exceed {MAX_PROBE_TARGETS} entries"
        )));
    }

    let mut hosts = HashSet::with_capacity(targets.len());
    targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| {
            let name = target.name.trim();
            if name.is_empty() || name.chars().count() > MAX_PROBE_NAME_CHARS {
                return Err(AppError::InvalidData(format!(
                    "probe target {} name must contain 1..={MAX_PROBE_NAME_CHARS} characters",
                    index + 1
                )));
            }

            let host = normalize_probe_host(target.host.trim()).ok_or_else(|| {
                AppError::InvalidData(format!(
                    "probe target {} host must be an IP address or valid DNS hostname up to {MAX_PROBE_HOST_BYTES} bytes",
                    index + 1
                ))
            })?;
            if !hosts.insert(host.clone()) {
                return Err(AppError::InvalidData(format!(
                    "probe target {} duplicates host '{host}'",
                    index + 1
                )));
            }

            let category = target.category.trim();
            if !PROBE_CATEGORIES.contains(&category) {
                return Err(AppError::InvalidData(format!(
                    "probe target {} category is not supported",
                    index + 1
                )));
            }

            Ok(ProbeTargetRow {
                id: 0,
                name: name.to_string(),
                host,
                category: category.to_string(),
                sort_order: index as i64,
            })
        })
        .collect()
}

fn normalize_probe_host(host: &str) -> Option<String> {
    if host.is_empty() || host.len() > MAX_PROBE_HOST_BYTES {
        return None;
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Some(address.to_string());
    }

    let hostname = host.strip_suffix('.').unwrap_or(host);
    if hostname.is_empty()
        || !hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return None;
    }
    Some(hostname.to_ascii_lowercase())
}

fn probe_targets_json(rows: &[ProbeTargetRow]) -> Json<Value> {
    Json(json!({ "targets": rows }))
}

fn runtime_probe_targets(rows: &[ProbeTargetRow]) -> Vec<(String, String, String)> {
    rows.iter()
        .map(|r| (r.name.clone(), r.host.clone(), r.category.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str, host: &str, category: &str) -> ProbeTargetInput {
        ProbeTargetInput {
            name: name.to_string(),
            host: host.to_string(),
            category: category.to_string(),
        }
    }

    #[test]
    fn validates_and_normalizes_probe_targets() {
        let rows = validate_probe_targets(vec![
            target(" DNS ", " EXAMPLE.COM. ", "dns"),
            target("Gateway", "2001:0db8::1", "isp"),
        ])
        .unwrap();
        assert_eq!(rows[0].name, "DNS");
        assert_eq!(rows[0].host, "example.com");
        assert_eq!(rows[0].sort_order, 0);
        assert_eq!(rows[1].host, "2001:db8::1");
        assert_eq!(rows[1].sort_order, 1);
    }

    #[test]
    fn rejects_unbounded_or_malformed_probe_targets_without_filtering() {
        assert!(validate_probe_targets(Vec::new()).is_err());
        assert!(validate_probe_targets(
            (0..=MAX_PROBE_TARGETS)
                .map(|index| target(
                    &format!("Target {index}"),
                    &format!("host-{index}"),
                    "custom"
                ))
                .collect()
        )
        .is_err());
        assert!(validate_probe_targets(vec![
            target("valid", "1.1.1.1", "dns"),
            target(" ", "8.8.8.8", "dns"),
        ])
        .is_err());
        assert!(
            validate_probe_targets(vec![target("Target", "https://example.com", "dns")]).is_err()
        );
        assert!(validate_probe_targets(vec![target("Target", "example.com", "unknown")]).is_err());
        assert!(validate_probe_targets(vec![
            target("First", "EXAMPLE.com.", "dns"),
            target("Second", "example.COM", "cloud"),
        ])
        .is_err());
        assert!(validate_probe_targets(vec![target(
            &"x".repeat(MAX_PROBE_NAME_CHARS + 1),
            "example.com",
            "dns",
        )])
        .is_err());
    }
}
