use std::collections::HashMap;

use tracing::info;

use crate::backends::RouterType;
use crate::config::Config;
use crate::db::TrafficDb;

/// Runtime configuration merged from environment variables (defaults)
/// and database overrides. DB values take precedence over env values.
#[derive(Clone, Debug)]
pub struct MergedConfig {
    // Router type
    pub router_type: RouterType,

    // Router connection
    pub router_host: String,
    pub router_port: u16,
    pub router_scheme: String,
    pub router_username: String,
    pub router_password: String,
    pub accept_invalid_certs: bool,

    // Polling
    pub poll_interval_secs: u64,
    pub probe_interval_secs: u64,

    // Server
    pub server_port: u16,

    // DB retention
    pub db_raw_retention_days: u64,
    pub db_total_retention_days: u64,

    // UI
    pub theme: String,

    // Latency thresholds
    pub latency_good_ms: u64,
    pub latency_poor_ms: u64,
}

impl MergedConfig {
    /// Build from env Config (defaults) and optional DB overrides.
    pub fn from_env_and_db(env: &Config, db_overrides: &HashMap<String, String>) -> Self {
        let get = |key: &str| -> Option<&str> { db_overrides.get(key).map(|s| s.as_str()) };

        let router_type = get("router_type")
            .and_then(|s| match s.to_lowercase().as_str() {
                "routeros" => Some(RouterType::RouterOs),
                _ => None,
            })
            .unwrap_or(env.router_type);

        Self {
            router_type,

            // Accept both new and legacy DB key names for router fields
            router_host: get("router_host")
                .or_else(|| get("routeros_host"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| env.router_host.clone()),

            router_port: get("router_port")
                .or_else(|| get("routeros_port"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.router_port),

            router_scheme: get("router_scheme")
                .or_else(|| get("routeros_scheme"))
                .map(|s| s.to_lowercase())
                .filter(|s| s == "http" || s == "https")
                .unwrap_or_else(|| env.router_scheme.clone()),

            router_username: get("router_username")
                .or_else(|| get("routeros_username"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| env.router_username.clone()),

            router_password: get("router_password")
                .or_else(|| get("routeros_password"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| env.router_password.clone()),

            accept_invalid_certs: get("accept_invalid_certs")
                .map(|s| s == "true" || s == "1")
                .unwrap_or(env.accept_invalid_certs),

            poll_interval_secs: get("poll_interval_secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.poll_interval_secs),

            probe_interval_secs: get("probe_interval_secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.probe_interval_secs),

            server_port: get("server_port")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.server_port),

            db_raw_retention_days: get("db_raw_retention_days")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.db_raw_retention_days),

            db_total_retention_days: get("db_total_retention_days")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.db_total_retention_days),

            theme: get("theme")
                .map(|s| s.to_string())
                .unwrap_or_else(|| "system".to_string()),

            latency_good_ms: get("latency_good_ms")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.latency_good_ms),

            latency_poor_ms: get("latency_poor_ms")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.latency_poor_ms),
        }
    }

    /// Whether the connection configuration has been filled in (credentials exist).
    pub fn has_connection_config(&self) -> bool {
        !self.router_password.is_empty()
    }
}

/// Persists runtime config overrides in the SQLite `config` table.
pub struct ConfigStore;

impl ConfigStore {
    /// Load merged config: env defaults + DB overrides.
    pub fn load(db: &TrafficDb, env: &Config) -> MergedConfig {
        let overrides = db.get_all_config();
        info!("ConfigStore: loaded {} overrides from DB", overrides.len());
        MergedConfig::from_env_and_db(env, &overrides)
    }

    /// Save a single config key/value to the database.
    pub fn save(db: &TrafficDb, key: &str, value: &str) {
        db.set_config(key, value);
    }

    /// Get all stored config entries.
    pub fn get_all(db: &TrafficDb) -> HashMap<String, String> {
        db.get_all_config()
    }
}
