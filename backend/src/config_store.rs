use std::collections::HashMap;

use tracing::info;

use crate::config::Config;
use crate::db::TrafficDb;

/// Runtime configuration merged from environment variables (defaults)
/// and database overrides. DB values take precedence over env values.
#[derive(Clone, Debug)]
pub struct MergedConfig {
    // RouterOS connection
    pub routeros_host: String,
    pub routeros_port: u16,
    pub routeros_scheme: String,
    pub routeros_username: String,
    pub routeros_password: String,
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
}

impl MergedConfig {
    /// Build from env Config (defaults) and optional DB overrides.
    pub fn from_env_and_db(env: &Config, db_overrides: &HashMap<String, String>) -> Self {
        let get = |key: &str| -> Option<&str> { db_overrides.get(key).map(|s| s.as_str()) };

        Self {
            routeros_host: get("routeros_host")
                .map(|s| s.to_string())
                .unwrap_or_else(|| env.routeros_host.clone()),

            routeros_port: get("routeros_port")
                .and_then(|s| s.parse().ok())
                .unwrap_or(env.routeros_port),

            routeros_scheme: get("routeros_scheme")
                .map(|s| s.to_lowercase())
                .filter(|s| s == "http" || s == "https")
                .unwrap_or_else(|| env.routeros_scheme.clone()),

            routeros_username: get("routeros_username")
                .map(|s| s.to_string())
                .unwrap_or_else(|| env.routeros_username.clone()),

            routeros_password: get("routeros_password")
                .map(|s| s.to_string())
                .unwrap_or_else(|| env.routeros_password.clone()),

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

            theme: get("theme").map(|s| s.to_string()).unwrap_or_else(|| "system".to_string()),
        }
    }

    /// Whether the connection configuration has been filled in (credentials exist).
    pub fn has_connection_config(&self) -> bool {
        !self.routeros_password.is_empty()
    }

    /// Build the RouterOS REST API base URL.
    pub fn routeros_base_url(&self) -> String {
        format!(
            "{}://{}:{}/rest",
            self.routeros_scheme, self.routeros_host, self.routeros_port
        )
    }

    pub fn is_tls(&self) -> bool {
        self.routeros_scheme == "https"
    }
}

/// Persists runtime config overrides in the SQLite `config` table.
pub struct ConfigStore;

impl ConfigStore {
    /// Load merged config: env defaults + DB overrides.
    pub fn load(db: &TrafficDb, env: &Config) -> MergedConfig {
        let overrides = db.get_all_config();
        info!(
            "ConfigStore: loaded {} overrides from DB",
            overrides.len()
        );
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
