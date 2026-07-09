use std::env;

use crate::backends::RouterType;

/// Application configuration loaded from environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// Router type (default: "routeros")
    pub router_type: RouterType,
    /// Router hostname or IP address
    pub router_host: String,
    /// Router REST API port (default: 443 for HTTPS, 80 for HTTP)
    pub router_port: u16,
    /// Connection scheme: "http" or "https"
    pub router_scheme: String,
    /// Router username
    pub router_username: String,
    /// Router password
    pub router_password: String,
    /// Accept invalid TLS certificates (self-signed) — only relevant for HTTPS
    pub accept_invalid_certs: bool,
    /// Poll interval in seconds
    pub poll_interval_secs: u64,
    /// Backend server listen port
    pub server_port: u16,
    /// Latency probe interval in seconds (separate from main poll)
    pub probe_interval_secs: u64,
    /// Path to the SQLite traffic history database
    pub db_path: String,
    /// Days to keep raw 5-second data before aggregating to 1-minute AVG
    pub db_raw_retention_days: u64,
    /// Days after which all traffic data is deleted
    pub db_total_retention_days: u64,
    /// Latency threshold: RTT below this is "good" (ms)
    pub latency_good_ms: u64,
    /// Latency threshold: RTT above this is "poor" (ms), between good and poor is "moderate"
    pub latency_poor_ms: u64,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Attempts to load `.env` file first via dotenvy, then falls back to
    /// environment variables with sensible defaults.
    ///
    /// Supports both new `ROUTER_*` and legacy `ROUTEROS_*` env var names
    /// for backward compatibility.
    pub fn from_env() -> Result<Self, ConfigError> {
        // Attempt to load .env file — ignore if missing
        let _ = dotenvy::dotenv();

        let scheme = env_host("ROUTER_SCHEME", "ROUTEROS_SCHEME")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|| "https".to_string());

        // Validate scheme
        if scheme != "http" && scheme != "https" {
            return Err(ConfigError::InvalidFormat(
                "ROUTER_SCHEME (or ROUTEROS_SCHEME) must be 'http' or 'https'".to_string(),
            ));
        }

        // Default port depends on scheme
        let default_port: u16 = if scheme == "http" { 80 } else { 443 };

        let router_type =
            env_host("ROUTER_TYPE", "ROUTEROS_TYPE").unwrap_or_else(|| "routeros".to_string());

        let router_type = match router_type.to_lowercase().as_str() {
            "routeros" => RouterType::RouterOs,
            other => {
                return Err(ConfigError::InvalidFormat(format!(
                    "Unknown router type: '{other}'. Supported: routeros"
                )));
            }
        };

        Ok(Config {
            router_type,
            router_host: env_host("ROUTER_HOST", "ROUTEROS_HOST")
                .unwrap_or_else(|| "192.168.88.1".to_string()),
            router_port: parse_env_host("ROUTER_PORT", "ROUTEROS_PORT", default_port)?,
            router_scheme: scheme,
            router_username: env_host("ROUTER_USERNAME", "ROUTEROS_USERNAME")
                .unwrap_or_else(|| "admin".to_string()),
            router_password: env_host("ROUTER_PASSWORD", "ROUTEROS_PASSWORD").unwrap_or_default(),
            accept_invalid_certs: env_host("ROUTER_INSECURE_TLS", "ROUTEROS_INSECURE_TLS")
                .map(|v| v.to_lowercase() == "true" || v == "1")
                .unwrap_or(false),
            poll_interval_secs: parse_env::<u64>("POLL_INTERVAL_SECS", 3)?,
            server_port: parse_env::<u16>("SERVER_PORT", 3001)?,
            probe_interval_secs: parse_env::<u64>("PROBE_INTERVAL_SECS", 60)?,
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "traffic.db".to_string()),
            db_raw_retention_days: parse_env::<u64>("DB_RAW_RETENTION_DAYS", 7)?,
            db_total_retention_days: parse_env::<u64>("DB_TOTAL_RETENTION_DAYS", 90)?,
            latency_good_ms: parse_env::<u64>("LATENCY_GOOD_MS", 30)?,
            latency_poor_ms: parse_env::<u64>("LATENCY_POOR_MS", 100)?,
        })
    }
}

/// Get an env var, checking the new name first, then the legacy name as fallback.
fn env_host(new_key: &str, legacy_key: &str) -> Option<String> {
    env::var(new_key).ok().or_else(|| env::var(legacy_key).ok())
}

/// Parse an env var, checking the new name first, then the legacy name as fallback.
fn parse_env_host<T: std::str::FromStr>(
    new_key: &str,
    legacy_key: &str,
    default: T,
) -> Result<T, ConfigError> {
    // Try new key first
    if let Ok(val) = env::var(new_key) {
        return val
            .parse::<T>()
            .map_err(|_| ConfigError::InvalidFormat(new_key.to_string()));
    }
    // Fall back to legacy key
    match env::var(legacy_key) {
        Ok(val) => val
            .parse::<T>()
            .map_err(|_| ConfigError::InvalidFormat(legacy_key.to_string())),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(ConfigError::EnvError(e)),
    }
}

fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> Result<T, ConfigError> {
    match env::var(key) {
        Ok(val) => val
            .parse::<T>()
            .map_err(|_| ConfigError::InvalidFormat(key.to_string())),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(ConfigError::EnvError(e)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    MissingRequired(String),
    #[error("Invalid format for environment variable: {0}")]
    InvalidFormat(String),
    #[error("Environment variable error: {0}")]
    EnvError(#[from] std::env::VarError),
}
