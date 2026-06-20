use std::env;

/// Application configuration loaded from environment variables.
#[derive(Clone, Debug)]
pub struct Config {
    /// RouterOS hostname or IP address
    pub routeros_host: String,
    /// RouterOS REST API port (default: 443 for HTTPS, 80 for HTTP)
    pub routeros_port: u16,
    /// Connection scheme: "http" or "https"
    pub routeros_scheme: String,
    /// RouterOS username
    pub routeros_username: String,
    /// RouterOS password
    pub routeros_password: String,
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
    pub fn from_env() -> Result<Self, ConfigError> {
        // Attempt to load .env file — ignore if missing
        let _ = dotenvy::dotenv();

        let scheme = env::var("ROUTEROS_SCHEME")
            .map(|s| s.to_lowercase())
            .unwrap_or_else(|_| "https".to_string());

        // Validate scheme
        if scheme != "http" && scheme != "https" {
            return Err(ConfigError::InvalidFormat(
                "ROUTEROS_SCHEME must be 'http' or 'https'".to_string(),
            ));
        }

        // Default port depends on scheme
        let default_port: u16 = if scheme == "http" { 80 } else { 443 };

        Ok(Config {
            routeros_host: env::var("ROUTEROS_HOST")
                .unwrap_or_else(|_| "192.168.88.1".to_string()),
            routeros_port: parse_env::<u16>("ROUTEROS_PORT", default_port)?,
            routeros_scheme: scheme,
            routeros_username: env::var("ROUTEROS_USERNAME")
                .unwrap_or_else(|_| "admin".to_string()),
            routeros_password: env::var("ROUTEROS_PASSWORD")
                .unwrap_or_default(),
            accept_invalid_certs: env::var("ROUTEROS_INSECURE_TLS")
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

    /// Build the RouterOS REST API base URL.
    pub fn routeros_base_url(&self) -> String {
        format!(
            "{}://{}:{}/rest",
            self.routeros_scheme, self.routeros_host, self.routeros_port
        )
    }

    /// Whether TLS is being used (for conditional client configuration).
    pub fn is_tls(&self) -> bool {
        self.routeros_scheme == "https"
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
