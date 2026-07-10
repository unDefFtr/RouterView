use std::collections::HashMap;

use tracing::info;

use crate::backends::RouterType;
use crate::config::Config;
use crate::db::TrafficDb;
use crate::error::AppError;
use crate::secrets::SecretCipher;

/// Runtime configuration merged from environment variables (defaults)
/// and database overrides. DB values take precedence over env values.
#[derive(Clone, Debug)]
pub struct MergedConfig {
    pub revision: u64,
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

    // Deployment-enforced router target policy
    pub router_management_cidrs: Vec<ipnet::IpNet>,
    pub allow_insecure_router_http: bool,
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
            revision: get("config_revision")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
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

            router_management_cidrs: env.router_management_cidrs.clone(),
            allow_insecure_router_http: env.allow_insecure_router_http,
        }
    }

    /// Whether the connection configuration has been filled in (credentials exist).
    pub fn has_connection_config(&self) -> bool {
        !self.router_password.is_empty()
    }

    pub fn validate(&self) -> Result<(), AppError> {
        if self.router_port == 0 {
            return Err(AppError::InvalidData(
                "router_port must be between 1 and 65535".into(),
            ));
        }
        if !(1..=30).contains(&self.poll_interval_secs) {
            return Err(AppError::InvalidData(
                "poll_interval_secs must be between 1 and 30".into(),
            ));
        }
        if !(10..=600).contains(&self.probe_interval_secs) {
            return Err(AppError::InvalidData(
                "probe_interval_secs must be between 10 and 600".into(),
            ));
        }
        if !(1..=30).contains(&self.db_raw_retention_days) {
            return Err(AppError::InvalidData(
                "db_raw_retention_days must be between 1 and 30".into(),
            ));
        }
        if !(7..=365).contains(&self.db_total_retention_days)
            || self.db_total_retention_days < self.db_raw_retention_days
        {
            return Err(AppError::InvalidData(
                "db_total_retention_days must be between 7 and 365 and not less than raw retention"
                    .into(),
            ));
        }
        if !(1..=500).contains(&self.latency_good_ms) {
            return Err(AppError::InvalidData(
                "latency_good_ms must be between 1 and 500".into(),
            ));
        }
        if !(1..=2000).contains(&self.latency_poor_ms) {
            return Err(AppError::InvalidData(
                "latency_poor_ms must be between 1 and 2000".into(),
            ));
        }
        if self.latency_good_ms >= self.latency_poor_ms {
            return Err(AppError::InvalidData(
                "latency_good_ms must be less than latency_poor_ms".into(),
            ));
        }
        if self.router_host.trim().is_empty() || self.router_host.len() > 253 {
            return Err(AppError::InvalidData(
                "router_host must contain 1 to 253 characters".into(),
            ));
        }
        if self.router_username.trim().is_empty() || self.router_username.len() > 128 {
            return Err(AppError::InvalidData(
                "router_username must contain 1 to 128 characters".into(),
            ));
        }
        if self.router_scheme != "https"
            && !(self.router_scheme == "http" && self.allow_insecure_router_http)
        {
            return Err(AppError::InvalidData(
                "HTTP router management is disabled by deployment policy".into(),
            ));
        }
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            return Err(AppError::InvalidData(
                "theme must be system, light, or dark".into(),
            ));
        }
        Ok(())
    }
}

/// Persists runtime config overrides in the SQLite `config` table.
pub struct ConfigStore;

impl ConfigStore {
    /// Load merged config: env defaults + DB overrides.
    pub fn load(
        db: &TrafficDb,
        env: &Config,
        cipher: &SecretCipher,
    ) -> Result<MergedConfig, AppError> {
        let mut overrides = db.get_all_config()?;
        info!("ConfigStore: loaded {} overrides from DB", overrides.len());
        let instance_id = db.instance_id()?;

        let canonical_plaintext = overrides.get("router_password").cloned();
        let legacy_plaintext = overrides.get("routeros_password").cloned();
        if canonical_plaintext.is_some()
            && legacy_plaintext.is_some()
            && canonical_plaintext != legacy_plaintext
        {
            return Err(AppError::InvalidData(
                "conflicting router_password and routeros_password values; remove one before migration"
                    .into(),
            ));
        }
        let plaintext = canonical_plaintext
            .or(legacy_plaintext)
            .filter(|value| !value.is_empty());
        let had_plaintext = plaintext.is_some();
        let stored_secret = db.load_secret("router_password")?;
        let password = if let Some(encrypted) = stored_secret {
            let decrypted = cipher
                .decrypt(&instance_id, "router_password", &encrypted)
                .map_err(|error| AppError::Secret(error.to_string()))?;
            let decrypted = String::from_utf8(decrypted)
                .map_err(|_| AppError::Secret("router password is not valid UTF-8".into()))?;
            if plaintext
                .as_ref()
                .is_some_and(|legacy| legacy != &decrypted)
            {
                return Err(AppError::InvalidData(
                    "encrypted and plaintext router passwords conflict; refusing automatic migration"
                        .into(),
                ));
            }
            if had_plaintext {
                db.migrate_plaintext_router_password(&encrypted)?;
            }
            decrypted
        } else {
            let value = plaintext.unwrap_or_else(|| env.router_password.clone());
            if !value.is_empty() {
                let encrypted = cipher
                    .encrypt(&instance_id, "router_password", value.as_bytes())
                    .map_err(|error| AppError::Secret(error.to_string()))?;
                if had_plaintext {
                    db.migrate_plaintext_router_password(&encrypted)?;
                } else {
                    db.save_config_transaction(
                        &[],
                        Some(("router_password", &encrypted)),
                        None,
                        None,
                    )?;
                }
            }
            value
        };

        overrides.remove("router_password");
        overrides.remove("routeros_password");
        let mut merged = MergedConfig::from_env_and_db(env, &overrides);
        merged.router_password = password;
        merged.validate()?;
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> MergedConfig {
        MergedConfig {
            router_type: RouterType::RouterOs,
            revision: 0,
            router_host: "192.168.88.1".into(),
            router_port: 443,
            router_scheme: "https".into(),
            router_username: "admin".into(),
            router_password: "secret".into(),
            accept_invalid_certs: false,
            poll_interval_secs: 3,
            probe_interval_secs: 60,
            server_port: 3001,
            db_raw_retention_days: 7,
            db_total_retention_days: 90,
            theme: "system".into(),
            latency_good_ms: 30,
            latency_poor_ms: 100,
            router_management_cidrs: vec!["192.168.0.0/16".parse().unwrap()],
            allow_insecure_router_http: false,
        }
    }

    #[test]
    fn rejects_out_of_range_router_and_latency_values() {
        let mut config = valid_config();
        config.router_port = 0;
        assert!(config.validate().is_err());

        config = valid_config();
        config.latency_good_ms = 501;
        assert!(config.validate().is_err());

        config = valid_config();
        config.latency_poor_ms = 2001;
        assert!(config.validate().is_err());
    }
}
