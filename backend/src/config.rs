use std::{env, fs};

use ipnet::IpNet;

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
    /// Loopback-only setup listener port
    pub setup_port: u16,
    /// File used to deliver the one-time loopback setup token
    pub setup_token_file: String,
    /// Exact browser origin accepted for authenticated mutations
    pub public_origin: String,
    /// Networks containing reverse proxies allowed to assert the client IP
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// Path to the 256-bit key used to encrypt RouterOS credentials
    pub master_key_file: String,
    /// Networks in which RouterOS management targets may resolve
    pub router_management_cidrs: Vec<IpNet>,
    /// Explicit opt-in for cleartext RouterOS management traffic
    pub allow_insecure_router_http: bool,
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
    /// Optional static OpenID Connect configuration.
    pub oidc: Option<OidcConfig>,
}

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub provider_name: String,
    pub groups_claim: String,
    pub viewer_group: String,
    pub admin_group: String,
    pub additional_scopes: Vec<String>,
    pub ca_pem: Option<Vec<u8>>,
    pub redirect_url: String,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcConfig")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("provider_name", &self.provider_name)
            .field("groups_claim", &self.groups_claim)
            .field("viewer_group", &self.viewer_group)
            .field("admin_group", &self.admin_group)
            .field("additional_scopes", &self.additional_scopes)
            .field("ca_pem", &self.ca_pem.as_ref().map(|_| "[CUSTOM CA]"))
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
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

        let allow_insecure_router_http = parse_bool_env("ALLOW_INSECURE_ROUTER_HTTP", false)?;
        if scheme == "http" && !allow_insecure_router_http {
            return Err(ConfigError::InvalidFormat(
                "ROUTER_SCHEME=http requires ALLOW_INSECURE_ROUTER_HTTP=true".to_string(),
            ));
        }

        let router_management_cidrs = env::var("ROUTER_MANAGEMENT_CIDRS")
            .unwrap_or_else(|_| "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7".to_string())
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse::<IpNet>().map_err(|_| {
                    ConfigError::InvalidFormat(format!(
                        "ROUTER_MANAGEMENT_CIDRS contains invalid network '{value}'"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if router_management_cidrs.is_empty() {
            return Err(ConfigError::InvalidFormat(
                "ROUTER_MANAGEMENT_CIDRS must contain at least one network".to_string(),
            ));
        }

        let public_origin = normalize_public_origin(
            &env::var("PUBLIC_ORIGIN").unwrap_or_else(|_| "https://localhost".to_string()),
        )?;
        let trusted_proxy_cidrs = parse_optional_cidrs_env("TRUSTED_PROXY_CIDRS")?;

        let oidc = load_oidc_config(&public_origin)?;

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
            setup_port: parse_env::<u16>("SETUP_PORT", 3002)?,
            setup_token_file: env::var("SETUP_TOKEN_FILE")
                .unwrap_or_else(|_| "/tmp/routerview-setup-token".to_string()),
            public_origin,
            trusted_proxy_cidrs,
            master_key_file: env::var("ROUTERVIEW_MASTER_KEY_FILE").map_err(|_| {
                ConfigError::MissingRequired("ROUTERVIEW_MASTER_KEY_FILE".to_string())
            })?,
            router_management_cidrs,
            allow_insecure_router_http,
            probe_interval_secs: parse_env::<u64>("PROBE_INTERVAL_SECS", 60)?,
            db_path: env::var("DB_PATH").unwrap_or_else(|_| "traffic.db".to_string()),
            db_raw_retention_days: parse_env::<u64>("DB_RAW_RETENTION_DAYS", 7)?,
            db_total_retention_days: parse_env::<u64>("DB_TOTAL_RETENTION_DAYS", 90)?,
            latency_good_ms: parse_env::<u64>("LATENCY_GOOD_MS", 30)?,
            latency_poor_ms: parse_env::<u64>("LATENCY_POOR_MS", 100)?,
            oidc,
        })
    }
}

fn load_oidc_config(public_origin: &str) -> Result<Option<OidcConfig>, ConfigError> {
    load_oidc_config_with(public_origin, &|key: &str| env::var(key))
}

fn load_oidc_config_with(
    public_origin: &str,
    env_var: &impl Fn(&str) -> Result<String, env::VarError>,
) -> Result<Option<OidcConfig>, ConfigError> {
    if !parse_bool_value("OIDC_ENABLED", env_var("OIDC_ENABLED"), false)? {
        return Ok(None);
    }

    let required = |key: &str| -> Result<String, ConfigError> {
        env_var(key)
            .map_err(|_| ConfigError::MissingRequired(key.to_string()))
            .and_then(|value| {
                let value = value.trim().to_string();
                if value.is_empty() {
                    Err(ConfigError::InvalidFormat(format!(
                        "{key} must not be empty"
                    )))
                } else {
                    Ok(value)
                }
            })
    };

    let issuer_url = normalize_oidc_url(&required("OIDC_ISSUER_URL")?, "OIDC_ISSUER_URL")?;
    let client_id = required("OIDC_CLIENT_ID")?;
    if client_id.len() > 512 {
        return Err(ConfigError::InvalidFormat(
            "OIDC_CLIENT_ID must not exceed 512 bytes".into(),
        ));
    }
    let client_secret_path = required("OIDC_CLIENT_SECRET_FILE")?;
    let client_secret = read_client_secret(&client_secret_path)?;

    let provider_name = required("OIDC_PROVIDER_NAME")?;
    validate_display_config("OIDC_PROVIDER_NAME", &provider_name, 80)?;
    let groups_claim = env_var("OIDC_GROUPS_CLAIM")
        .unwrap_or_else(|_| "groups".to_string())
        .trim()
        .to_string();
    if groups_claim.is_empty()
        || groups_claim.len() > 128
        || !groups_claim
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ConfigError::InvalidFormat(
            "OIDC_GROUPS_CLAIM must be a simple top-level claim name".into(),
        ));
    }
    let viewer_group = required("OIDC_VIEWER_GROUP")?;
    let admin_group = required("OIDC_ADMIN_GROUP")?;
    validate_display_config("OIDC_VIEWER_GROUP", &viewer_group, 256)?;
    validate_display_config("OIDC_ADMIN_GROUP", &admin_group, 256)?;
    if viewer_group == admin_group {
        return Err(ConfigError::InvalidFormat(
            "OIDC_VIEWER_GROUP and OIDC_ADMIN_GROUP must be different".into(),
        ));
    }

    let additional_scopes =
        parse_additional_scopes(&env_var("OIDC_ADDITIONAL_SCOPES").unwrap_or_default())?;

    let ca_pem = env_var("OIDC_CA_FILE")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(|path| read_bounded_file(path.trim(), 1024 * 1024, "OIDC_CA_FILE"))
        .transpose()?;

    Ok(Some(OidcConfig {
        issuer_url,
        client_id,
        client_secret,
        provider_name,
        groups_claim,
        viewer_group,
        admin_group,
        additional_scopes,
        ca_pem,
        redirect_url: format!("{public_origin}/api/auth/oidc/callback"),
    }))
}

fn read_client_secret(path: &str) -> Result<String, ConfigError> {
    let mut bytes = read_bounded_file(path, 4 * 1024, "OIDC_CLIENT_SECRET_FILE")?;
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(ConfigError::InvalidFormat(
            "OIDC_CLIENT_SECRET_FILE must contain a non-empty secret".into(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        ConfigError::InvalidFormat("OIDC_CLIENT_SECRET_FILE must contain UTF-8 text".into())
    })
}

fn parse_additional_scopes(value: &str) -> Result<Vec<String>, ConfigError> {
    let mut scopes = Vec::new();
    for scope in value
        .split(|character: char| character == ',' || character.is_ascii_whitespace())
        .filter(|scope| !scope.is_empty())
    {
        if scope.len() > 128
            || !scope.bytes().all(|byte| {
                byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
            })
        {
            return Err(ConfigError::InvalidFormat(
                "OIDC_ADDITIONAL_SCOPES contains an invalid scope".into(),
            ));
        }
        if !matches!(scope, "openid" | "profile" | "email")
            && !scopes.iter().any(|existing| existing == scope)
        {
            scopes.push(scope.to_string());
        }
    }
    if scopes.len() > 32 {
        return Err(ConfigError::InvalidFormat(
            "OIDC_ADDITIONAL_SCOPES must contain at most 32 scopes".into(),
        ));
    }
    Ok(scopes)
}

fn read_bounded_file(path: &str, maximum: u64, key: &str) -> Result<Vec<u8>, ConfigError> {
    let metadata = fs::metadata(path)
        .map_err(|_| ConfigError::InvalidFormat(format!("{key} cannot be read")))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(ConfigError::InvalidFormat(format!(
            "{key} must be a regular file no larger than {maximum} bytes"
        )));
    }
    let bytes =
        fs::read(path).map_err(|_| ConfigError::InvalidFormat(format!("{key} cannot be read")))?;
    if bytes.len() as u64 > maximum {
        return Err(ConfigError::InvalidFormat(format!(
            "{key} must not exceed {maximum} bytes"
        )));
    }
    Ok(bytes)
}

fn validate_display_config(key: &str, value: &str, maximum: usize) -> Result<(), ConfigError> {
    if value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ConfigError::InvalidFormat(format!(
            "{key} must not exceed {maximum} bytes or contain control characters"
        )));
    }
    Ok(())
}

fn normalize_oidc_url(value: &str, key: &str) -> Result<String, ConfigError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| ConfigError::InvalidFormat(format!("{key} must be an absolute URL")))?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.scheme(), "http" | "https")
    {
        return Err(ConfigError::InvalidFormat(format!(
            "{key} must contain an http(s) URL without credentials, query, or fragment"
        )));
    }
    let loopback = match parsed.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    if parsed.scheme() != "https" && !loopback {
        return Err(ConfigError::InvalidFormat(format!(
            "{key} must use HTTPS except for loopback development"
        )));
    }
    Ok(parsed.to_string())
}

fn normalize_public_origin(value: &str) -> Result<String, ConfigError> {
    let parsed = url::Url::parse(value)
        .map_err(|_| ConfigError::InvalidFormat("PUBLIC_ORIGIN must be an absolute URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::InvalidFormat(
            "PUBLIC_ORIGIN must contain only an http(s) scheme and authority".into(),
        ));
    }
    if parsed.scheme() != "https" && parsed.host_str() != Some("localhost") {
        return Err(ConfigError::InvalidFormat(
            "PUBLIC_ORIGIN must use HTTPS except for localhost development".into(),
        ));
    }
    Ok(parsed.origin().ascii_serialization())
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

fn parse_bool_env(key: &str, default: bool) -> Result<bool, ConfigError> {
    parse_bool_value(key, env::var(key), default)
}

fn parse_bool_value(
    key: &str,
    value: Result<String, env::VarError>,
    default: bool,
) -> Result<bool, ConfigError> {
    match value {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            _ => Err(ConfigError::InvalidFormat(key.to_string())),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(ConfigError::EnvError(error)),
    }
}

fn parse_optional_cidrs_env(key: &str) -> Result<Vec<IpNet>, ConfigError> {
    match env::var(key) {
        Ok(value) => parse_cidrs(key, &value),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(error) => Err(ConfigError::EnvError(error)),
    }
}

fn parse_cidrs(key: &str, value: &str) -> Result<Vec<IpNet>, ConfigError> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|network| {
            network.parse::<IpNet>().map_err(|_| {
                ConfigError::InvalidFormat(format!("{key} contains invalid network '{network}'"))
            })
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::Path};

    use super::*;

    fn oidc_test_env(secret_path: &Path) -> HashMap<String, String> {
        [
            ("OIDC_ENABLED", "true".to_string()),
            (
                "OIDC_ISSUER_URL",
                "https://idp.example/realms/routerview".to_string(),
            ),
            ("OIDC_CLIENT_ID", "routerview".to_string()),
            (
                "OIDC_CLIENT_SECRET_FILE",
                secret_path.to_string_lossy().into_owned(),
            ),
            ("OIDC_PROVIDER_NAME", "Company SSO".to_string()),
            ("OIDC_VIEWER_GROUP", "routerview-viewers".to_string()),
            ("OIDC_ADMIN_GROUP", "routerview-admins".to_string()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
    }

    fn load_test_oidc(values: &HashMap<String, String>) -> Result<Option<OidcConfig>, ConfigError> {
        load_oidc_config_with("https://routerview.example", &|key| {
            values.get(key).cloned().ok_or(env::VarError::NotPresent)
        })
    }

    fn oidc_test_directory() -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "routerview-oidc-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn public_origin_is_canonicalized() {
        assert_eq!(
            normalize_public_origin("HTTPS://Example.COM:443/").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalize_public_origin("https://Example.COM:8443").unwrap(),
            "https://example.com:8443"
        );
        assert_eq!(
            normalize_public_origin("http://LOCALHOST:80/").unwrap(),
            "http://localhost"
        );
    }

    #[test]
    fn public_origin_rejects_non_origin_components() {
        assert!(normalize_public_origin("https://example.com/app").is_err());
        assert!(normalize_public_origin("https://user@example.com/").is_err());
        assert!(normalize_public_origin("http://192.168.1.10/").is_err());
    }

    #[test]
    fn trusted_proxy_cidrs_are_explicit_and_strictly_parsed() {
        assert!(parse_cidrs("TRUSTED_PROXY_CIDRS", "").unwrap().is_empty());
        assert_eq!(
            parse_cidrs("TRUSTED_PROXY_CIDRS", "172.31.254.2/32, 2001:db8::1/128").unwrap(),
            vec![
                "172.31.254.2/32".parse::<IpNet>().unwrap(),
                "2001:db8::1/128".parse::<IpNet>().unwrap(),
            ]
        );
        assert!(parse_cidrs("TRUSTED_PROXY_CIDRS", "private-network").is_err());
    }

    #[test]
    fn oidc_config_is_optional_and_rejects_invalid_enable_flag() {
        let mut values = HashMap::new();
        assert!(load_test_oidc(&values).unwrap().is_none());

        values.insert("OIDC_ENABLED".into(), "false".into());
        assert!(load_test_oidc(&values).unwrap().is_none());

        values.insert("OIDC_ENABLED".into(), "sometimes".into());
        assert!(matches!(
            load_test_oidc(&values),
            Err(ConfigError::InvalidFormat(value)) if value == "OIDC_ENABLED"
        ));
    }

    #[test]
    fn oidc_config_requires_every_confidential_client_and_role_field() {
        let directory = oidc_test_directory();
        let secret = directory.join("client-secret");
        std::fs::write(&secret, b"test-secret\n").unwrap();
        let values = oidc_test_env(&secret);

        for key in [
            "OIDC_ISSUER_URL",
            "OIDC_CLIENT_ID",
            "OIDC_CLIENT_SECRET_FILE",
            "OIDC_PROVIDER_NAME",
            "OIDC_VIEWER_GROUP",
            "OIDC_ADMIN_GROUP",
        ] {
            let mut missing = values.clone();
            missing.remove(key);
            assert!(matches!(
                load_test_oidc(&missing),
                Err(ConfigError::MissingRequired(value)) if value == key
            ));

            let mut empty = values.clone();
            empty.insert(key.into(), " \t ".into());
            assert!(matches!(
                load_test_oidc(&empty),
                Err(ConfigError::InvalidFormat(value)) if value.contains(key)
            ));
        }

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oidc_config_loads_files_defaults_and_exact_callback() {
        let directory = oidc_test_directory();
        let secret = directory.join("client-secret");
        let ca = directory.join("provider-ca.pem");
        std::fs::write(&secret, b"file-secret\r\n").unwrap();
        std::fs::write(&ca, b"explicit-ca-bundle").unwrap();
        let mut values = oidc_test_env(&secret);
        values.insert("OIDC_CLIENT_SECRET".into(), "ignored-env-secret".into());
        values.insert("OIDC_CA_FILE".into(), ca.to_string_lossy().into_owned());
        values.insert(
            "OIDC_ADDITIONAL_SCOPES".into(),
            "groups profile groups offline_access".into(),
        );

        let config = load_test_oidc(&values).unwrap().unwrap();
        assert_eq!(config.issuer_url, "https://idp.example/realms/routerview");
        assert_eq!(config.client_secret, "file-secret");
        assert_eq!(config.groups_claim, "groups");
        assert_eq!(config.additional_scopes, ["groups", "offline_access"]);
        assert_eq!(
            config.ca_pem.as_deref(),
            Some(b"explicit-ca-bundle".as_slice())
        );
        assert_eq!(
            config.redirect_url,
            "https://routerview.example/api/auth/oidc/callback"
        );

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oidc_config_rejects_invalid_names_claims_and_group_mapping() {
        let directory = oidc_test_directory();
        let secret = directory.join("client-secret");
        std::fs::write(&secret, b"test-secret").unwrap();
        let values = oidc_test_env(&secret);

        for (key, value) in [
            ("OIDC_CLIENT_ID", "x".repeat(513)),
            ("OIDC_PROVIDER_NAME", "x".repeat(81)),
            ("OIDC_PROVIDER_NAME", "Company\nSSO".into()),
            ("OIDC_GROUPS_CLAIM", String::new()),
            ("OIDC_GROUPS_CLAIM", "nested claim".into()),
            ("OIDC_GROUPS_CLAIM", "x".repeat(129)),
            ("OIDC_VIEWER_GROUP", "x".repeat(257)),
            ("OIDC_ADMIN_GROUP", "admins\nother".into()),
        ] {
            let mut invalid = values.clone();
            invalid.insert(key.into(), value);
            assert!(
                matches!(load_test_oidc(&invalid), Err(ConfigError::InvalidFormat(_))),
                "{key} should have been rejected"
            );
        }

        let mut equal_groups = values.clone();
        equal_groups.insert("OIDC_ADMIN_GROUP".into(), "routerview-viewers".into());
        assert!(matches!(
            load_test_oidc(&equal_groups),
            Err(ConfigError::InvalidFormat(_))
        ));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oidc_issuer_preserves_path_and_requires_https_or_loopback() {
        assert_eq!(
            normalize_oidc_url("https://idp.example/tenant/", "OIDC_ISSUER_URL").unwrap(),
            "https://idp.example/tenant/"
        );
        assert_eq!(
            normalize_oidc_url("https://idp.example/tenant", "OIDC_ISSUER_URL").unwrap(),
            "https://idp.example/tenant"
        );
        assert!(normalize_oidc_url("http://localhost:8080/issuer", "issuer").is_ok());
        assert!(normalize_oidc_url("http://127.0.0.1:8080", "issuer").is_ok());
        assert!(normalize_oidc_url("http://[::1]:8080", "issuer").is_ok());
        assert!(normalize_oidc_url("http://192.0.2.1", "issuer").is_err());
        assert!(normalize_oidc_url("idp.example/tenant", "issuer").is_err());
        assert!(normalize_oidc_url("https://user@idp.example", "issuer").is_err());
        assert!(normalize_oidc_url("https://idp.example?tenant=one", "issuer").is_err());
        assert!(normalize_oidc_url("https://idp.example#tenant", "issuer").is_err());
    }

    #[test]
    fn oidc_scopes_are_split_and_deduplicated() {
        assert_eq!(
            parse_additional_scopes("groups, offline_access groups\tprofile openid").unwrap(),
            vec!["groups", "offline_access"]
        );
        let too_many = (0..33)
            .map(|index| format!("scope-{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_additional_scopes(&too_many).is_err());
        assert!(parse_additional_scopes("valid invalid\\scope").is_err());
        assert!(parse_additional_scopes("grüp").is_err());
    }

    #[test]
    fn oidc_secret_file_is_bounded_and_only_trims_line_endings() {
        let directory = oidc_test_directory();
        let secret = directory.join("client-secret");
        std::fs::write(&secret, b"  exact secret  \r\n").unwrap();
        assert_eq!(
            read_client_secret(secret.to_str().unwrap()).unwrap(),
            "  exact secret  "
        );
        std::fs::write(&secret, b"\r\n").unwrap();
        assert!(read_client_secret(secret.to_str().unwrap()).is_err());
        std::fs::write(&secret, [0xff, 0xfe]).unwrap();
        assert!(read_client_secret(secret.to_str().unwrap()).is_err());
        std::fs::write(&secret, vec![b'x'; 4097]).unwrap();
        assert!(read_client_secret(secret.to_str().unwrap()).is_err());
        assert!(read_client_secret(directory.to_str().unwrap()).is_err());
        assert!(read_client_secret(directory.join("missing").to_str().unwrap()).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn oidc_debug_output_redacts_secrets_and_ca_bytes() {
        let config = OidcConfig {
            issuer_url: "https://idp.example/".into(),
            client_id: "routerview".into(),
            client_secret: "must-never-appear".into(),
            provider_name: "Example".into(),
            groups_claim: "groups".into(),
            viewer_group: "readers".into(),
            admin_group: "operators".into(),
            additional_scopes: vec![],
            ca_pem: Some(b"private-ca-bytes".to_vec()),
            redirect_url: "https://routerview.example/api/auth/oidc/callback".into(),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("must-never-appear"));
        assert!(!debug.contains("private-ca-bytes"));
    }
}
