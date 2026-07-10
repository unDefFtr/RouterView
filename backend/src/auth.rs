use std::{
    collections::HashMap,
    fs::OpenOptions,
    hash::Hash,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path as FsPath,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use argon2::{
    password_hash::{
        rand_core::OsRng as PasswordOsRng, PasswordHash, PasswordHasher, PasswordVerifier,
        SaltString,
    },
    Algorithm, Argon2, Params, Version,
};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use ipnet::IpNet;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::{
    db::{AdminRecord, AuthSessionRecord, PairingRecord, TrafficDb},
    error::{ApiJson, ApiPath, AppError},
    state::AppState,
};

pub const SESSION_COOKIE: &str = "__Host-routerview_session";
pub const CSRF_COOKIE: &str = "__Host-routerview_csrf";
const STANDARD_IDLE_SECS: i64 = 12 * 60 * 60;
const STANDARD_ABSOLUTE_SECS: i64 = 7 * 24 * 60 * 60;
const FIXED_VIEWER_SECS: i64 = 180 * 24 * 60 * 60;
const FIXED_ADMIN_SECS: i64 = 30 * 24 * 60 * 60;
const PAIRING_SECS: i64 = 10 * 60;
pub const SETUP_TOKEN_TTL_SECS: u64 = 15 * 60;
const SETUP_SECS: i64 = SETUP_TOKEN_TTL_SECS as i64;
const ARGON2_CONCURRENCY: usize = 2;
const ARGON2_WAIT_TIMEOUT: Duration = Duration::from_millis(250);
const PAIRING_CONCURRENCY: usize = 1;
const HTTP_SESSION_TOUCH_SECS: i64 = 5 * 60;
const AUTH_FAILURE_CAPACITY: usize = 1_024;
const AUTH_FAILURE_TTL: Duration = Duration::from_secs(15 * 60);
const AUTH_BACKOFF_MAX_SECS: u64 = 60;
const CLIENT_IP_HEADER: &str = "x-real-ip";

/// Process-wide authentication work limits and source-aware timing state.
pub struct AuthSecurity {
    argon2_slots: Arc<Semaphore>,
    pairing_slots: Arc<Semaphore>,
    dummy_password_hash: String,
    login_failures: FailureLimiter<LoginFailureKey>,
    pairing_attempts: FailureLimiter<PairingFailureKey>,
    trusted_proxy_cidrs: Vec<IpNet>,
}

impl AuthSecurity {
    pub fn new(trusted_proxy_cidrs: Vec<IpNet>) -> Result<Self, AppError> {
        Ok(Self {
            argon2_slots: Arc::new(Semaphore::new(ARGON2_CONCURRENCY)),
            pairing_slots: Arc::new(Semaphore::new(PAIRING_CONCURRENCY)),
            dummy_password_hash: hash_password_sync(&random_token())?,
            login_failures: FailureLimiter::default(),
            pairing_attempts: FailureLimiter::default(),
            trusted_proxy_cidrs,
        })
    }

    async fn acquire_argon2(&self) -> Result<OwnedSemaphorePermit, AppError> {
        match tokio::time::timeout(
            ARGON2_WAIT_TIMEOUT,
            self.argon2_slots.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(AppError::Internal(
                "password verification semaphore is closed".into(),
            )),
            Err(_) => Err(AppError::RateLimited {
                retry_after_secs: 1,
            }),
        }
    }

    fn acquire_pairing_slot(&self) -> Result<OwnedSemaphorePermit, AppError> {
        match self.pairing_slots.clone().try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(TryAcquireError::NoPermits) => Err(AppError::RateLimited {
                retry_after_secs: 1,
            }),
            Err(TryAcquireError::Closed) => Err(AppError::Internal(
                "pairing admission semaphore is closed".into(),
            )),
        }
    }

    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, AppError> {
        resolve_client_ip(peer, headers, &self.trusted_proxy_cidrs)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum LoginFailureKey {
    Username(String),
    Source(IpAddr),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum PairingFailureKey {
    Source(IpAddr),
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PairingAttempt {
    key: PairingFailureKey,
    started_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct FailureState {
    failures: u8,
    blocked_until: Instant,
    last_failure: Instant,
    last_seen: Instant,
}

struct FailureLimiter<K> {
    entries: Mutex<HashMap<K, FailureState>>,
}

impl<K> Default for FailureLimiter<K> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<K> FailureLimiter<K>
where
    K: Clone + Eq + Hash,
{
    fn retry_after(&self, key: &K, now: Instant) -> Option<u64> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let state = entries.get_mut(key)?;
        if now.saturating_duration_since(state.last_seen) >= AUTH_FAILURE_TTL {
            entries.remove(key);
            return None;
        }
        state.last_seen = now;
        (state.blocked_until > now).then(|| retry_after_seconds(state.blocked_until, now))
    }

    fn record_failure(&self, key: K, now: Instant) -> u64 {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        expire_failure_entries(&mut entries, now);
        record_failure_locked(&mut entries, key, now)
    }

    fn clear_if_latest(&self, key: &K, attempt_started_at: Instant) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if entries
            .get(key)
            .is_some_and(|state| state.last_failure == attempt_started_at)
        {
            entries.remove(key);
        }
    }
}

impl FailureLimiter<PairingFailureKey> {
    fn begin_pairing_attempt(&self, source: IpAddr, now: Instant) -> Result<PairingAttempt, u64> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let source_key = PairingFailureKey::Source(source);
        let key = if entries.contains_key(&source_key) || entries.len() < AUTH_FAILURE_CAPACITY {
            source_key
        } else {
            // Preserve tracked penalties at capacity; excess addresses share one backoff bucket.
            let overflow_key = PairingFailureKey::Overflow;
            if entries.get(&overflow_key).is_some_and(|state| {
                now.saturating_duration_since(state.last_seen) >= AUTH_FAILURE_TTL
            }) {
                entries.remove(&overflow_key);
            }
            if let Some(state) = entries.get_mut(&overflow_key) {
                state.last_seen = now;
                if state.blocked_until > now {
                    return Err(retry_after_seconds(state.blocked_until, now));
                }
            }

            expire_failure_entries(&mut entries, now);
            let tracked_sources = entries
                .keys()
                .filter(|key| matches!(key, PairingFailureKey::Source(_)))
                .count();
            if tracked_sources < AUTH_FAILURE_CAPACITY {
                entries.remove(&overflow_key);
                source_key
            } else {
                overflow_key
            }
        };

        begin_failure_attempt_locked(&mut entries, key, now)?;
        Ok(PairingAttempt {
            key,
            started_at: now,
        })
    }
}

fn expire_failure_entries<K>(entries: &mut HashMap<K, FailureState>, now: Instant) {
    entries.retain(|_, state| now.saturating_duration_since(state.last_seen) < AUTH_FAILURE_TTL);
}

fn record_failure_locked<K>(entries: &mut HashMap<K, FailureState>, key: K, now: Instant) -> u64
where
    K: Clone + Eq + Hash,
{
    if !entries.contains_key(&key) && entries.len() >= AUTH_FAILURE_CAPACITY {
        if let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, state)| state.last_seen)
            .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
    }

    record_failure_entry_locked(entries, key, now)
}

fn begin_failure_attempt_locked<K>(
    entries: &mut HashMap<K, FailureState>,
    key: K,
    now: Instant,
) -> Result<(), u64>
where
    K: Eq + Hash,
{
    if entries
        .get(&key)
        .is_some_and(|state| now.saturating_duration_since(state.last_seen) >= AUTH_FAILURE_TTL)
    {
        entries.remove(&key);
    }
    if let Some(state) = entries.get_mut(&key) {
        state.last_seen = now;
        if state.blocked_until > now {
            return Err(retry_after_seconds(state.blocked_until, now));
        }
    }
    record_failure_entry_locked(entries, key, now);
    Ok(())
}

fn record_failure_entry_locked<K>(
    entries: &mut HashMap<K, FailureState>,
    key: K,
    now: Instant,
) -> u64
where
    K: Eq + Hash,
{
    let state = entries.entry(key).or_insert(FailureState {
        failures: 0,
        blocked_until: now,
        last_failure: now,
        last_seen: now,
    });
    state.failures = state.failures.saturating_add(1).min(7);
    let backoff_secs = (1_u64 << (state.failures - 1)).min(AUTH_BACKOFF_MAX_SECS);
    state.blocked_until = now + Duration::from_secs(backoff_secs);
    state.last_failure = now;
    state.last_seen = now;
    backoff_secs
}

fn retry_after_seconds(blocked_until: Instant, now: Instant) -> u64 {
    let remaining = blocked_until.saturating_duration_since(now);
    remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0)
}

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub id: String,
    pub username: String,
    pub role: String,
    pub kind: String,
    pub csrf_hash: Vec<u8>,
}

impl SessionContext {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRequest {
    token: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePairingRequest {
    label: String,
    role: String,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    code: String,
}

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub setup_required: bool,
    pub authenticated: bool,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub username: String,
    pub role: String,
    pub session_kind: String,
    pub capabilities: Vec<&'static str>,
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let session = authenticate_headers(&state.traffic_db, request.headers())?
        .ok_or(AppError::Unauthorized)?;

    let path = request.uri().path();
    let is_websocket = path == "/ws";
    let is_mutation = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if is_websocket || is_mutation {
        validate_origin(request.headers(), &state.public_origin)?;
    }
    if is_mutation {
        validate_csrf(request.headers(), &session.csrf_hash)?;
        if !session.is_admin() && path != "/api/auth/logout" {
            return Err(AppError::Forbidden(
                "viewer sessions cannot modify application state".into(),
            ));
        }
    }

    let now = unix_time();
    let active = if is_websocket {
        state.traffic_db.session_is_active(
            &session.id,
            &session.username,
            &session.role,
            &session.kind,
            now,
        )?
    } else {
        state.traffic_db.touch_session_if_active_throttled(
            &session.id,
            &session.username,
            &session.role,
            &session.kind,
            now,
            HTTP_SESSION_TOUCH_SECS,
        )?
    };
    if !active {
        return Err(AppError::Unauthorized);
    }
    request.extensions_mut().insert(session);
    Ok(next.run(request).await)
}

pub fn revalidate_session(db: &TrafficDb, session: &SessionContext) -> Result<bool, AppError> {
    Ok(db.session_is_active(
        &session.id,
        &session.username,
        &session.role,
        &session.kind,
        unix_time(),
    )?)
}

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, AppError> {
    Ok(Json(AuthStatusResponse {
        setup_required: state.traffic_db.admin()?.is_none(),
        authenticated: authenticate_headers(&state.traffic_db, &headers)?.is_some(),
    }))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connection): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<LoginRequest>,
) -> Result<Response, AppError> {
    let username = login_key_username(&body.username);
    let source = state.auth_security.client_ip(connection.ip(), &headers)?;
    let failure_keys = [
        LoginFailureKey::Username(username.clone()),
        LoginFailureKey::Source(source),
    ];
    if let Some(retry_after_secs) = failure_keys
        .iter()
        .filter_map(|key| {
            state
                .auth_security
                .login_failures
                .retry_after(key, Instant::now())
        })
        .max()
    {
        return Err(AppError::RateLimited { retry_after_secs });
    }

    let admin = state.traffic_db.admin()?;
    let (encoded_hash, username_matches) = password_hash_for_login(
        admin.as_ref(),
        &username,
        &state.auth_security.dummy_password_hash,
    );
    let permit = state.auth_security.acquire_argon2().await?;
    let password_is_bounded = body.password.len() <= 128;
    let password = if password_is_bounded {
        body.password
    } else {
        "invalid-password-input".to_string()
    };
    let (password_matches, attempt_started_at) = verify_login_password(
        state.auth_security.clone(),
        failure_keys.clone(),
        password,
        encoded_hash,
        permit,
    )
    .await?;

    if !username_matches || !password_matches || !password_is_bounded {
        return Err(AppError::Unauthorized);
    }
    let admin = admin.ok_or_else(|| {
        AppError::Internal("administrator record disappeared during authentication".into())
    })?;

    let (session, token, csrf) = new_session(
        &admin.username,
        "admin",
        "standard",
        None,
        STANDARD_ABSOLUTE_SECS,
    );
    if !state
        .traffic_db
        .insert_standard_session_if_admin_version(&session, admin.credential_version)?
    {
        return Err(AppError::Unauthorized);
    }
    for key in &failure_keys {
        state
            .auth_security
            .login_failures
            .clear_if_latest(key, attempt_started_at);
    }
    session_response(&session, &token, &csrf)
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<SessionContext>,
) -> Result<Response, AppError> {
    state.traffic_db.revoke_session(&session.id, unix_time())?;
    let mut headers = HeaderMap::new();
    append_clear_cookies(&mut headers)?;
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

pub async fn me(axum::Extension(session): axum::Extension<SessionContext>) -> Json<MeResponse> {
    Json(me_for(&session))
}

pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<SessionContext>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin_session(&session)?;
    let now = unix_time();
    let sessions: Vec<_> = state
        .traffic_db
        .list_sessions()?
        .into_iter()
        .map(|session| {
            serde_json::json!({
                "id": session.id,
                "username": session.username,
                "role": session.role,
                "session_kind": session.kind,
                "label": session.label,
                "created_at": session.created_at,
                "last_seen_at": session.last_seen_at,
                "expires_at": session.absolute_expires_at,
                "active": session.revoked_at.is_none()
                    && session.absolute_expires_at > now
                    && session.idle_expires_at.is_none_or(|expiry| expiry > now),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "sessions": sessions })))
}

fn require_admin_session(session: &SessionContext) -> Result<(), AppError> {
    if session.is_admin() {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "administrator capability is required".into(),
        ))
    }
}

pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<String>,
) -> Result<StatusCode, AppError> {
    if state.traffic_db.revoke_session(&id, unix_time())? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::InvalidData("unknown or revoked session".into()))
    }
}

pub async fn create_pairing(
    State(state): State<Arc<AppState>>,
    axum::Extension(session): axum::Extension<SessionContext>,
    ApiJson(body): ApiJson<CreatePairingRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let label = body.label.trim();
    if label.is_empty() || label.len() > 80 {
        return Err(AppError::InvalidData(
            "pairing label must contain 1 to 80 characters".into(),
        ));
    }
    if !matches!(body.role.as_str(), "viewer" | "admin") {
        return Err(AppError::InvalidData(
            "pairing role must be viewer or admin".into(),
        ));
    }
    let expected_credential_version = if body.role == "admin" {
        let admin = state.traffic_db.admin()?.ok_or(AppError::Unauthorized)?;
        let password = body.password.ok_or_else(|| {
            AppError::InvalidData("password is required for an admin pairing".into())
        })?;
        if password.len() > 128 {
            return Err(AppError::Unauthorized);
        }
        let permit = state.auth_security.acquire_argon2().await?;
        let verified = verify_password(password, admin.password_hash, permit).await?;
        if !verified {
            return Err(AppError::Unauthorized);
        }
        Some(admin.credential_version)
    } else {
        None
    };

    let code = random_token();
    let now = unix_time();
    let pairing = PairingRecord {
        id: uuid::Uuid::new_v4().to_string(),
        role: body.role,
        label: label.to_string(),
        expires_at: now + PAIRING_SECS,
    };
    let inserted = state.traffic_db.insert_pairing_if_authorized(
        &pairing,
        &hash_token(&code),
        &session.id,
        &session.username,
        &session.role,
        &session.kind,
        now,
        expected_credential_version,
    )?;
    if !inserted {
        return Err(AppError::Unauthorized);
    }
    Ok(Json(serde_json::json!({
        "code": code,
        "expires_at": pairing.expires_at,
        "role": pairing.role,
        "label": pairing.label,
    })))
}

pub async fn pair(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connection): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<PairRequest>,
) -> Result<Response, AppError> {
    let source = state.auth_security.client_ip(connection.ip(), &headers)?;
    let attempt = state
        .auth_security
        .pairing_attempts
        .begin_pairing_attempt(source, Instant::now())
        .map_err(|retry_after_secs| AppError::RateLimited { retry_after_secs })?;
    let code_hash = validated_token_hash(&body.code)?;
    let _pairing_slot = state.auth_security.acquire_pairing_slot()?;
    if !state
        .traffic_db
        .pairing_is_eligible(&code_hash, unix_time())?
    {
        return Err(AppError::Unauthorized);
    }
    let token = random_token();
    let csrf = random_token();
    let session = state
        .traffic_db
        .consume_pairing_and_insert_session(
            &code_hash,
            unix_time(),
            &uuid::Uuid::new_v4().to_string(),
            &hash_token(&token),
            &hash_token(&csrf),
            FIXED_VIEWER_SECS,
            FIXED_ADMIN_SECS,
        )?
        .ok_or(AppError::Unauthorized)?;
    state
        .auth_security
        .pairing_attempts
        .clear_if_latest(&attempt.key, attempt.started_at);
    session_response(&session, &token, &csrf)
}

pub async fn setup(
    State(state): State<Arc<AppState>>,
    ApiJson(body): ApiJson<SetupRequest>,
) -> Result<StatusCode, AppError> {
    if state.traffic_db.admin()?.is_some() {
        return Err(AppError::Conflict(
            "initial setup has already been completed".into(),
        ));
    }
    let username = normalize_username(&body.username)?;
    validate_password(&body.password)?;
    let setup_token_hash = validate_setup_token(&state.traffic_db, &body.token, unix_time())?;
    let permit = state.auth_security.acquire_argon2().await?;
    let password_hash = hash_password(body.password, permit).await?;
    let consumed = state.traffic_db.consume_setup_and_create_admin(
        &setup_token_hash,
        unix_time(),
        &username,
        &password_hash,
    )?;
    if !consumed {
        return Err(AppError::Unauthorized);
    }
    if let Err(error) = remove_setup_token_file(&state.setup_token_path) {
        tracing::error!(%error, "administrator created but setup token cleanup failed");
    }
    Ok(StatusCode::CREATED)
}

pub fn issue_setup_token(db: &TrafficDb, path: &FsPath) -> Result<bool, AppError> {
    if db.admin()?.is_some() {
        remove_setup_token_file(path)?;
        return Ok(false);
    }
    let token = random_token();
    db.store_setup_token(&hash_token(&token), unix_time() + SETUP_SECS)?;
    if let Err(error) = write_setup_token_file(path, &token) {
        if let Err(cleanup_error) = db.store_setup_token(&[], 0) {
            tracing::error!(%cleanup_error, "failed to invalidate setup token after file write failure");
        }
        let _ = remove_setup_token_file(path);
        return Err(error);
    }
    Ok(true)
}

fn write_setup_token_file(path: &FsPath, token: &str) -> Result<(), AppError> {
    let parent = path.parent().ok_or_else(|| {
        AppError::Internal("setup token path must have a parent directory".into())
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::Internal("setup token path must have a valid file name".into()))?;
    let temporary_path = parent.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));

    let write_result = (|| -> Result<(), std::io::Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary_path)?;
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary_path, path)?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(AppError::Internal(format!(
            "failed to write setup token file: {error}"
        )));
    }
    Ok(())
}

pub fn remove_setup_token_file(path: &FsPath) -> Result<(), AppError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AppError::Internal(format!(
            "failed to remove setup token file: {error}"
        ))),
    }
}

pub fn create_admin_from_cli(
    db: &TrafficDb,
    username: &str,
    password: &str,
    replace: bool,
) -> Result<(), AppError> {
    let username = normalize_username(username)?;
    validate_password(password)?;
    let password_hash = hash_password_sync(password)?;
    if replace {
        if db.admin()?.is_none() {
            return Err(AppError::InvalidData(
                "cannot reset an administrator before setup".into(),
            ));
        }
        db.replace_admin_password(&username, &password_hash)?;
    } else {
        db.create_admin(&username, &password_hash)
            .map_err(|error| {
                if matches!(error, rusqlite::Error::SqliteFailure(_, _)) {
                    AppError::Conflict("an administrator already exists".into())
                } else {
                    AppError::Database(error)
                }
            })?;
    }
    Ok(())
}

fn authenticate_headers(
    db: &TrafficDb,
    headers: &HeaderMap,
) -> Result<Option<SessionContext>, AppError> {
    let Some(token) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let Some(session) = db.session_by_token_hash(&hash_token(token))? else {
        return Ok(None);
    };
    let now = unix_time();
    let expired = session.revoked_at.is_some()
        || session.absolute_expires_at <= now
        || session.idle_expires_at.is_some_and(|expiry| expiry <= now);
    if expired {
        if session.revoked_at.is_none() {
            let _ = db.revoke_session(&session.id, now);
        }
        return Ok(None);
    }
    Ok(Some(SessionContext {
        id: session.id,
        username: session.username,
        role: session.role,
        kind: session.kind,
        csrf_hash: session.csrf_hash,
    }))
}

fn validate_origin(headers: &HeaderMap, public_origin: &str) -> Result<(), AppError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Forbidden("missing Origin header".into()))?;
    if origin != public_origin {
        return Err(AppError::Forbidden("request origin is not allowed".into()));
    }
    Ok(())
}

fn validate_csrf(headers: &HeaderMap, expected_hash: &[u8]) -> Result<(), AppError> {
    let mut header_values = headers.get_all("x-csrf-token").iter();
    let header_token = header_values
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Forbidden("missing CSRF token".into()))?;
    if header_values.next().is_some() {
        return Err(AppError::Forbidden("invalid CSRF token".into()));
    }

    let mut cookie_tokens = cookie_values(headers, CSRF_COOKIE);
    let cookie_token = cookie_tokens
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Forbidden("missing CSRF cookie".into()))?;
    if cookie_tokens.next().is_some() {
        return Err(AppError::Forbidden("invalid CSRF token".into()));
    }

    let header_hash = hash_token(header_token);
    let cookie_hash = hash_token(cookie_token);
    if !constant_time_eq(&header_hash, &cookie_hash)
        || !constant_time_eq(&header_hash, expected_hash)
    {
        return Err(AppError::Forbidden("invalid CSRF token".into()));
    }
    Ok(())
}

fn new_session(
    username: &str,
    role: &str,
    kind: &str,
    label: Option<String>,
    lifetime: i64,
) -> (AuthSessionRecord, String, String) {
    let token = random_token();
    let csrf = random_token();
    let now = unix_time();
    (
        AuthSessionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            token_hash: hash_token(&token),
            csrf_hash: hash_token(&csrf),
            username: username.to_string(),
            role: role.to_string(),
            kind: kind.to_string(),
            label,
            created_at: now,
            last_seen_at: now,
            idle_expires_at: (kind == "standard").then_some(now + STANDARD_IDLE_SECS),
            absolute_expires_at: now + lifetime,
            revoked_at: None,
        },
        token,
        csrf,
    )
}

fn session_response(
    session: &AuthSessionRecord,
    token: &str,
    csrf: &str,
) -> Result<Response, AppError> {
    let mut headers = HeaderMap::new();
    let max_age = session.absolute_expires_at.saturating_sub(unix_time());
    append_cookie(
        &mut headers,
        &format!(
            "{SESSION_COOKIE}={token}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"
        ),
    )?;
    append_cookie(
        &mut headers,
        &format!("{CSRF_COOKIE}={csrf}; Path=/; Max-Age={max_age}; Secure; SameSite=Strict"),
    )?;
    let context = SessionContext {
        id: session.id.clone(),
        username: session.username.clone(),
        role: session.role.clone(),
        kind: session.kind.clone(),
        csrf_hash: session.csrf_hash.clone(),
    };
    Ok((headers, Json(me_for(&context))).into_response())
}

fn me_for(session: &SessionContext) -> MeResponse {
    let capabilities = if session.is_admin() {
        vec!["read", "configure", "manage_devices", "manage_sessions"]
    } else {
        vec!["read"]
    };
    MeResponse {
        username: session.username.clone(),
        role: session.role.clone(),
        session_kind: session.kind.clone(),
        capabilities,
    }
}

fn append_clear_cookies(headers: &mut HeaderMap) -> Result<(), AppError> {
    append_cookie(
        headers,
        &format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"),
    )?;
    append_cookie(
        headers,
        &format!("{CSRF_COOKIE}=; Path=/; Max-Age=0; Secure; SameSite=Strict"),
    )
}

fn append_cookie(headers: &mut HeaderMap, value: &str) -> Result<(), AppError> {
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(value)
            .map_err(|_| AppError::Internal("failed to create session cookie".into()))?,
    );
    Ok(())
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &'a str) -> Option<&'a str> {
    cookie_values(headers, name).next()
}

fn cookie_values<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .filter_map(move |(key, value)| (key == name).then_some(value))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
}

fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxy_cidrs: &[IpNet],
) -> Result<IpAddr, AppError> {
    let peer = normalize_ip(peer);
    if !trusted_proxy_cidrs
        .iter()
        .any(|network| network.contains(&peer))
    {
        return Ok(peer);
    }

    let mut forwarded_values = headers.get_all(CLIENT_IP_HEADER).iter();
    let forwarded = forwarded_values
        .next()
        .ok_or_else(invalid_proxy_client_ip)?;
    if forwarded_values.next().is_some() {
        return Err(invalid_proxy_client_ip());
    }
    let forwarded = forwarded.to_str().map_err(|_| invalid_proxy_client_ip())?;
    if forwarded.is_empty() || forwarded.trim() != forwarded || forwarded.contains(',') {
        return Err(invalid_proxy_client_ip());
    }
    forwarded
        .parse::<IpAddr>()
        .map(normalize_ip)
        .map_err(|_| invalid_proxy_client_ip())
}

fn invalid_proxy_client_ip() -> AppError {
    AppError::Forbidden("trusted proxy supplied an invalid client address".into())
}

fn normalize_ip(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        source => source,
    }
}

fn login_key_username(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() <= 64
        && normalized.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        normalized
    } else {
        let digest = Sha256::digest(normalized.as_bytes());
        format!(
            "invalid:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        )
    }
}

fn password_hash_for_login(
    admin: Option<&AdminRecord>,
    username: &str,
    dummy_password_hash: &str,
) -> (String, bool) {
    match admin {
        Some(admin) if constant_time_eq(admin.username.as_bytes(), username.as_bytes()) => {
            (admin.password_hash.clone(), true)
        }
        _ => (dummy_password_hash.to_string(), false),
    }
}

fn argon2() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(64 * 1024, 3, 1, None)
        .map_err(|_| AppError::Internal("invalid password hashing parameters".into()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_password_sync(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut PasswordOsRng);
    argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AppError::Internal("password hashing failed".into()))
}

async fn run_argon2_task<T, F>(
    permit: OwnedSemaphorePermit,
    failure_message: &'static str,
    task: F,
) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        task()
    })
    .await
    .map_err(|_| AppError::Internal(failure_message.into()))?
}

async fn hash_password(password: String, permit: OwnedSemaphorePermit) -> Result<String, AppError> {
    run_argon2_task(permit, "password hashing task failed", move || {
        hash_password_sync(&password)
    })
    .await
}

async fn verify_password(
    password: String,
    encoded: String,
    permit: OwnedSemaphorePermit,
) -> Result<bool, AppError> {
    run_argon2_task(permit, "password verification task failed", move || {
        verify_password_sync(&password, &encoded)
    })
    .await
}

async fn verify_login_password(
    security: Arc<AuthSecurity>,
    failure_keys: [LoginFailureKey; 2],
    password: String,
    encoded: String,
    permit: OwnedSemaphorePermit,
) -> Result<(bool, Instant), AppError> {
    run_login_argon2_task(
        security,
        failure_keys,
        permit,
        "password verification task failed",
        move || verify_password_sync(&password, &encoded),
    )
    .await
}

async fn run_login_argon2_task<T, F>(
    security: Arc<AuthSecurity>,
    failure_keys: [LoginFailureKey; 2],
    permit: OwnedSemaphorePermit,
    failure_message: &'static str,
    task: F,
) -> Result<(T, Instant), AppError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
{
    // This closure outlives request cancellation, so attempts that consumed
    // Argon2 work remain counted unless the handler creates a session.
    run_argon2_task(permit, failure_message, move || {
        let started_at = Instant::now();
        for key in failure_keys {
            security.login_failures.record_failure(key, started_at);
        }
        task().map(|result| (result, started_at))
    })
    .await
}

fn verify_password_sync(password: &str, encoded: &str) -> Result<bool, AppError> {
    let parsed = PasswordHash::new(encoded)
        .map_err(|_| AppError::Internal("stored password hash is invalid".into()))?;
    Ok(argon2()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn validated_token_hash(token: &str) -> Result<Vec<u8>, AppError> {
    let token = token.trim();
    if token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AppError::Unauthorized);
    }
    Ok(hash_token(token))
}

fn validate_setup_token(db: &TrafficDb, token: &str, now: i64) -> Result<Vec<u8>, AppError> {
    let token_hash = validated_token_hash(token)?;
    if !db.setup_token_is_valid(&token_hash, now)? {
        return Err(AppError::Unauthorized);
    }
    Ok(token_hash)
}

fn normalize_username(value: &str) -> Result<String, AppError> {
    let value = value.trim().to_ascii_lowercase();
    if !(3..=64).contains(&value.len())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
    {
        return Err(AppError::InvalidData(
            "username must be 3 to 64 lowercase ASCII letters, digits, '.', '_' or '-'".into(),
        ));
    }
    Ok(value)
}

fn validate_password(value: &str) -> Result<(), AppError> {
    if !(12..=128).contains(&value.len()) {
        return Err(AppError::InvalidData(
            "password must be 12 to 128 UTF-8 bytes".into(),
        ));
    }
    Ok(())
}

fn unix_time() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_key(username: &str) -> LoginFailureKey {
        LoginFailureKey::Username(username.to_string())
    }

    fn test_auth_security(argon2_slots: usize) -> Arc<AuthSecurity> {
        Arc::new(AuthSecurity {
            argon2_slots: Arc::new(Semaphore::new(argon2_slots)),
            pairing_slots: Arc::new(Semaphore::new(PAIRING_CONCURRENCY)),
            dummy_password_hash: String::new(),
            login_failures: FailureLimiter::default(),
            pairing_attempts: FailureLimiter::default(),
            trusted_proxy_cidrs: Vec::new(),
        })
    }

    #[test]
    fn validates_admin_identifiers() {
        assert_eq!(normalize_username(" Admin.User ").unwrap(), "admin.user");
        assert!(normalize_username("no spaces").is_err());
        assert!(validate_password("short").is_err());
        assert!(validate_password("a sufficiently long password").is_ok());
    }

    #[test]
    fn cookies_are_parsed_by_exact_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; __Host-routerview_session=abc123"),
        );
        assert_eq!(cookie_value(&headers, SESSION_COOKIE), Some("abc123"));
    }

    #[test]
    fn csrf_requires_one_matching_header_and_cookie() {
        let token = "csrf-token";
        let expected_hash = hash_token(token);
        let mut valid = HeaderMap::new();
        valid.insert("x-csrf-token", HeaderValue::from_static(token));
        valid.insert(
            header::COOKIE,
            HeaderValue::from_static("other=x; __Host-routerview_csrf=csrf-token"),
        );
        assert!(validate_csrf(&valid, &expected_hash).is_ok());

        let mut missing_header = HeaderMap::new();
        missing_header.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-routerview_csrf=csrf-token"),
        );
        assert!(validate_csrf(&missing_header, &expected_hash).is_err());

        let mut missing_cookie = HeaderMap::new();
        missing_cookie.insert("x-csrf-token", HeaderValue::from_static(token));
        assert!(validate_csrf(&missing_cookie, &expected_hash).is_err());

        let mut mismatch = valid.clone();
        mismatch.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-routerview_csrf=different"),
        );
        assert!(validate_csrf(&mismatch, &expected_hash).is_err());

        let mut repeated_header = valid.clone();
        repeated_header.append("x-csrf-token", HeaderValue::from_static(token));
        assert!(validate_csrf(&repeated_header, &expected_hash).is_err());

        let mut repeated_cookie = valid;
        repeated_cookie.insert(
            header::COOKIE,
            HeaderValue::from_static(
                "__Host-routerview_csrf=csrf-token; __Host-routerview_csrf=csrf-token",
            ),
        );
        assert!(validate_csrf(&repeated_cookie, &expected_hash).is_err());
    }

    #[test]
    fn login_failures_back_off_and_remain_bounded() {
        let limiter = FailureLimiter::default();
        let now = Instant::now();
        let key = login_key("admin");

        assert_eq!(limiter.retry_after(&key, now), None);
        assert_eq!(limiter.record_failure(key.clone(), now), 1);
        assert_eq!(limiter.retry_after(&key, now), Some(1));
        assert_eq!(
            limiter.record_failure(key.clone(), now + Duration::from_secs(1)),
            2
        );
        assert_eq!(
            limiter.retry_after(&key, now + Duration::from_secs(1)),
            Some(2)
        );

        for index in 0..(AUTH_FAILURE_CAPACITY + 25) {
            limiter.record_failure(login_key(&format!("user-{index}")), now);
        }
        assert_eq!(
            limiter
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            AUTH_FAILURE_CAPACITY
        );
    }

    #[test]
    fn source_backoff_cannot_be_bypassed_by_rotating_usernames() {
        let limiter = FailureLimiter::default();
        let now = Instant::now();
        let source = LoginFailureKey::Source("192.0.2.10".parse().unwrap());
        limiter.record_failure(source.clone(), now);
        assert_eq!(limiter.retry_after(&source, now), Some(1));
    }

    #[test]
    fn successful_attempt_does_not_clear_a_newer_failure() {
        let limiter = FailureLimiter::default();
        let key = login_key("admin");
        let first = Instant::now();
        let newer = first + Duration::from_millis(1);
        limiter.record_failure(key.clone(), first);
        limiter.record_failure(key.clone(), newer);

        limiter.clear_if_latest(&key, first);
        assert!(limiter.retry_after(&key, newer).is_some());

        limiter.clear_if_latest(&key, newer);
        assert!(limiter.retry_after(&key, newer).is_none());
    }

    #[test]
    fn pairing_code_validation_accepts_generated_tokens() {
        let token = random_token();
        assert_eq!(validated_token_hash(&token).unwrap(), hash_token(&token));
        assert_eq!(
            validated_token_hash(&format!(" \t{token}\n")).unwrap(),
            hash_token(&token)
        );
    }

    #[test]
    fn pairing_code_validation_rejects_invalid_shapes() {
        let token = random_token();
        let invalid = [
            String::new(),
            token[..42].to_string(),
            format!("{token}A"),
            format!("{}+", &token[..42]),
            format!("{}/", &token[..42]),
            format!("{}=", &token[..42]),
            format!("{} {}", &token[..21], &token[22..]),
            format!("é{}", &token[2..]),
        ];
        for code in invalid {
            assert!(matches!(
                validated_token_hash(&code),
                Err(AppError::Unauthorized)
            ));
        }
    }

    #[test]
    fn pairing_attempts_back_off_per_source() {
        let limiter = FailureLimiter::default();
        let now = Instant::now();
        let first_source: IpAddr = "192.0.2.10".parse().unwrap();
        let second_source: IpAddr = "192.0.2.11".parse().unwrap();

        let first = limiter.begin_pairing_attempt(first_source, now).unwrap();
        assert_eq!(first.key, PairingFailureKey::Source(first_source));
        assert_eq!(first.started_at, now);
        assert_eq!(limiter.begin_pairing_attempt(first_source, now), Err(1));
        assert!(limiter.begin_pairing_attempt(second_source, now).is_ok());

        let next = now + Duration::from_secs(1);
        assert!(limiter.begin_pairing_attempt(first_source, next).is_ok());
        assert_eq!(limiter.begin_pairing_attempt(first_source, next), Err(2));
    }

    #[test]
    fn pairing_attempt_state_expires_and_remains_bounded() {
        let limiter = FailureLimiter::default();
        let now = Instant::now();
        let source: IpAddr = "192.0.2.10".parse().unwrap();
        limiter.begin_pairing_attempt(source, now).unwrap();

        let after_ttl = now + AUTH_FAILURE_TTL;
        assert_eq!(
            limiter
                .begin_pairing_attempt(source, after_ttl)
                .unwrap()
                .started_at,
            after_ttl
        );
        assert_eq!(
            limiter
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(&PairingFailureKey::Source(source))
                .map(|state| state.failures),
            Some(1)
        );

        for index in 0..(AUTH_FAILURE_CAPACITY - 1) {
            let source = IpAddr::V6(std::net::Ipv6Addr::from(index as u128 + 1));
            limiter.begin_pairing_attempt(source, after_ttl).unwrap();
        }
        let overflow_source = IpAddr::V6(std::net::Ipv6Addr::from(u128::MAX));
        let overflow = limiter
            .begin_pairing_attempt(overflow_source, after_ttl)
            .unwrap();
        assert_eq!(overflow.key, PairingFailureKey::Overflow);
        assert_eq!(
            limiter.begin_pairing_attempt(
                IpAddr::V6(std::net::Ipv6Addr::from(u128::MAX - 1)),
                after_ttl,
            ),
            Err(1)
        );
        let entries = limiter
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(entries.len(), AUTH_FAILURE_CAPACITY + 1);
        assert!(entries.contains_key(&PairingFailureKey::Source(source)));
    }

    #[test]
    fn pairing_attempt_check_and_record_is_atomic() {
        let limiter = Arc::new(FailureLimiter::default());
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let source: IpAddr = "192.0.2.10".parse().unwrap();
        let now = Instant::now();
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let limiter = limiter.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    limiter.begin_pairing_attempt(source, now)
                })
            })
            .collect();

        assert_eq!(
            attempts
                .into_iter()
                .map(|attempt| attempt.join().unwrap())
                .filter(Result::is_ok)
                .count(),
            1
        );
    }

    #[test]
    fn successful_pairing_does_not_clear_a_newer_attempt() {
        let limiter = FailureLimiter::default();
        let source: IpAddr = "192.0.2.10".parse().unwrap();
        let first = limiter
            .begin_pairing_attempt(source, Instant::now())
            .unwrap();
        let newer_at = first.started_at + Duration::from_secs(1);
        let newer = limiter.begin_pairing_attempt(source, newer_at).unwrap();

        limiter.clear_if_latest(&first.key, first.started_at);
        assert_eq!(limiter.retry_after(&newer.key, newer_at), Some(2));

        limiter.clear_if_latest(&newer.key, newer.started_at);
        assert_eq!(limiter.retry_after(&newer.key, newer_at), None);
    }

    #[test]
    fn direct_clients_cannot_spoof_forwarded_addresses() {
        let peer = "192.0.2.10".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_IP_HEADER, HeaderValue::from_static("198.51.100.25"));

        assert_eq!(resolve_client_ip(peer, &headers, &[]).unwrap(), peer);
        assert_eq!(
            resolve_client_ip(peer, &headers, &["10.0.0.0/8".parse::<IpNet>().unwrap()]).unwrap(),
            peer
        );
    }

    #[test]
    fn trusted_proxy_requires_one_bare_client_address() {
        let peer = "::ffff:172.31.254.2".parse().unwrap();
        let trusted = ["172.31.254.2/32".parse::<IpNet>().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(CLIENT_IP_HEADER, HeaderValue::from_static("198.51.100.25"));
        assert_eq!(
            resolve_client_ip(peer, &headers, &trusted).unwrap(),
            "198.51.100.25".parse::<IpAddr>().unwrap()
        );

        let mut missing = HeaderMap::new();
        assert!(resolve_client_ip(peer, &missing, &trusted).is_err());

        missing.insert(
            CLIENT_IP_HEADER,
            HeaderValue::from_static("198.51.100.25, 203.0.113.8"),
        );
        assert!(resolve_client_ip(peer, &missing, &trusted).is_err());

        let mut repeated = headers;
        repeated.append(CLIENT_IP_HEADER, HeaderValue::from_static("203.0.113.8"));
        assert!(resolve_client_ip(peer, &repeated, &trusted).is_err());
    }

    #[test]
    fn unknown_username_selects_the_dummy_hash() {
        let admin = AdminRecord {
            username: "admin".into(),
            password_hash: "real-hash".into(),
            credential_version: 1,
        };
        assert_eq!(
            password_hash_for_login(Some(&admin), "unknown", "dummy-hash"),
            ("dummy-hash".into(), false)
        );
        assert_eq!(
            password_hash_for_login(Some(&admin), "admin", "dummy-hash"),
            ("real-hash".into(), true)
        );
    }

    #[tokio::test]
    async fn argon2_gate_waits_fairly_and_bounds_queue_time() {
        let security = test_auth_security(ARGON2_CONCURRENCY);
        let first = security.acquire_argon2().await.unwrap();
        let second = security.acquire_argon2().await.unwrap();
        let waiting_security = security.clone();
        let waiter = tokio::spawn(async move { waiting_security.acquire_argon2().await });
        tokio::task::yield_now().await;
        drop(first);
        let third = waiter.await.unwrap().unwrap();

        let started = Instant::now();
        assert!(matches!(
            security.acquire_argon2().await,
            Err(AppError::RateLimited {
                retry_after_secs: 1
            })
        ));
        assert!(started.elapsed() >= ARGON2_WAIT_TIMEOUT);
        drop((second, third));
        assert!(security.acquire_argon2().await.is_ok());
    }

    #[test]
    fn pairing_gate_rejects_parallel_database_work_without_queueing() {
        let security = test_auth_security(ARGON2_CONCURRENCY);
        let first = security.acquire_pairing_slot().unwrap();
        assert!(matches!(
            security.acquire_pairing_slot(),
            Err(AppError::RateLimited {
                retry_after_secs: 1
            })
        ));

        drop(first);
        assert!(security.acquire_pairing_slot().is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_does_not_release_running_argon2_permit() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.clone().acquire_owned().await.unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let waiter = tokio::spawn(run_argon2_task(
            permit,
            "test password task failed",
            move || {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                Ok(())
            },
        ));
        started_rx.await.unwrap();
        waiter.abort();
        let _ = waiter.await;

        assert!(slots.clone().try_acquire_owned().is_err());
        release_tx.send(()).unwrap();
        let reacquired = tokio::time::timeout(Duration::from_secs(1), slots.acquire_owned())
            .await
            .unwrap()
            .unwrap();
        drop(reacquired);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_login_remains_counted_after_verification_starts() {
        let security = test_auth_security(1);
        let permit = security.acquire_argon2().await.unwrap();
        let username = LoginFailureKey::Username("admin".into());
        let source = LoginFailureKey::Source("192.0.2.10".parse().unwrap());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let verifier = tokio::spawn(run_login_argon2_task(
            security.clone(),
            [username.clone(), source.clone()],
            permit,
            "test password task failed",
            move || {
                let _ = started_tx.send(());
                release_rx.recv().unwrap();
                Ok(true)
            },
        ));
        started_rx.await.unwrap();

        {
            let entries = security
                .login_failures
                .entries
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            assert_eq!(entries.get(&username).map(|state| state.failures), Some(1));
            assert_eq!(entries.get(&source).map(|state| state.failures), Some(1));
        }
        verifier.abort();
        let _ = verifier.await;
        assert!(security
            .login_failures
            .entries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains_key(&username));

        release_tx.send(()).unwrap();
        let reacquired = tokio::time::timeout(
            Duration::from_secs(1),
            security.argon2_slots.clone().acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(reacquired);
    }

    #[test]
    fn setup_token_is_prechecked_and_atomically_rechecked() {
        let database = TrafficDb::open(FsPath::new(":memory:")).unwrap();
        let token = random_token();
        let token_hash = hash_token(&token);
        let now = unix_time();
        database.store_setup_token(&token_hash, now + 60).unwrap();

        assert!(matches!(
            validate_setup_token(&database, "not-a-token", now),
            Err(AppError::Unauthorized)
        ));
        assert_eq!(
            validate_setup_token(&database, &token, now).unwrap(),
            token_hash
        );
        assert!(database
            .consume_setup_and_create_admin(&token_hash, now, "admin", "hash")
            .unwrap());
        assert!(matches!(
            validate_setup_token(&database, &token, now),
            Err(AppError::Unauthorized)
        ));
        assert!(!database
            .consume_setup_and_create_admin(&token_hash, now, "admin", "other-hash")
            .unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn setup_token_file_is_private_and_removable() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "routerview-setup-token-test-{}",
            uuid::Uuid::new_v4()
        ));
        write_setup_token_file(&path, "one-time-secret").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one-time-secret\n");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        remove_setup_token_file(&path).unwrap();
        assert!(!path.exists());
        remove_setup_token_file(&path).unwrap();
    }

    #[test]
    fn setup_token_publication_failure_invalidates_database_token() {
        let directory = std::env::temp_dir().join(format!(
            "routerview-setup-token-rollback-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database_path = directory.join("routerview.db");
        let database = TrafficDb::open(&database_path).unwrap();
        let unavailable_path = directory.join("missing-parent/setup-token");

        assert!(issue_setup_token(&database, &unavailable_path).is_err());

        let verification = rusqlite::Connection::open(&database_path).unwrap();
        let stored: (i64, i64) = verification
            .query_row(
                "SELECT length(token_hash), expires_at FROM setup_tokens WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, (0, 0));
        assert!(!unavailable_path.exists());

        drop(verification);
        drop(database);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn password_hash_uses_argon2id_and_verifies() {
        let hash = hash_password_sync("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        let parsed = PasswordHash::new(&hash).unwrap();
        assert!(argon2()
            .unwrap()
            .verify_password(b"correct horse battery staple", &parsed)
            .is_ok());
    }

    #[test]
    fn viewer_cannot_use_administrator_capabilities() {
        let viewer = SessionContext {
            id: "viewer-session".into(),
            username: "admin".into(),
            role: "viewer".into(),
            kind: "fixed".into(),
            csrf_hash: vec![0; 32],
        };
        assert!(matches!(
            require_admin_session(&viewer),
            Err(AppError::Forbidden(_))
        ));
    }
}
