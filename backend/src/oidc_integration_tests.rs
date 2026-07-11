use super::*;

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock, RwLock as StdRwLock,
    },
    time::Duration,
};

use axum::extract::{ConnectInfo, RawQuery, State};
use openidconnect::{
    core::{
        CoreEdDsaPrivateSigningKey, CoreGenderClaim, CoreJsonWebKeySet,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    },
    AccessToken, Audience, EndUserName, EndUserUsername, IdToken, IdTokenClaims, IssuerUrl,
    JsonWebKeyId, LocalizedClaim, Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use rcgen::{generate_simple_self_signed, CertifiedKey, KeyPair, PKCS_ED25519};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    rustls::{
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

use crate::{
    auth::AuthSecurity,
    backends::RouterType,
    config_store::MergedConfig,
    db::TrafficDb,
    poller::engine::PollEngine,
    secrets::SecretCipher,
    state::AppState,
    ws::{
        limits::{
            WsConnectionLimiter, MAX_CONNECTIONS_GLOBAL, MAX_CONNECTIONS_PER_SESSION,
            MAX_CONNECTIONS_PER_SOURCE,
        },
        protocol::{DashboardSnapshot, ServerMessage},
        tracker::WsSessionTracker,
    },
};

type TestIdToken = IdToken<
    DynamicClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type TestIdTokenClaims = IdTokenClaims<DynamicClaims, CoreGenderClaim>;

#[derive(Clone, Copy)]
enum TokenAuthMethod {
    Basic,
    Post,
}

impl TokenAuthMethod {
    fn metadata_value(self) -> &'static str {
        match self {
            Self::Basic => "client_secret_basic",
            Self::Post => "client_secret_post",
        }
    }
}

#[derive(Clone)]
struct MockReply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    delay: Duration,
}

impl MockReply {
    fn json(value: serde_json::Value) -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            body: serde_json::to_vec(&value).expect("serialize mock OIDC response"),
            delay: Duration::ZERO,
        }
    }

    fn error(status: u16, marker: &str) -> Self {
        Self::json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": marker,
        }))
        .with_status(status)
    }

    fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

struct MockOidcState {
    issuer: String,
    auth_method: TokenAuthMethod,
    requests: Mutex<Vec<RecordedRequest>>,
    token_reply: Mutex<MockReply>,
    userinfo_reply: Mutex<MockReply>,
    jwks: StdRwLock<Vec<Vec<u8>>>,
    jwks_hits: AtomicUsize,
}

impl MockOidcState {
    fn requests_for(&self, path: &str) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .filter(|request| request.path == path)
            .cloned()
            .collect()
    }

    fn clear_requests(&self) {
        self.requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
    }

    fn set_token_reply(&self, reply: MockReply) {
        *self
            .token_reply
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = reply;
    }

    fn set_userinfo_reply(&self, reply: MockReply) {
        *self
            .userinfo_reply
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = reply;
    }

    fn response_for(&self, request: &RecordedRequest) -> MockReply {
        match request.path.as_str() {
            "/.well-known/openid-configuration" => MockReply::json(serde_json::json!({
                "issuer": self.issuer,
                "authorization_endpoint": format!("{}/authorize", self.issuer),
                "token_endpoint": format!("{}/token", self.issuer),
                "userinfo_endpoint": format!("{}/userinfo", self.issuer),
                "jwks_uri": format!("{}/jwks", self.issuer),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["EdDSA"],
                "token_endpoint_auth_methods_supported": [self.auth_method.metadata_value()],
            })),
            "/jwks" => {
                let index = self.jwks_hits.fetch_add(1, Ordering::SeqCst);
                let jwks = self.jwks.read().unwrap_or_else(|error| error.into_inner());
                let body = jwks
                    .get(index)
                    .or_else(|| jwks.last())
                    .cloned()
                    .unwrap_or_else(|| br#"{"keys":[]}"#.to_vec());
                MockReply {
                    status: 200,
                    content_type: "application/jwk-set+json",
                    body,
                    delay: Duration::ZERO,
                }
            }
            "/token" => self
                .token_reply
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
            "/userinfo" => self
                .userinfo_reply
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
            _ => MockReply::error(404, "unknown mock endpoint"),
        }
    }
}

struct MockOidcServer {
    issuer: String,
    ca_pem: Vec<u8>,
    state: Arc<MockOidcState>,
    task: tokio::task::JoinHandle<()>,
}

impl MockOidcServer {
    async fn start(auth_method: TokenAuthMethod, jwks: Vec<Vec<u8>>) -> Self {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate test TLS certificate");
        let ca_pem = cert.pem().into_bytes();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .expect("construct test TLS server config");
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test OIDC provider");
        let issuer = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let state = Arc::new(MockOidcState {
            issuer: issuer.clone(),
            auth_method,
            requests: Mutex::new(Vec::new()),
            token_reply: Mutex::new(MockReply::error(500, "token reply not configured")),
            userinfo_reply: Mutex::new(MockReply::error(500, "userinfo reply not configured")),
            jwks: StdRwLock::new(jwks),
            jwks_hits: AtomicUsize::new(0),
        });
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let state = server_state.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    state
                        .requests
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .push(request.clone());
                    let response = state.response_for(&request);
                    if !response.delay.is_zero() {
                        tokio::time::sleep(response.delay).await;
                    }
                    let reason = match response.status {
                        200 => "OK",
                        400 => "Bad Request",
                        404 => "Not Found",
                        500 => "Internal Server Error",
                        _ => "Error",
                    };
                    let head = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.status,
                        response.content_type,
                        response.body.len(),
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&response.body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            issuer,
            ca_pem,
            state,
            task,
        }
    }
}

impl Drop for MockOidcServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request<S>(stream: &mut S) -> Option<RecordedRequest>
where
    S: tokio::io::AsyncRead + Unpin,
{
    const MAX_REQUEST_BYTES: usize = 64 * 1024;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 || bytes.len().saturating_add(read) > MAX_REQUEST_BYTES {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':')?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if header_end.saturating_add(content_length) > MAX_REQUEST_BYTES {
        return None;
    }
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 || bytes.len().saturating_add(read) > MAX_REQUEST_BYTES {
            return None;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Some(RecordedRequest {
        method,
        path,
        headers,
        body: String::from_utf8(bytes[header_end..header_end + content_length].to_vec()).ok()?,
    })
}

struct SigningKeys {
    primary: CoreEdDsaPrivateSigningKey,
    secondary: CoreEdDsaPrivateSigningKey,
    primary_jwks: Vec<u8>,
    secondary_jwks: Vec<u8>,
}

fn signing_keys() -> &'static SigningKeys {
    static KEYS: OnceLock<SigningKeys> = OnceLock::new();
    KEYS.get_or_init(SigningKeys::new)
}

impl SigningKeys {
    fn new() -> Self {
        let primary = generate_signing_key("primary-key");
        let secondary = generate_signing_key("secondary-key");
        let primary_jwks =
            serde_json::to_vec(&CoreJsonWebKeySet::new(vec![primary.as_verification_key()]))
                .unwrap();
        let secondary_jwks = serde_json::to_vec(&CoreJsonWebKeySet::new(vec![
            secondary.as_verification_key()
        ]))
        .unwrap();
        Self {
            primary,
            secondary,
            primary_jwks,
            secondary_jwks,
        }
    }
}

fn generate_signing_key(kid: &str) -> CoreEdDsaPrivateSigningKey {
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("generate test Ed25519 key");
    CoreEdDsaPrivateSigningKey::from_ed25519_pem(
        &key.serialize_pem(),
        Some(JsonWebKeyId::new(kid.to_string())),
    )
    .expect("load test Ed25519 key")
}

fn config_for(server: &MockOidcServer) -> OidcConfig {
    OidcConfig {
        issuer_url: server.issuer.clone(),
        client_id: "routerview-client".into(),
        client_secret: "routerview-secret".into(),
        provider_name: "Test Identity".into(),
        groups_claim: "groups".into(),
        viewer_group: "routerview-viewers".into(),
        admin_group: "routerview-admins".into(),
        additional_scopes: vec!["groups".into()],
        ca_pem: Some(server.ca_pem.clone()),
        redirect_url: "https://routerview.test/api/auth/oidc/callback".into(),
    }
}

async fn discovered_manager(server: &MockOidcServer) -> OidcManager {
    let manager = OidcManager::new(Some(config_for(server))).expect("construct OIDC manager");
    let provider = manager
        .discover()
        .await
        .expect("discover test OIDC provider");
    *manager.provider.write().await = Some(provider);
    manager
}

fn signed_id_token(
    server: &MockOidcServer,
    nonce: &str,
    groups: Option<Vec<&str>>,
    signing_key: &CoreEdDsaPrivateSigningKey,
) -> TestIdToken {
    let mut spec = IdTokenSpec::valid(server, nonce, signing_key);
    spec.groups = groups.map(|groups| serde_json::json!(groups));
    signed_id_token_with(spec)
}

struct IdTokenSpec<'a> {
    issuer: String,
    audience: String,
    expiration: chrono::DateTime<chrono::Utc>,
    nonce: Option<String>,
    subject: String,
    groups: Option<Value>,
    preferred_username: Option<String>,
    display_name: Option<String>,
    signing_key: &'a CoreEdDsaPrivateSigningKey,
    hash_access_token: Option<String>,
}

impl<'a> IdTokenSpec<'a> {
    fn valid(
        server: &MockOidcServer,
        nonce: &str,
        signing_key: &'a CoreEdDsaPrivateSigningKey,
    ) -> Self {
        Self {
            issuer: server.issuer.clone(),
            audience: "routerview-client".into(),
            expiration: chrono::Utc::now() + chrono::Duration::minutes(5),
            nonce: Some(nonce.to_string()),
            subject: "subject-123".into(),
            groups: Some(serde_json::json!(["routerview-viewers"])),
            preferred_username: Some("alice".into()),
            display_name: None,
            signing_key,
            hash_access_token: Some("access-token".into()),
        }
    }
}

fn signed_id_token_with(spec: IdTokenSpec<'_>) -> TestIdToken {
    let mut values = HashMap::new();
    if let Some(groups) = spec.groups {
        values.insert("groups".into(), groups);
    }
    let mut standard_claims =
        StandardClaims::<CoreGenderClaim>::new(SubjectIdentifier::new(spec.subject));
    if let Some(username) = spec.preferred_username {
        standard_claims =
            standard_claims.set_preferred_username(Some(EndUserUsername::new(username)));
    }
    if let Some(display_name) = spec.display_name {
        standard_claims =
            standard_claims.set_name(Some(LocalizedClaim::from(EndUserName::new(display_name))));
    }
    let claims = TestIdTokenClaims::new(
        IssuerUrl::new(spec.issuer).unwrap(),
        vec![Audience::new(spec.audience)],
        spec.expiration,
        chrono::Utc::now(),
        standard_claims,
        DynamicClaims { values },
    );
    let claims = match spec.nonce {
        Some(nonce) => claims.set_nonce(Some(Nonce::new(nonce))),
        None => claims,
    };
    let hash_access_token = spec.hash_access_token.map(AccessToken::new);
    TestIdToken::new(
        claims,
        spec.signing_key,
        CoreJwsSigningAlgorithm::EdDsa,
        hash_access_token.as_ref(),
        None,
    )
    .expect("sign test ID token")
}

fn token_reply(id_token: &TestIdToken) -> MockReply {
    MockReply::json(serde_json::json!({
        "access_token": "access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": serde_json::to_value(id_token).unwrap(),
    }))
}

fn form_fields(request: &RecordedRequest) -> HashMap<String, String> {
    url::form_urlencoded::parse(request.body.as_bytes())
        .into_owned()
        .collect()
}

fn test_merged_config() -> MergedConfig {
    MergedConfig {
        revision: 0,
        router_type: RouterType::RouterOs,
        router_host: "192.168.88.1".into(),
        router_port: 443,
        router_scheme: "https".into(),
        router_username: "admin".into(),
        router_password: String::new(),
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

async fn test_app_state(oidc: Arc<OidcManager>) -> Arc<AppState> {
    let traffic_db = Arc::new(TrafficDb::open(&PathBuf::from(":memory:")).unwrap());
    traffic_db
        .create_admin("local-admin", "unused-test-password-hash")
        .unwrap();
    let instance_id = traffic_db.instance_id().unwrap();
    let config = Arc::new(tokio::sync::RwLock::new(test_merged_config()));
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<Arc<ServerMessage>>(8);
    let last_snapshot: Arc<tokio::sync::RwLock<Option<Arc<DashboardSnapshot>>>> =
        Arc::new(tokio::sync::RwLock::new(None));
    let probe_targets = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    let poll_engine = PollEngine::new(
        config.clone(),
        broadcast_tx.clone(),
        last_snapshot.clone(),
        traffic_db.clone(),
        probe_targets.clone(),
    )
    .await;
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    Arc::new(AppState {
        config,
        broadcast_tx,
        ws_connections: Arc::new(WsConnectionLimiter::new(
            MAX_CONNECTIONS_GLOBAL,
            MAX_CONNECTIONS_PER_SESSION,
            MAX_CONNECTIONS_PER_SOURCE,
        )),
        ws_sessions: Arc::new(WsSessionTracker::new()),
        last_snapshot,
        traffic_db,
        probe_targets,
        secret_cipher: Arc::new(SecretCipher::from_bytes([7; 32])),
        instance_id,
        public_origin: "https://routerview.test".into(),
        auth_security: Arc::new(AuthSecurity::new(Vec::new()).unwrap()),
        oidc,
        setup_token_path: PathBuf::from("/tmp/routerview-unused-setup-token"),
        poller_control: poll_engine.control(),
        shutdown_tx,
        traffic_query_limit: Arc::new(tokio::sync::Semaphore::new(2)),
    })
}

async fn call_callback(
    state: Arc<AppState>,
    source: std::net::IpAddr,
    query: String,
    cookie_state: Option<&str>,
) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(cookie_state) = cookie_state {
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{FLOW_COOKIE}={cookie_state}")).unwrap(),
        );
    }
    callback(
        State(state),
        ConnectInfo(SocketAddr::new(source, 443)),
        headers,
        RawQuery(Some(query)),
    )
    .await
    .unwrap()
}

fn callback_query(state: &str, code: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("code", code)
        .append_pair("state", state)
        .finish()
}

fn assert_callback_error(response: &Response, expected_error: &str) {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    let location = url::Url::parse(&format!("https://routerview.test{location}")).unwrap();
    let query: HashMap<_, _> = location.query_pairs().into_owned().collect();
    assert_eq!(query.get("error").map(String::as_str), Some(expected_error));
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(&format!("{FLOW_COOKIE}=;"))
            && value.ends_with("Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")));
}

#[tokio::test]
async fn tls_basic_flow_validates_pkce_nonce_and_admin_groups() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = discovered_manager(&server).await;
    server.state.clear_requests();

    let source = "192.0.2.10".parse().unwrap();
    let started = manager.begin(source, "/sessions".into()).await.unwrap();
    let authorization = url::Url::parse(&started.authorization_url).unwrap();
    let authorization_query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    let flow = manager.consume_flow(&started.state, source).unwrap();
    let verifier = flow.pkce_verifier.clone();
    let nonce = flow.nonce.clone();
    let id_token = signed_id_token(
        &server,
        &nonce,
        Some(vec!["routerview-viewers", "routerview-admins"]),
        &keys.primary,
    );
    server.state.set_token_reply(token_reply(&id_token));

    let identity = manager
        .authenticate("authorization-code".into(), flow)
        .await
        .unwrap();
    assert_eq!(identity.role, "admin");
    assert_eq!(identity.username, "alice");
    assert_eq!(identity.issuer, server.issuer);
    assert_eq!(identity.subject, "subject-123");
    assert!(server.state.requests_for("/userinfo").is_empty());

    let token_requests = server.state.requests_for("/token");
    assert_eq!(token_requests.len(), 1);
    let token_request = &token_requests[0];
    assert_eq!(token_request.method, "POST");
    let expected_basic =
        base64::engine::general_purpose::STANDARD.encode("routerview-client:routerview-secret");
    assert_eq!(
        token_request
            .headers
            .get("authorization")
            .map(String::as_str),
        Some(format!("Basic {expected_basic}").as_str()),
    );
    let fields = form_fields(token_request);
    assert_eq!(
        fields.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        fields.get("code").map(String::as_str),
        Some("authorization-code")
    );
    assert_eq!(fields.get("code_verifier"), Some(&verifier));
    assert_eq!(
        fields.get("redirect_uri").map(String::as_str),
        Some("https://routerview.test/api/auth/oidc/callback"),
    );
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier));
    assert_eq!(
        authorization_query
            .get("code_challenge")
            .map(String::as_str),
        Some(challenge.as_str()),
    );
    assert_eq!(authorization_query.get("nonce"), Some(&nonce));
}

#[tokio::test]
async fn token_exchange_uses_client_secret_post_when_basic_is_unavailable() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Post, vec![keys.primary_jwks.clone()]).await;
    let manager = discovered_manager(&server).await;
    server.state.clear_requests();

    let source = "192.0.2.11".parse().unwrap();
    let started = manager.begin(source, "/".into()).await.unwrap();
    let flow = manager.consume_flow(&started.state, source).unwrap();
    let id_token = signed_id_token(
        &server,
        &flow.nonce,
        Some(vec!["routerview-viewers"]),
        &keys.primary,
    );
    server.state.set_token_reply(token_reply(&id_token));

    let identity = manager
        .authenticate("post-code".into(), flow)
        .await
        .unwrap();
    assert_eq!(identity.role, "viewer");
    let requests = server.state.requests_for("/token");
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].headers.contains_key("authorization"));
    let fields = form_fields(&requests[0]);
    assert_eq!(
        fields.get("client_id").map(String::as_str),
        Some("routerview-client")
    );
    assert_eq!(
        fields.get("client_secret").map(String::as_str),
        Some("routerview-secret"),
    );
}

#[tokio::test]
async fn rejects_invalid_id_token_security_claims_and_signatures() {
    #[derive(Clone, Copy, Debug)]
    enum InvalidCase {
        Issuer,
        Audience,
        Nonce,
        Expiration,
        Signature,
        AccessTokenHash,
    }

    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = discovered_manager(&server).await;
    for case in [
        InvalidCase::Issuer,
        InvalidCase::Audience,
        InvalidCase::Nonce,
        InvalidCase::Expiration,
        InvalidCase::Signature,
        InvalidCase::AccessTokenHash,
    ] {
        let source = "192.0.2.12".parse().unwrap();
        let started = manager.begin(source, "/".into()).await.unwrap();
        let flow = manager.consume_flow(&started.state, source).unwrap();
        let mut spec = IdTokenSpec::valid(&server, &flow.nonce, &keys.primary);
        match case {
            InvalidCase::Issuer => spec.issuer = "https://wrong-issuer.example".into(),
            InvalidCase::Audience => spec.audience = "another-client".into(),
            InvalidCase::Nonce => spec.nonce = Some("wrong-nonce".into()),
            InvalidCase::Expiration => {
                spec.expiration = chrono::Utc::now() - chrono::Duration::minutes(5)
            }
            InvalidCase::Signature => spec.signing_key = &keys.secondary,
            InvalidCase::AccessTokenHash => spec.hash_access_token = Some("wrong-token".into()),
        }
        server
            .state
            .set_token_reply(token_reply(&signed_id_token_with(spec)));

        let result = manager
            .authenticate("invalid-token-code".into(), flow)
            .await;
        assert!(
            matches!(result, Err(LoginError::AuthenticationFailed)),
            "unexpected result for {case:?}"
        );
    }
}

#[tokio::test]
async fn id_token_groups_must_be_a_string_array_with_an_allowed_group() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = discovered_manager(&server).await;
    let source = "192.0.2.18".parse().unwrap();

    for (groups, expected) in [
        (
            serde_json::json!(["routerview-viewers", 7]),
            LoginError::AuthenticationFailed,
        ),
        (
            serde_json::json!(["unrelated-group"]),
            LoginError::NotAuthorized,
        ),
    ] {
        let started = manager.begin(source, "/".into()).await.unwrap();
        let flow = manager.consume_flow(&started.state, source).unwrap();
        let mut spec = IdTokenSpec::valid(&server, &flow.nonce, &keys.primary);
        spec.groups = Some(groups);
        server
            .state
            .set_token_reply(token_reply(&signed_id_token_with(spec)));
        let error = manager
            .authenticate("invalid-groups-code".into(), flow)
            .await
            .unwrap_err();
        assert_eq!(error, expected);
    }
}

#[tokio::test]
async fn userinfo_supplies_missing_groups_and_display_fields_for_the_same_subject() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = discovered_manager(&server).await;
    server.state.clear_requests();

    let source = "192.0.2.13".parse().unwrap();
    let started = manager.begin(source, "/dashboard".into()).await.unwrap();
    let flow = manager.consume_flow(&started.state, source).unwrap();
    let mut spec = IdTokenSpec::valid(&server, &flow.nonce, &keys.primary);
    spec.groups = None;
    spec.preferred_username = None;
    spec.display_name = None;
    server
        .state
        .set_token_reply(token_reply(&signed_id_token_with(spec)));
    server
        .state
        .set_userinfo_reply(MockReply::json(serde_json::json!({
            "sub": "subject-123",
            "preferred_username": "userinfo-alice",
            "name": "Alice from UserInfo",
            "groups": ["routerview-viewers"]
        })));

    let identity = manager
        .authenticate("userinfo-code".into(), flow)
        .await
        .unwrap();
    assert_eq!(identity.role, "viewer");
    assert_eq!(identity.username, "userinfo-alice");
    assert_eq!(identity.display_name, "Alice from UserInfo");
    let requests = server.state.requests_for("/userinfo");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(
        requests[0].headers.get("authorization").map(String::as_str),
        Some("Bearer access-token"),
    );
}

#[tokio::test]
async fn userinfo_requires_exact_subject_and_an_allowed_group() {
    #[derive(Clone, Copy, Debug)]
    enum UserInfoCase {
        SubjectMismatch,
        MissingGroups,
        UnmappedGroups,
        InvalidGroupsType,
    }

    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = discovered_manager(&server).await;
    for case in [
        UserInfoCase::SubjectMismatch,
        UserInfoCase::MissingGroups,
        UserInfoCase::UnmappedGroups,
        UserInfoCase::InvalidGroupsType,
    ] {
        let source = "192.0.2.14".parse().unwrap();
        let started = manager.begin(source, "/".into()).await.unwrap();
        let flow = manager.consume_flow(&started.state, source).unwrap();
        let mut spec = IdTokenSpec::valid(&server, &flow.nonce, &keys.primary);
        spec.groups = None;
        server
            .state
            .set_token_reply(token_reply(&signed_id_token_with(spec)));
        let userinfo = match case {
            UserInfoCase::SubjectMismatch => serde_json::json!({
                "sub": "different-subject",
                "groups": ["routerview-viewers"]
            }),
            UserInfoCase::MissingGroups => serde_json::json!({ "sub": "subject-123" }),
            UserInfoCase::UnmappedGroups => serde_json::json!({
                "sub": "subject-123",
                "groups": ["unrelated-group"]
            }),
            UserInfoCase::InvalidGroupsType => serde_json::json!({
                "sub": "subject-123",
                "groups": "routerview-viewers"
            }),
        };
        server.state.set_userinfo_reply(MockReply::json(userinfo));

        let result = manager
            .authenticate("userinfo-failure-code".into(), flow)
            .await;
        match case {
            UserInfoCase::MissingGroups | UserInfoCase::UnmappedGroups => assert!(
                matches!(result, Err(LoginError::NotAuthorized)),
                "unexpected result for {case:?}"
            ),
            UserInfoCase::SubjectMismatch | UserInfoCase::InvalidGroupsType => assert!(
                matches!(result, Err(LoginError::AuthenticationFailed)),
                "unexpected result for {case:?}"
            ),
        }
    }
}

#[tokio::test]
async fn unknown_signing_key_refreshes_discovery_and_jwks_once() {
    let keys = signing_keys();
    let server = MockOidcServer::start(
        TokenAuthMethod::Basic,
        vec![keys.primary_jwks.clone(), keys.secondary_jwks.clone()],
    )
    .await;
    let manager = discovered_manager(&server).await;

    let source = "192.0.2.15".parse().unwrap();
    let started = manager.begin(source, "/".into()).await.unwrap();
    let flow = manager.consume_flow(&started.state, source).unwrap();
    let id_token = signed_id_token(
        &server,
        &flow.nonce,
        Some(vec!["routerview-admins"]),
        &keys.secondary,
    );
    server.state.set_token_reply(token_reply(&id_token));

    let identity = manager
        .authenticate("rotated-key-code".into(), flow)
        .await
        .unwrap();
    assert_eq!(identity.role, "admin");
    assert_eq!(
        server
            .state
            .requests_for("/.well-known/openid-configuration")
            .len(),
        2
    );
    assert_eq!(server.state.requests_for("/jwks").len(), 2);
}

#[tokio::test]
async fn provider_token_errors_and_oversized_responses_are_redacted() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = discovered_manager(&server).await;
    let source = "192.0.2.16".parse().unwrap();

    for status in [400, 500] {
        let marker = format!("sensitive-provider-body-{status}");
        server
            .state
            .set_token_reply(MockReply::error(status, &marker));
        let started = manager.begin(source, "/".into()).await.unwrap();
        let flow = manager.consume_flow(&started.state, source).unwrap();
        let error = manager
            .authenticate("provider-error-code".into(), flow)
            .await
            .unwrap_err();
        assert_eq!(error, LoginError::AuthenticationFailed);
        assert!(!format!("{error:?}").contains(&marker));
    }

    server.state.set_token_reply(MockReply {
        status: 200,
        content_type: "application/json",
        body: vec![b'x'; MAX_HTTP_RESPONSE_BYTES + 1],
        delay: Duration::ZERO,
    });
    let started = manager.begin(source, "/".into()).await.unwrap();
    let flow = manager.consume_flow(&started.state, source).unwrap();
    assert!(matches!(
        manager.authenticate("oversized-code".into(), flow).await,
        Err(LoginError::AuthenticationFailed)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn provider_token_timeout_fails_closed_without_wall_clock_delay() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = Arc::new(discovered_manager(&server).await);
    let source = "192.0.2.17".parse().unwrap();
    let started = manager.begin(source, "/".into()).await.unwrap();
    let flow = manager.consume_flow(&started.state, source).unwrap();
    let id_token = signed_id_token(
        &server,
        &flow.nonce,
        Some(vec!["routerview-viewers"]),
        &keys.primary,
    );
    let mut delayed = token_reply(&id_token);
    delayed.delay = Duration::from_secs(30);
    server.state.set_token_reply(delayed);

    let authenticating = tokio::spawn({
        let manager = manager.clone();
        async move { manager.authenticate("timeout-code".into(), flow).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while server.state.requests_for("/token").is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mock provider did not receive the token request");
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(matches!(
        authenticating.await.unwrap(),
        Err(LoginError::AuthenticationFailed)
    ));
    assert_eq!(server.state.requests_for("/token").len(), 1);
}

#[tokio::test]
async fn callback_rejects_invalid_expired_cross_source_and_polluted_state_before_token_exchange() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = Arc::new(discovered_manager(&server).await);
    let app_state = test_app_state(manager.clone()).await;
    server.state.clear_requests();
    let source = "192.0.2.20".parse().unwrap();
    let other_source = "192.0.2.21".parse().unwrap();

    let start_response = start(
        State(app_state.clone()),
        ConnectInfo(SocketAddr::new(source, 443)),
        HeaderMap::new(),
        RawQuery(Some("redirect=%2Fsessions".into())),
    )
    .await
    .unwrap();
    assert_eq!(start_response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        start_response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert!(start_response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(&format!("{}/authorize?", server.issuer))));
    let flow_cookie = start_response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{FLOW_COOKIE}=")))
        .unwrap();
    assert!(flow_cookie.ends_with("; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax"));

    let missing_cookie = manager.begin(source, "/missing".into()).await.unwrap();
    let response = call_callback(
        app_state.clone(),
        source,
        callback_query(&missing_cookie.state, "code"),
        None,
    )
    .await;
    assert_callback_error(&response, "invalid_state");

    let mismatched_cookie = manager.begin(source, "/mismatch".into()).await.unwrap();
    let response = call_callback(
        app_state.clone(),
        source,
        callback_query(&mismatched_cookie.state, "code"),
        Some("different-browser-state"),
    )
    .await;
    assert_callback_error(&response, "invalid_state");

    let polluted = manager.begin(source, "/polluted".into()).await.unwrap();
    let response = call_callback(
        app_state.clone(),
        source,
        format!(
            "code=code&state={}&state={}",
            polluted.state, polluted.state
        ),
        Some(&polluted.state),
    )
    .await;
    assert_callback_error(&response, "authentication_failed");

    let cross_source = manager.begin(source, "/cross-source".into()).await.unwrap();
    let cross_source_query = callback_query(&cross_source.state, "code");
    let response = call_callback(
        app_state.clone(),
        other_source,
        cross_source_query.clone(),
        Some(&cross_source.state),
    )
    .await;
    assert_callback_error(&response, "invalid_state");
    let response = call_callback(
        app_state.clone(),
        source,
        cross_source_query,
        Some(&cross_source.state),
    )
    .await;
    assert_callback_error(&response, "invalid_state");

    let expired = manager.begin(source, "/expired".into()).await.unwrap();
    manager
        .flows
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .entries
        .get_mut(&expired.state)
        .unwrap()
        .expires_at = Instant::now() - Duration::from_secs(1);
    let response = call_callback(
        app_state,
        source,
        callback_query(&expired.state, "code"),
        Some(&expired.state),
    )
    .await;
    assert_callback_error(&response, "invalid_state");

    assert!(server.state.requests_for("/token").is_empty());
}

#[tokio::test]
async fn successful_callback_persists_oidc_session_rejects_replay_and_redacts_provider_error() {
    let keys = signing_keys();
    let server =
        MockOidcServer::start(TokenAuthMethod::Basic, vec![keys.primary_jwks.clone()]).await;
    let manager = Arc::new(discovered_manager(&server).await);
    let app_state = test_app_state(manager.clone()).await;
    server.state.clear_requests();
    let source = "192.0.2.22".parse().unwrap();

    let started = manager
        .begin(source, "/sessions?view=active".into())
        .await
        .unwrap();
    let nonce = manager
        .flows
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .entries
        .get(&started.state)
        .unwrap()
        .nonce
        .clone();
    let mut spec = IdTokenSpec::valid(&server, &nonce, &keys.primary);
    spec.groups = Some(serde_json::json!(["routerview-admins"]));
    spec.display_name = Some("Alice External".into());
    server
        .state
        .set_token_reply(token_reply(&signed_id_token_with(spec)));
    let query = callback_query(&started.state, "successful-code");
    let response = call_callback(
        app_state.clone(),
        source,
        query.clone(),
        Some(&started.state),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/login/oidc/complete?redirect=%2Fsessions%3Fview%3Dactive")
    );
    let set_cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert!(set_cookies
        .iter()
        .any(|value| value.starts_with(&format!("{}=", auth::SESSION_COOKIE))));
    assert!(set_cookies
        .iter()
        .any(|value| value.starts_with(&format!("{}=", auth::CSRF_COOKIE))));
    assert!(set_cookies
        .iter()
        .any(|value| value.starts_with(&format!("{FLOW_COOKIE}=;"))
            && value.ends_with("Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")));
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let sessions = app_state.traffic_db.list_sessions().unwrap();
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert_eq!(session.username, "alice");
    assert_eq!(session.display_name, "Alice External");
    assert_eq!(session.role, "admin");
    assert_eq!(session.kind, "standard");
    assert_eq!(session.auth_method, "oidc");
    assert_eq!(session.provider_name.as_deref(), Some("Test Identity"));
    assert_eq!(
        session.identity_issuer.as_deref(),
        Some(server.issuer.as_str())
    );
    assert_eq!(session.identity_subject.as_deref(), Some("subject-123"));
    assert_eq!(
        session.oidc_policy_fingerprint.as_deref(),
        manager.policy_fingerprint()
    );

    let replay = call_callback(app_state.clone(), source, query, Some(&started.state)).await;
    assert_callback_error(&replay, "invalid_state");
    assert_eq!(server.state.requests_for("/token").len(), 1);

    let marker = "sensitive-callback-provider-body";
    server.state.set_token_reply(MockReply::error(400, marker));
    let failed = manager.begin(source, "/sessions".into()).await.unwrap();
    let response = call_callback(
        app_state,
        source,
        callback_query(&failed.state, "failed-code"),
        Some(&failed.state),
    )
    .await;
    assert_callback_error(&response, "authentication_failed");
    assert!(!format!("{:?}", response.headers()).contains(marker));
    let body = axum::body::to_bytes(response.into_body(), MAX_HTTP_RESPONSE_BYTES)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains(marker));
}
