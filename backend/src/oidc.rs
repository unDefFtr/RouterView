use std::{
    collections::HashMap,
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use futures_util::StreamExt;
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreIdToken, CoreIdTokenVerifier,
        CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    },
    AccessToken, AccessTokenHash, AdditionalClaims, AsyncHttpClient, AuthType, AuthorizationCode,
    ClientId, ClientSecret, CsrfToken, EndUserName, HttpRequest, HttpResponse, IssuerUrl,
    JsonWebKey, JsonWebTokenType, JwsSigningAlgorithm, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, SignatureVerificationError,
    SubjectIdentifier, UserInfoClaims,
};
use rand::{rngs::OsRng, RngCore};
use serde::{
    de::{Error as _, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{watch, RwLock, Semaphore};

use crate::{auth, config::OidcConfig, error::AppError, state::AppState};

pub const FLOW_COOKIE: &str = "__Host-routerview_oidc_flow";
const FLOW_TTL: Duration = Duration::from_secs(5 * 60);
const FLOW_CAPACITY: usize = 1_024;
const FLOW_PER_SOURCE: usize = 8;
const MAX_QUERY_BYTES: usize = 8 * 1024;
const MAX_REDIRECT_BYTES: usize = 2 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 1024 * 1024;
const DISCOVERY_RETRY_MIN: Duration = Duration::from_secs(15);
const DISCOVERY_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
const DISCOVERY_REFRESH: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, thiserror::Error)]
pub enum OidcInitError {
    #[error("invalid OIDC issuer or callback URL")]
    InvalidUrl,
    #[error("invalid OIDC private CA bundle")]
    InvalidCa,
    #[error("failed to construct the OIDC HTTP client")]
    HttpClient,
}

#[derive(Debug, thiserror::Error)]
enum BoundedHttpError {
    #[error("OIDC HTTP endpoint is not allowed")]
    DisallowedEndpoint,
    #[error("OIDC HTTP request failed")]
    Request(#[source] reqwest::Error),
    #[error("OIDC HTTP response exceeded the configured limit")]
    ResponseTooLarge,
    #[error("OIDC HTTP response was invalid")]
    InvalidResponse(#[source] openidconnect::http::Error),
}

#[derive(Clone)]
struct BoundedHttpClient {
    inner: reqwest::Client,
}

impl<'client> AsyncHttpClient<'client> for BoundedHttpClient {
    type Error = BoundedHttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'client>>;

    fn call(&'client self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request = reqwest::Request::try_from(request).map_err(BoundedHttpError::Request)?;
            if !secure_url(request.url()) {
                return Err(BoundedHttpError::DisallowedEndpoint);
            }
            let response = self
                .inner
                .execute(request)
                .await
                .map_err(BoundedHttpError::Request)?;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_HTTP_RESPONSE_BYTES as u64)
            {
                return Err(BoundedHttpError::ResponseTooLarge);
            }

            let status = response.status();
            let version = response.version();
            let headers = response.headers().clone();
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(BoundedHttpError::Request)?;
                if body.len().saturating_add(chunk.len()) > MAX_HTTP_RESPONSE_BYTES {
                    return Err(BoundedHttpError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }

            let mut builder = openidconnect::http::Response::builder()
                .status(status)
                .version(version);
            for (name, value) in &headers {
                builder = builder.header(name, value);
            }
            builder
                .body(body)
                .map_err(BoundedHttpError::InvalidResponse)
        })
    }
}

#[derive(Clone)]
struct CapturingHttpClient {
    inner: BoundedHttpClient,
    response: Arc<Mutex<Option<CapturedHttpResponse>>>,
}

struct CapturedHttpResponse {
    status: StatusCode,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct UniqueObject(Map<String, Value>);

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueObjectVisitor;

        impl<'de> Visitor<'de> for UniqueObjectVisitor {
            type Value = UniqueObject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object without duplicate fields")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, value)) = access.next_entry::<String, Value>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(A::Error::custom(format!("duplicate field `{key}`")));
                    }
                }
                Ok(UniqueObject(values))
            }
        }

        deserializer.deserialize_map(UniqueObjectVisitor)
    }
}

impl CapturingHttpClient {
    fn new(inner: BoundedHttpClient) -> Self {
        Self {
            inner,
            response: Arc::new(Mutex::new(None)),
        }
    }

    fn take_response(&self) -> Option<CapturedHttpResponse> {
        self.response
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }
}

impl<'client> AsyncHttpClient<'client> for CapturingHttpClient {
    type Error = BoundedHttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'client>>;

    fn call(&'client self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.inner.call(request).await?;
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .map(str::trim)
                .map(str::to_owned);
            *self
                .response
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(CapturedHttpResponse {
                status: response.status(),
                content_type,
                body: response.body().clone(),
            });
            Ok(response)
        })
    }
}

#[derive(Clone)]
struct Provider {
    metadata: CoreProviderMetadata,
    auth_type: AuthType,
}

struct VerifiedIdentityToken {
    provider: Provider,
    access_token: AccessToken,
    subject: String,
    values: HashMap<String, Value>,
    username: Option<String>,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct CompatibleTokenResponse {
    access_token: String,
    token_type: String,
    id_token: String,
}

#[derive(Deserialize)]
struct CompatibleJoseHeader {
    alg: CoreJwsSigningAlgorithm,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<JsonWebTokenType>,
    #[serde(default)]
    cty: Option<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompatibleTokenError {
    NoMatchingKey,
    Invalid,
}

#[derive(Debug)]
struct LoginFlow {
    nonce: String,
    pkce_verifier: String,
    source: IpAddr,
    redirect: String,
    expires_at: Instant,
}

#[derive(Default)]
struct FlowStore {
    entries: HashMap<String, LoginFlow>,
}

impl FlowStore {
    fn insert(&mut self, state: String, flow: LoginFlow, now: Instant) -> Result<(), ()> {
        self.entries.retain(|_, entry| entry.expires_at > now);
        if self.entries.len() >= FLOW_CAPACITY
            || self
                .entries
                .values()
                .filter(|entry| entry.source == flow.source)
                .count()
                >= FLOW_PER_SOURCE
        {
            return Err(());
        }
        self.entries.insert(state, flow);
        Ok(())
    }

    fn consume(&mut self, state: &str, source: IpAddr, now: Instant) -> Option<LoginFlow> {
        self.entries.retain(|_, entry| entry.expires_at > now);
        let flow = self.entries.remove(state)?;
        (flow.source == source && flow.expires_at > now).then_some(flow)
    }
}

#[derive(Debug)]
pub struct StartedFlow {
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug)]
pub struct ConsumedFlow {
    nonce: String,
    pkce_verifier: String,
    pub redirect: String,
}

#[derive(Debug)]
pub struct OidcIdentity {
    pub username: String,
    pub display_name: String,
    pub role: String,
    pub provider_name: String,
    pub issuer: String,
    pub subject: String,
    pub policy_fingerprint: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginError {
    ProviderUnavailable,
    NotAuthorized,
    AuthenticationFailed,
}

#[derive(Debug, Deserialize, Serialize)]
struct DynamicClaims {
    #[serde(flatten)]
    values: HashMap<String, Value>,
}

impl AdditionalClaims for DynamicClaims {}

pub struct OidcManager {
    config: Option<Arc<OidcConfig>>,
    provider: RwLock<Option<Provider>>,
    http: Option<BoundedHttpClient>,
    flows: Mutex<FlowStore>,
    requests: Arc<Semaphore>,
    policy_fingerprint: Option<Vec<u8>>,
}

impl OidcManager {
    pub fn new(config: Option<OidcConfig>) -> Result<Self, OidcInitError> {
        let Some(config) = config else {
            return Ok(Self {
                config: None,
                provider: RwLock::new(None),
                http: None,
                flows: Mutex::new(FlowStore::default()),
                requests: Arc::new(Semaphore::new(8)),
                policy_fingerprint: None,
            });
        };
        IssuerUrl::new(config.issuer_url.clone()).map_err(|_| OidcInitError::InvalidUrl)?;
        RedirectUrl::new(config.redirect_url.clone()).map_err(|_| OidcInitError::InvalidUrl)?;

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(2);
        if let Some(pem) = &config.ca_pem {
            let certificates =
                reqwest::Certificate::from_pem_bundle(pem).map_err(|_| OidcInitError::InvalidCa)?;
            if certificates.is_empty() {
                return Err(OidcInitError::InvalidCa);
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = BoundedHttpClient {
            inner: builder.build().map_err(|_| OidcInitError::HttpClient)?,
        };
        let fingerprint = policy_fingerprint(&config);
        Ok(Self {
            config: Some(Arc::new(config)),
            provider: RwLock::new(None),
            http: Some(http),
            flows: Mutex::new(FlowStore::default()),
            requests: Arc::new(Semaphore::new(8)),
            policy_fingerprint: Some(fingerprint),
        })
    }

    pub fn enabled(&self) -> bool {
        self.config.is_some()
    }

    pub fn provider_name(&self) -> Option<&str> {
        self.config
            .as_deref()
            .map(|config| config.provider_name.as_str())
    }

    fn issuer_matches(&self, issuer: &str) -> bool {
        self.config
            .as_deref()
            .is_some_and(|config| constant_time_eq(config.issuer_url.as_bytes(), issuer.as_bytes()))
    }

    pub async fn available(&self) -> bool {
        self.provider.read().await.is_some()
    }

    pub fn session_policy_valid(&self, auth_method: &str, fingerprint: Option<&[u8]>) -> bool {
        auth_method != "oidc"
            || self
                .policy_fingerprint
                .as_deref()
                .zip(fingerprint)
                .is_some_and(|(expected, actual)| constant_time_eq(expected, actual))
    }

    pub(crate) fn policy_fingerprint(&self) -> Option<&[u8]> {
        self.policy_fingerprint.as_deref()
    }

    pub fn spawn_discovery(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        if !self.enabled() {
            return;
        }
        let manager = self.clone();
        tokio::spawn(async move {
            let mut retry = DISCOVERY_RETRY_MIN;
            loop {
                if *shutdown.borrow() {
                    break;
                }
                let discovered = manager.discover().await;
                let delay = match discovered {
                    Ok(provider) => {
                        *manager.provider.write().await = Some(provider);
                        retry = DISCOVERY_RETRY_MIN;
                        DISCOVERY_REFRESH
                    }
                    Err(()) => {
                        *manager.provider.write().await = None;
                        tracing::warn!("OIDC provider is unavailable; discovery will retry");
                        let delay = retry;
                        retry = retry.saturating_mul(2).min(DISCOVERY_RETRY_MAX);
                        delay
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn discover(&self) -> Result<Provider, ()> {
        let config = self.config.as_deref().ok_or(())?;
        let http = self.http.as_ref().ok_or(())?;
        let _permit = tokio::time::timeout(Duration::from_secs(1), self.requests.acquire())
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        discover_provider(config, http).await
    }

    async fn refresh_provider(&self) -> Result<Provider, LoginError> {
        let config = self
            .config
            .as_deref()
            .ok_or(LoginError::ProviderUnavailable)?;
        let http = self.http.as_ref().ok_or(LoginError::ProviderUnavailable)?;
        let provider = match discover_provider(config, http).await {
            Ok(provider) => provider,
            Err(()) => {
                *self.provider.write().await = None;
                return Err(LoginError::AuthenticationFailed);
            }
        };
        *self.provider.write().await = Some(provider.clone());
        Ok(provider)
    }

    pub async fn begin(&self, source: IpAddr, redirect: String) -> Result<StartedFlow, LoginError> {
        let provider = self
            .provider
            .read()
            .await
            .clone()
            .ok_or(LoginError::ProviderUnavailable)?;
        let config = self
            .config
            .as_deref()
            .ok_or(LoginError::ProviderUnavailable)?;
        let client = oidc_client(config, provider);
        let state = random_token();
        let nonce = random_token();
        let authorization_state = state.clone();
        let authorization_nonce = nonce.clone();
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut authorization = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                move || CsrfToken::new(authorization_state),
                move || Nonce::new(authorization_nonce),
            )
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("email".into()))
            .set_pkce_challenge(challenge);
        for scope in &config.additional_scopes {
            authorization = authorization.add_scope(Scope::new(scope.clone()));
        }
        let (authorization_url, _, _) = authorization.url();
        let flow = LoginFlow {
            nonce,
            pkce_verifier: verifier.secret().to_string(),
            source,
            redirect,
            expires_at: Instant::now() + FLOW_TTL,
        };
        self.flows
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(state.clone(), flow, Instant::now())
            .map_err(|_| LoginError::AuthenticationFailed)?;
        Ok(StartedFlow {
            authorization_url: authorization_url.to_string(),
            state,
        })
    }

    pub fn consume_flow(&self, state: &str, source: IpAddr) -> Option<ConsumedFlow> {
        let flow = self
            .flows
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .consume(state, source, Instant::now())?;
        Some(ConsumedFlow {
            nonce: flow.nonce,
            pkce_verifier: flow.pkce_verifier,
            redirect: flow.redirect,
        })
    }

    fn discard_flow(&self, state: &str) {
        self.flows
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entries
            .remove(state);
    }

    pub async fn authenticate(
        &self,
        code: String,
        flow: ConsumedFlow,
    ) -> Result<OidcIdentity, LoginError> {
        let config = self
            .config
            .as_deref()
            .ok_or(LoginError::ProviderUnavailable)?;
        let http = self.http.as_ref().ok_or(LoginError::ProviderUnavailable)?;
        let provider = self
            .provider
            .read()
            .await
            .clone()
            .ok_or(LoginError::ProviderUnavailable)?;
        let _permit = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| LoginError::ProviderUnavailable)?;
        let client = oidc_client(config, provider.clone());
        let capturing_http = CapturingHttpClient::new(http.clone());
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier))
            .request_async(&capturing_http)
            .await;
        let nonce = Nonce::new(flow.nonce.clone());
        let verified = match token {
            Ok(token) => {
                let _ = capturing_http.take_response();
                let id_token = token
                    .extra_fields()
                    .id_token()
                    .ok_or(LoginError::AuthenticationFailed)?;
                let first_validation_succeeded = {
                    let verifier = client.id_token_verifier();
                    id_token.claims(&verifier, &nonce).is_ok()
                };
                let active_provider = if first_validation_succeeded {
                    provider
                } else {
                    self.refresh_provider().await?
                };
                let active_client = oidc_client(config, active_provider.clone());
                let verifier = active_client.id_token_verifier();
                let claims = id_token
                    .claims(&verifier, &nonce)
                    .map_err(|_| LoginError::AuthenticationFailed)?;

                if let Some(expected_hash) = claims.access_token_hash() {
                    let signing_algorithm = id_token
                        .signing_alg()
                        .map_err(|_| LoginError::AuthenticationFailed)?;
                    let signing_key = id_token
                        .signing_key(&verifier)
                        .map_err(|_| LoginError::AuthenticationFailed)?;
                    let actual_hash = AccessTokenHash::from_token(
                        token.access_token(),
                        signing_algorithm,
                        signing_key,
                    )
                    .map_err(|_| LoginError::AuthenticationFailed)?;
                    if actual_hash != *expected_hash {
                        return Err(LoginError::AuthenticationFailed);
                    }
                }

                let subject = claims.subject().as_str().to_string();
                let values = id_token_values(id_token)?;
                let username = valid_identity_text(
                    claims.preferred_username().map(|value| value.as_str()),
                    256,
                )
                .or_else(|| valid_identity_text(claims.email().map(|value| value.as_str()), 256));
                let display_name = claims.name().and_then(localized_value);
                VerifiedIdentityToken {
                    provider: active_provider,
                    access_token: token.access_token().to_owned(),
                    subject,
                    values,
                    username,
                    display_name,
                }
            }
            Err(_) => {
                let response = capturing_http
                    .take_response()
                    .ok_or(LoginError::AuthenticationFailed)?;
                self.verify_compatible_token_response(config, provider, response, &flow.nonce)
                    .await?
            }
        };
        let VerifiedIdentityToken {
            provider: active_provider,
            access_token,
            subject,
            values: id_values,
            mut username,
            mut display_name,
        } = verified;
        if subject.is_empty() || subject.len() > 512 || subject.chars().any(char::is_control) {
            return Err(LoginError::AuthenticationFailed);
        }
        let active_client = oidc_client(config, active_provider);

        let groups = match group_claim(&id_values, &config.groups_claim)? {
            Some(groups) => groups,
            None => {
                let request = active_client
                    .user_info(access_token, Some(SubjectIdentifier::new(subject.clone())))
                    .map_err(|_| LoginError::AuthenticationFailed)?;
                let user_info: UserInfoClaims<DynamicClaims, CoreGenderClaim> = request
                    .request_async(http)
                    .await
                    .map_err(|_| LoginError::AuthenticationFailed)?;
                if username.is_none() {
                    username = valid_identity_text(
                        user_info.preferred_username().map(|value| value.as_str()),
                        256,
                    )
                    .or_else(|| {
                        valid_identity_text(user_info.email().map(|value| value.as_str()), 256)
                    });
                }
                if display_name.is_none() {
                    display_name = user_info.name().and_then(localized_value);
                }
                group_claim(&user_info.additional_claims().values, &config.groups_claim)?
                    .ok_or(LoginError::NotAuthorized)?
            }
        };
        let role = map_role(&groups, config)?;
        let username = username.unwrap_or_else(|| subject.clone());
        let display_name = display_name.unwrap_or_else(|| username.clone());
        Ok(OidcIdentity {
            username,
            display_name,
            role,
            provider_name: config.provider_name.clone(),
            issuer: config.issuer_url.clone(),
            subject,
            policy_fingerprint: self
                .policy_fingerprint
                .clone()
                .ok_or(LoginError::ProviderUnavailable)?,
        })
    }

    async fn verify_compatible_token_response(
        &self,
        config: &OidcConfig,
        provider: Provider,
        response: CapturedHttpResponse,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentityToken, LoginError> {
        let token = parse_compatible_token_response(response)?;
        match verify_compatible_id_token(config, provider.clone(), &token, expected_nonce) {
            Ok(verified) => Ok(verified),
            Err(CompatibleTokenError::NoMatchingKey) => {
                let refreshed = self.refresh_provider().await?;
                verify_compatible_id_token(config, refreshed, &token, expected_nonce)
                    .map_err(|_| LoginError::AuthenticationFailed)
            }
            Err(CompatibleTokenError::Invalid) => Err(LoginError::AuthenticationFailed),
        }
    }
}

fn parse_compatible_token_response(
    response: CapturedHttpResponse,
) -> Result<CompatibleTokenResponse, LoginError> {
    if response.status != StatusCode::OK
        || !response
            .content_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
    {
        return Err(LoginError::AuthenticationFailed);
    }
    let UniqueObject(values) =
        serde_json::from_slice(&response.body).map_err(|_| LoginError::AuthenticationFailed)?;
    if values.contains_key("error") {
        return Err(LoginError::AuthenticationFailed);
    }
    let token: CompatibleTokenResponse = serde_json::from_value(Value::Object(values))
        .map_err(|_| LoginError::AuthenticationFailed)?;
    if token.access_token.is_empty()
        || token.id_token.is_empty()
        || token.access_token.len() > MAX_HTTP_RESPONSE_BYTES
        || token.id_token.len() > MAX_HTTP_RESPONSE_BYTES
        || !token.token_type.eq_ignore_ascii_case("bearer")
    {
        return Err(LoginError::AuthenticationFailed);
    }
    Ok(token)
}

fn verify_compatible_id_token(
    config: &OidcConfig,
    provider: Provider,
    token: &CompatibleTokenResponse,
    expected_nonce: &str,
) -> Result<VerifiedIdentityToken, CompatibleTokenError> {
    let mut pieces = token.id_token.split('.');
    let encoded_header = pieces.next().ok_or(CompatibleTokenError::Invalid)?;
    let encoded_payload = pieces.next().ok_or(CompatibleTokenError::Invalid)?;
    let encoded_signature = pieces.next().ok_or(CompatibleTokenError::Invalid)?;
    if pieces.next().is_some()
        || encoded_header.is_empty()
        || encoded_payload.is_empty()
        || encoded_signature.is_empty()
    {
        return Err(CompatibleTokenError::Invalid);
    }

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| CompatibleTokenError::Invalid)?;
    let UniqueObject(header_values) =
        serde_json::from_slice(&header_bytes).map_err(|_| CompatibleTokenError::Invalid)?;
    if header_values.contains_key("cty") || header_values.contains_key("crit") {
        return Err(CompatibleTokenError::Invalid);
    }
    let header: CompatibleJoseHeader = serde_json::from_value(Value::Object(header_values))
        .map_err(|_| CompatibleTokenError::Invalid)?;
    if header.cty.is_some() || header.crit.is_some() || header.alg.uses_shared_secret() {
        return Err(CompatibleTokenError::Invalid);
    }
    if let Some(token_type) = &header.typ {
        let normalized = token_type
            .normalize()
            .map_err(|_| CompatibleTokenError::Invalid)?;
        if normalized.as_str() != "application/jwt" && normalized.as_str() != "application/jose" {
            return Err(CompatibleTokenError::Invalid);
        }
    }
    let key_id = header.kid.as_deref().filter(|value| {
        !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
    });
    if key_id.is_none()
        || !provider
            .metadata
            .id_token_signing_alg_values_supported()
            .contains(&header.alg)
    {
        return Err(CompatibleTokenError::Invalid);
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .map_err(|_| CompatibleTokenError::Invalid)?;
    let UniqueObject(mut payload_values) =
        serde_json::from_slice(&payload_bytes).map_err(|_| CompatibleTokenError::Invalid)?;
    let compatible_address = payload_values
        .get("address")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values.len() <= 32
                && values.iter().all(|value| {
                    value.as_str().is_some_and(|address| {
                        address.len() <= 512 && !address.chars().any(char::is_control)
                    })
                })
        });
    if !compatible_address {
        return Err(CompatibleTokenError::Invalid);
    }
    let original_payload_values = payload_values.clone();

    // Parsing the token after changing only Casdoor's non-standard address array proves that no
    // other standard claim shape is being accepted through this compatibility path. Signature
    // verification below always uses the untouched, provider-signed input.
    payload_values.insert("address".into(), Value::Object(Map::new()));
    let normalized_payload =
        serde_json::to_vec(&payload_values).map_err(|_| CompatibleTokenError::Invalid)?;
    let normalized_token = format!(
        "{encoded_header}.{}.{encoded_signature}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(normalized_payload)
    )
    .parse::<CoreIdToken>()
    .map_err(|_| CompatibleTokenError::Invalid)?;

    let client = oidc_client(config, provider.clone());
    let verifier = client.id_token_verifier();
    let signing_algorithm = normalized_token
        .signing_alg()
        .map_err(|_| CompatibleTokenError::Invalid)?;
    if signing_algorithm != &header.alg {
        return Err(CompatibleTokenError::Invalid);
    }
    let signing_key = normalized_token
        .signing_key(&verifier)
        .map_err(|error| match error {
            SignatureVerificationError::NoMatchingKey => CompatibleTokenError::NoMatchingKey,
            _ => CompatibleTokenError::Invalid,
        })?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| CompatibleTokenError::Invalid)?;
    let signing_input = format!("{encoded_header}.{encoded_payload}");
    signing_key
        .verify_signature(signing_algorithm, signing_input.as_bytes(), &signature)
        .map_err(|_| CompatibleTokenError::Invalid)?;

    // The original JWS has already been verified above. This verifier is used only to retain the
    // library's typed expiration, nonce, and standard-claim checks on the address-normalized copy.
    let claims_verifier = CoreIdTokenVerifier::new_insecure_without_verification();
    let expected_nonce = Nonce::new(expected_nonce.to_owned());
    let claims = normalized_token
        .claims(&claims_verifier, &expected_nonce)
        .map_err(|_| CompatibleTokenError::Invalid)?;
    if !constant_time_eq(
        claims.issuer().as_str().as_bytes(),
        config.issuer_url.as_bytes(),
    ) {
        return Err(CompatibleTokenError::Invalid);
    }
    let audiences = claims.audiences();
    if audiences.is_empty()
        || audiences
            .iter()
            .any(|audience| audience.as_str() != config.client_id)
    {
        return Err(CompatibleTokenError::Invalid);
    }
    if claims
        .authorized_party()
        .is_some_and(|party| party.as_str() != config.client_id)
    {
        return Err(CompatibleTokenError::Invalid);
    }
    if let Some(expected_hash) = claims.access_token_hash() {
        let access_token = AccessToken::new(token.access_token.clone());
        let actual_hash =
            AccessTokenHash::from_token(&access_token, signing_algorithm, signing_key)
                .map_err(|_| CompatibleTokenError::Invalid)?;
        if actual_hash != *expected_hash {
            return Err(CompatibleTokenError::Invalid);
        }
    }

    let subject = claims.subject().as_str().to_owned();
    let username =
        valid_identity_text(claims.preferred_username().map(|value| value.as_str()), 256)
            .or_else(|| valid_identity_text(claims.email().map(|value| value.as_str()), 256));
    let display_name = claims.name().and_then(localized_value);
    Ok(VerifiedIdentityToken {
        provider,
        access_token: AccessToken::new(token.access_token.clone()),
        subject,
        values: original_payload_values.into_iter().collect(),
        username,
        display_name,
    })
}

async fn discover_provider(config: &OidcConfig, http: &BoundedHttpClient) -> Result<Provider, ()> {
    let issuer = IssuerUrl::new(config.issuer_url.clone()).map_err(|_| ())?;
    let discovery_url = discovery_url(&config.issuer_url)?;
    let mut metadata: CoreProviderMetadata = fetch_oidc_json(http, &discovery_url).await?;
    if metadata.issuer() != &issuer {
        return Err(());
    }
    let endpoints = [
        metadata.authorization_endpoint().as_str(),
        metadata.jwks_uri().as_str(),
    ];
    if endpoints.iter().any(|endpoint| !secure_endpoint(endpoint))
        || metadata
            .token_endpoint()
            .is_none_or(|endpoint| !secure_endpoint(endpoint.as_str()))
        || metadata
            .userinfo_endpoint()
            .is_some_and(|endpoint| !secure_endpoint(endpoint.as_str()))
    {
        return Err(());
    }
    let methods = metadata.token_endpoint_auth_methods_supported();
    let auth_type = if methods.is_none_or(|methods| {
        methods
            .iter()
            .any(|method| method.as_ref() == "client_secret_basic")
    }) {
        AuthType::BasicAuth
    } else if methods.is_some_and(|methods| {
        methods
            .iter()
            .any(|method| method.as_ref() == "client_secret_post")
    }) {
        AuthType::RequestBody
    } else {
        return Err(());
    };
    let jwks: CoreJsonWebKeySet = fetch_oidc_json(http, metadata.jwks_uri().as_str()).await?;
    metadata = metadata.set_jwks(jwks);
    Ok(Provider {
        metadata,
        auth_type,
    })
}

fn discovery_url(issuer: &str) -> Result<String, ()> {
    let issuer = issuer.strip_suffix('/').unwrap_or(issuer);
    let value = format!("{issuer}/.well-known/openid-configuration");
    let parsed = url::Url::parse(&value).map_err(|_| ())?;
    secure_url(&parsed).then_some(value).ok_or(())
}

async fn fetch_oidc_json<T>(http: &BoundedHttpClient, endpoint: &str) -> Result<T, ()>
where
    T: serde::de::DeserializeOwned,
{
    let request = openidconnect::http::Request::builder()
        .method(openidconnect::http::Method::GET)
        .uri(endpoint)
        .header(
            openidconnect::http::header::ACCEPT,
            HeaderValue::from_static("application/json"),
        )
        .body(Vec::new())
        .map_err(|_| ())?;
    let response = http.call(request).await.map_err(|_| ())?;
    if response.status() != StatusCode::OK {
        return Err(());
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type.is_some_and(|value| {
        !value.eq_ignore_ascii_case("application/json")
            && !value.eq_ignore_ascii_case("application/jwk-set+json")
    }) {
        return Err(());
    }
    serde_json::from_slice(response.body()).map_err(|_| ())
}

fn oidc_client(
    config: &OidcConfig,
    provider: Provider,
) -> CoreClient<
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointSet,
    openidconnect::EndpointMaybeSet,
> {
    let token_endpoint = provider
        .metadata
        .token_endpoint()
        .expect("validated OIDC token endpoint")
        .clone();
    CoreClient::from_provider_metadata(
        provider.metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_token_uri(token_endpoint)
    .set_auth_type(provider.auth_type)
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_url.clone()).expect("validated OIDC callback URL"),
    )
}

fn secure_endpoint(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    secure_url(&url)
}

fn secure_url(url: &url::Url) -> bool {
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    url.scheme() == "http"
        && match url.host() {
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        }
}

fn id_token_values<T: Serialize>(id_token: &T) -> Result<HashMap<String, Value>, LoginError> {
    let serialized = serde_json::to_value(id_token)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(LoginError::AuthenticationFailed)?;
    if serialized.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(LoginError::AuthenticationFailed);
    }
    let mut pieces = serialized.split('.');
    let _header = pieces.next();
    let payload = pieces.next().ok_or(LoginError::AuthenticationFailed)?;
    if pieces.next().is_none() || pieces.next().is_some() {
        return Err(LoginError::AuthenticationFailed);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| LoginError::AuthenticationFailed)?;
    let UniqueObject(values) =
        serde_json::from_slice(&decoded).map_err(|_| LoginError::AuthenticationFailed)?;
    Ok(values.into_iter().collect())
}

fn group_claim(
    values: &HashMap<String, Value>,
    claim_name: &str,
) -> Result<Option<Vec<String>>, LoginError> {
    let Some(value) = values.get(claim_name) else {
        return Ok(None);
    };
    let array = value.as_array().ok_or(LoginError::AuthenticationFailed)?;
    if array.len() > 512 {
        return Err(LoginError::AuthenticationFailed);
    }
    array
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|group| group.len() <= 512 && !group.chars().any(char::is_control))
                .map(str::to_owned)
                .ok_or(LoginError::AuthenticationFailed)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn map_role(groups: &[String], config: &OidcConfig) -> Result<String, LoginError> {
    if groups.iter().any(|group| group == &config.admin_group) {
        Ok("admin".into())
    } else if groups.iter().any(|group| group == &config.viewer_group) {
        Ok("viewer".into())
    } else {
        Err(LoginError::NotAuthorized)
    }
}

fn localized_value(claim: &openidconnect::LocalizedClaim<EndUserName>) -> Option<String> {
    claim
        .get(None)
        .or_else(|| claim.iter().next().map(|(_, value)| value))
        .and_then(|value| valid_identity_text(Some(value.as_str()), 256))
}

fn valid_identity_text(value: Option<&str>, maximum: usize) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control))
        .then(|| value.to_string())
}

fn policy_fingerprint(config: &OidcConfig) -> Vec<u8> {
    let mut digest = Sha256::new();
    for value in [
        &config.issuer_url,
        &config.client_id,
        &config.groups_claim,
        &config.viewer_group,
        &config.admin_group,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    digest.finalize().to_vec()
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn validate_internal_redirect(value: &str) -> Result<String, ()> {
    if value.is_empty() {
        return Ok("/".into());
    }
    if value.len() > MAX_REDIRECT_BYTES
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(value.to_string())
}

fn parse_query(raw: Option<&str>, allowed: &[&str]) -> Result<HashMap<String, String>, ()> {
    let raw = raw.unwrap_or_default();
    if raw.len() > MAX_QUERY_BYTES {
        return Err(());
    }
    let mut values = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !allowed.contains(&key.as_ref())
            || values
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(());
        }
    }
    Ok(values)
}

fn completion_location(redirect: &str, error: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("redirect", redirect);
    if let Some(error) = error {
        query.append_pair("error", error);
    }
    format!("/login/oidc/complete?{}", query.finish())
}

fn redirect_response(location: &str, flow_cookie: Option<&str>) -> Result<Response, AppError> {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location)
            .map_err(|_| AppError::Internal("failed to construct OIDC redirect".into()))?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(state) = flow_cookie {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "{FLOW_COOKIE}={state}; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax"
            ))
            .map_err(|_| AppError::Internal("failed to construct OIDC flow cookie".into()))?,
        );
    }
    Ok(response)
}

fn clear_flow_cookie(response: &mut Response) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-routerview_oidc_flow=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
        ),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn error_response(code: &str, redirect: &str) -> Result<Response, AppError> {
    let mut response = redirect_response(&completion_location(redirect, Some(code)), None)?;
    clear_flow_cookie(&mut response);
    Ok(response)
}

fn single_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut matches = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .filter_map(|(key, value)| (key == name).then_some(value));
    let value = matches.next()?;
    matches.next().is_none().then_some(value)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

pub async fn start(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connection): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, AppError> {
    let values = match parse_query(raw_query.as_deref(), &["redirect"]) {
        Ok(values) => values,
        Err(()) => return error_response("authentication_failed", "/"),
    };
    let redirect =
        match validate_internal_redirect(values.get("redirect").map(String::as_str).unwrap_or("/"))
        {
            Ok(redirect) => redirect,
            Err(()) => return error_response("authentication_failed", "/"),
        };
    match state.traffic_db.admin() {
        Ok(Some(_)) => {}
        Ok(None) => return error_response("authentication_failed", &redirect),
        Err(_) => {
            tracing::error!("failed to verify local setup state before OIDC login");
            return error_response("authentication_failed", &redirect);
        }
    }
    let source = match state.auth_security.client_ip(connection.ip(), &headers) {
        Ok(source) => source,
        Err(_) => return error_response("authentication_failed", &redirect),
    };
    match state.oidc.begin(source, redirect.clone()).await {
        Ok(flow) => redirect_response(&flow.authorization_url, Some(&flow.state)),
        Err(LoginError::ProviderUnavailable) => error_response("provider_unavailable", &redirect),
        Err(_) => error_response("authentication_failed", &redirect),
    }
}

pub async fn callback(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connection): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, AppError> {
    let values = match parse_query(
        raw_query.as_deref(),
        &[
            "code",
            "state",
            "error",
            "error_description",
            "error_uri",
            "iss",
            "session_state",
            "scope",
            "authuser",
            "prompt",
            "hd",
        ],
    ) {
        Ok(values) => values,
        Err(()) => return error_response("authentication_failed", "/"),
    };
    let has_error = values.contains_key("error");
    if !has_error && (values.contains_key("error_description") || values.contains_key("error_uri"))
    {
        return error_response("authentication_failed", "/");
    }
    let Some(query_state) = values.get("state") else {
        return error_response("invalid_state", "/");
    };
    let Some(cookie_state) = single_cookie(&headers, FLOW_COOKIE) else {
        return error_response("invalid_state", "/");
    };
    if !constant_time_eq(query_state.as_bytes(), cookie_state.as_bytes()) {
        return error_response("invalid_state", "/");
    }
    let source = match state.auth_security.client_ip(connection.ip(), &headers) {
        Ok(source) => source,
        Err(_) => {
            state.oidc.discard_flow(query_state);
            return error_response("authentication_failed", "/");
        }
    };
    let Some(flow) = state.oidc.consume_flow(query_state, source) else {
        return error_response("invalid_state", "/");
    };
    let redirect = flow.redirect.clone();
    match state.traffic_db.admin() {
        Ok(Some(_)) => {}
        Ok(None) => return error_response("authentication_failed", &redirect),
        Err(_) => {
            tracing::error!("failed to verify local setup state during OIDC callback");
            return error_response("authentication_failed", &redirect);
        }
    }
    if values
        .get("iss")
        .is_some_and(|issuer| !state.oidc.issuer_matches(issuer))
    {
        return error_response("authentication_failed", &redirect);
    }
    if has_error {
        if values.contains_key("code") {
            return error_response("authentication_failed", &redirect);
        }
        return if values.get("error").map(String::as_str) == Some("access_denied") {
            error_response("access_denied", &redirect)
        } else {
            error_response("authentication_failed", &redirect)
        };
    }
    let Some(code) = values
        .get("code")
        .filter(|code| !code.is_empty() && code.len() <= 4096)
    else {
        return error_response("authentication_failed", &redirect);
    };
    match state.oidc.authenticate(code.clone(), flow).await {
        Ok(identity) => {
            let location = completion_location(&redirect, None);
            match auth::establish_oidc_session(&state, identity, &location) {
                Ok(mut response) => {
                    clear_flow_cookie(&mut response);
                    Ok(response)
                }
                Err(_) => {
                    tracing::error!("failed to persist an OIDC session");
                    error_response("authentication_failed", &redirect)
                }
            }
        }
        Err(LoginError::ProviderUnavailable) => error_response("provider_unavailable", &redirect),
        Err(LoginError::NotAuthorized) => error_response("not_authorized", &redirect),
        Err(LoginError::AuthenticationFailed) => error_response("authentication_failed", &redirect),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_discovery_server(
        issuer_path: &str,
        issuer_override: Option<String>,
        token_endpoint_override: Option<String>,
        jwks_endpoint_override: Option<String>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let issuer = format!("{origin}{issuer_path}");
        let discovery_path = format!(
            "{}/.well-known/openid-configuration",
            issuer_path.strip_suffix('/').unwrap_or(issuer_path)
        );
        let metadata = serde_json::json!({
            "issuer": issuer_override.unwrap_or_else(|| issuer.clone()),
            "authorization_endpoint": format!("{origin}/authorize"),
            "token_endpoint": token_endpoint_override.unwrap_or_else(|| format!("{origin}/token")),
            "userinfo_endpoint": format!("{origin}/userinfo"),
            "jwks_uri": jwks_endpoint_override.unwrap_or_else(|| format!("{origin}/jwks")),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
        });
        let app = axum::Router::new()
            .route(
                &discovery_path,
                axum::routing::get({
                    let metadata = metadata.clone();
                    move || {
                        let metadata = metadata.clone();
                        async move { axum::Json(metadata) }
                    }
                }),
            )
            .route(
                "/jwks",
                axum::routing::get(|| async { axum::Json(serde_json::json!({ "keys": [] })) }),
            );
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (issuer, handle)
    }

    fn test_config() -> OidcConfig {
        OidcConfig {
            issuer_url: "https://idp.example/tenant/".into(),
            client_id: "routerview".into(),
            client_secret: "test-secret".into(),
            provider_name: "Example SSO".into(),
            groups_claim: "groups".into(),
            viewer_group: "readers".into(),
            admin_group: "operators".into(),
            additional_scopes: vec!["groups".into()],
            ca_pem: None,
            redirect_url: "https://routerview.example/api/auth/oidc/callback".into(),
        }
    }

    #[test]
    fn internal_redirects_reject_external_and_ambiguous_paths() {
        assert_eq!(
            validate_internal_redirect("/traffic?range=day"),
            Ok("/traffic?range=day".into())
        );
        for invalid in [
            "https://example.com",
            "//example.com",
            "/\\example",
            "relative",
            "/bad\npath",
        ] {
            assert!(validate_internal_redirect(invalid).is_err());
        }
    }

    #[test]
    fn callback_query_rejects_duplicates_and_unknown_parameters() {
        assert!(parse_query(Some("state=one&code=two"), &["state", "code", "error"]).is_ok());
        assert!(parse_query(Some("state=one&state=two"), &["state", "code", "error"]).is_err());
        assert!(parse_query(
            Some("state=one&error_description=discarded"),
            &["state", "code", "error", "error_description"]
        )
        .is_ok());
        assert!(parse_query(
            Some("state=one&unexpected=secret"),
            &["state", "code", "error", "error_description"]
        )
        .is_err());
        let callback_fields = [
            "state",
            "code",
            "error",
            "error_description",
            "error_uri",
            "iss",
            "session_state",
            "scope",
            "authuser",
            "prompt",
            "hd",
        ];
        assert!(parse_query(
            Some("state=one&code=two&session_state=s&scope=openid&authuser=0&prompt=none&hd=example.com"),
            &callback_fields,
        )
        .is_ok());
        assert!(parse_query(
            Some("state=one&code=two&session_state=a&session_state=b"),
            &callback_fields,
        )
        .is_err());
    }

    #[test]
    fn flow_store_is_bounded_per_source_and_consumes_once() {
        let source = "192.0.2.10".parse().unwrap();
        let now = Instant::now();
        let mut store = FlowStore::default();
        for index in 0..FLOW_PER_SOURCE {
            store
                .insert(
                    format!("state-{index}"),
                    LoginFlow {
                        nonce: "nonce".into(),
                        pkce_verifier: "pkce".into(),
                        source,
                        redirect: "/".into(),
                        expires_at: now + FLOW_TTL,
                    },
                    now,
                )
                .unwrap();
        }
        assert!(store
            .insert(
                "overflow".into(),
                LoginFlow {
                    nonce: "nonce".into(),
                    pkce_verifier: "pkce".into(),
                    source,
                    redirect: "/".into(),
                    expires_at: now + FLOW_TTL,
                },
                now,
            )
            .is_err());
        assert!(store.consume("state-0", source, now).is_some());
        assert!(store.consume("state-0", source, now).is_none());
    }

    #[test]
    fn flow_store_rejects_cross_source_consumption_and_expires_entries() {
        let source = "192.0.2.10".parse().unwrap();
        let other_source = "192.0.2.11".parse().unwrap();
        let now = Instant::now();
        let mut store = FlowStore::default();
        let flow = |expires_at| LoginFlow {
            nonce: "nonce".into(),
            pkce_verifier: "pkce".into(),
            source,
            redirect: "/sessions".into(),
            expires_at,
        };
        store
            .insert("cross-source".into(), flow(now + FLOW_TTL), now)
            .unwrap();
        assert!(store.consume("cross-source", other_source, now).is_none());
        assert!(store.consume("cross-source", source, now).is_none());

        store
            .insert("expired".into(), flow(now + Duration::from_secs(1)), now)
            .unwrap();
        assert!(store
            .consume("expired", source, now + Duration::from_secs(1))
            .is_none());
    }

    #[test]
    fn flow_store_enforces_global_capacity_and_releases_expired_entries() {
        let now = Instant::now();
        let mut store = FlowStore::default();
        for index in 0..FLOW_CAPACITY {
            let source = IpAddr::V6(std::net::Ipv6Addr::from(index as u128 + 1));
            store
                .insert(
                    format!("state-{index}"),
                    LoginFlow {
                        nonce: "nonce".into(),
                        pkce_verifier: "pkce".into(),
                        source,
                        redirect: "/".into(),
                        expires_at: now + FLOW_TTL,
                    },
                    now,
                )
                .unwrap();
        }

        let extra_flow = |expires_at| LoginFlow {
            nonce: "nonce".into(),
            pkce_verifier: "pkce".into(),
            source: "192.0.2.10".parse().unwrap(),
            redirect: "/".into(),
            expires_at,
        };
        assert!(store
            .insert("over-capacity".into(), extra_flow(now + FLOW_TTL), now,)
            .is_err());
        assert!(store
            .insert(
                "after-expiry".into(),
                extra_flow(now + FLOW_TTL + Duration::from_secs(1)),
                now + FLOW_TTL,
            )
            .is_ok());
        assert_eq!(store.entries.len(), 1);
    }

    #[test]
    fn group_claim_requires_a_string_array_and_admin_wins() {
        let mut values = HashMap::new();
        values.insert("groups".into(), serde_json::json!(["readers", "operators"]));
        assert_eq!(group_claim(&values, "groups").unwrap().unwrap().len(), 2);
        values.insert("groups".into(), serde_json::json!("operators"));
        assert_eq!(
            group_claim(&values, "groups"),
            Err(LoginError::AuthenticationFailed)
        );
    }

    #[test]
    fn verified_token_payload_parser_reads_only_structured_claims() {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"groups":["readers"]}"#);
        let token = format!("header.{payload}.signature");
        let values = id_token_values(&token).unwrap();
        assert_eq!(
            group_claim(&values, "groups").unwrap(),
            Some(vec!["readers".into()])
        );
        let duplicate_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"groups":["readers"],"groups":["operators"]}"#);
        let duplicate_token = format!("header.{duplicate_payload}.signature");
        assert!(id_token_values(&duplicate_token).is_err());
        assert!(id_token_values(&"not-a-jwt").is_err());
    }

    #[test]
    fn role_mapping_prefers_admin_and_rejects_unmapped_users() {
        let config = test_config();
        assert_eq!(
            map_role(&["readers".into(), "operators".into()], &config).unwrap(),
            "admin"
        );
        assert_eq!(
            map_role(&["unrelated".into()], &config),
            Err(LoginError::NotAuthorized)
        );
    }

    #[tokio::test]
    async fn manager_starts_unavailable_and_enforces_static_policy() {
        let config = test_config();
        let fingerprint = policy_fingerprint(&config);
        let manager = OidcManager::new(Some(config.clone())).unwrap();
        assert!(manager.enabled());
        assert!(!manager.available().await);
        assert_eq!(manager.provider_name(), Some("Example SSO"));
        assert!(manager.session_policy_valid("oidc", Some(&fingerprint)));

        let mut changed = config;
        changed.admin_group = "different-operators".into();
        let changed_manager = OidcManager::new(Some(changed)).unwrap();
        assert!(!changed_manager.session_policy_valid("oidc", Some(&fingerprint)));
        let disabled = OidcManager::new(None).unwrap();
        assert!(!disabled.session_policy_valid("oidc", Some(&fingerprint)));
        assert!(disabled.session_policy_valid("password", None));
    }

    #[tokio::test]
    async fn discovery_and_authorization_use_state_nonce_scopes_and_pkce_s256() {
        let (issuer, server) = spawn_discovery_server("", None, None, None).await;
        let mut config = test_config();
        config.issuer_url = issuer;
        let manager = OidcManager::new(Some(config)).unwrap();
        let provider = manager.discover().await.unwrap();
        assert!(matches!(provider.auth_type, AuthType::BasicAuth));
        *manager.provider.write().await = Some(provider);

        let started = manager
            .begin("192.0.2.10".parse().unwrap(), "/sessions".into())
            .await
            .unwrap();
        let authorization_url = url::Url::parse(&started.authorization_url).unwrap();
        let query: HashMap<_, _> = authorization_url.query_pairs().into_owned().collect();
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("routerview")
        );
        assert_eq!(query.get("state"), Some(&started.state));
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        let scopes = query
            .get("scope")
            .unwrap()
            .split(' ')
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(
            scopes,
            ["openid", "profile", "email", "groups"]
                .into_iter()
                .collect()
        );

        let flow = manager
            .consume_flow(&started.state, "192.0.2.10".parse().unwrap())
            .unwrap();
        assert_eq!(query.get("nonce"), Some(&flow.nonce));
        assert_eq!(flow.redirect, "/sessions");
        let verifier = PkceCodeVerifier::new(flow.pkce_verifier);
        let expected_challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some(expected_challenge.as_str())
        );
        server.abort();
    }

    #[tokio::test]
    async fn discovery_appends_well_known_path_to_a_non_trailing_path_issuer() {
        let (issuer, server) = spawn_discovery_server("/realms/routerview", None, None, None).await;
        assert!(!issuer.ends_with('/'));
        assert_eq!(
            discovery_url(&issuer).unwrap(),
            format!("{issuer}/.well-known/openid-configuration")
        );
        let mut config = test_config();
        config.issuer_url = issuer;
        let manager = OidcManager::new(Some(config)).unwrap();
        assert!(manager.discover().await.is_ok());
        server.abort();
    }

    #[tokio::test]
    async fn discovery_rejects_issuer_mismatch_and_insecure_remote_endpoints() {
        let (issuer, mismatched_server) =
            spawn_discovery_server("", Some("https://other-idp.example/".into()), None, None).await;
        let mut config = test_config();
        config.issuer_url = issuer;
        let manager = OidcManager::new(Some(config)).unwrap();
        assert!(manager.discover().await.is_err());
        mismatched_server.abort();

        let (issuer, insecure_server) =
            spawn_discovery_server("", None, Some("http://192.0.2.10/token".into()), None).await;
        let mut config = test_config();
        config.issuer_url = issuer;
        let manager = OidcManager::new(Some(config)).unwrap();
        assert!(manager.discover().await.is_err());
        insecure_server.abort();
        assert!(!secure_endpoint("https://user:password@idp.example/jwks"));
    }

    #[tokio::test]
    async fn http_client_blocks_insecure_jwks_before_any_network_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let blocked_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blocked_address = blocked_listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let blocked_app = axum::Router::new().route(
            "/jwks",
            axum::routing::get({
                let requests = requests.clone();
                move || {
                    let requests = requests.clone();
                    async move {
                        requests.fetch_add(1, Ordering::SeqCst);
                        axum::Json(serde_json::json!({ "keys": [] }))
                    }
                }
            }),
        );
        let blocked_server = tokio::spawn(async move {
            axum::serve(blocked_listener, blocked_app).await.unwrap();
        });

        let blocked_jwks = format!("http://insecure-idp.test:{}/jwks", blocked_address.port());
        let (issuer, discovery_server) =
            spawn_discovery_server("", None, None, Some(blocked_jwks)).await;
        let http = BoundedHttpClient {
            inner: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .resolve("insecure-idp.test", blocked_address)
                .build()
                .unwrap(),
        };
        let mut config = test_config();
        config.issuer_url = issuer;

        assert!(discover_provider(&config, &http).await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        discovery_server.abort();
        blocked_server.abort();
    }

    #[test]
    fn manager_rejects_invalid_private_ca_at_startup() {
        let mut config = test_config();
        config.ca_pem = Some(b"not a PEM certificate".to_vec());
        assert!(matches!(
            OidcManager::new(Some(config)),
            Err(OidcInitError::InvalidCa)
        ));
    }

    #[test]
    fn completion_redirect_encodes_the_internal_deep_link() {
        assert_eq!(
            completion_location("/traffic?range=day&wan=ether1", Some("access_denied")),
            "/login/oidc/complete?redirect=%2Ftraffic%3Frange%3Dday%26wan%3Dether1&error=access_denied"
        );
    }
}

#[cfg(test)]
#[path = "oidc_integration_tests.rs"]
mod integration_tests;
