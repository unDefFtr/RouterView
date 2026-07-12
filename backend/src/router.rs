use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::trace::TraceLayer;

use crate::state::AppState;
use crate::{api, auth, error, oidc};

fn trace_layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    impl Clone + Fn(&axum::http::Request<axum::body::Body>) -> tracing::Span,
> {
    TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<axum::body::Body>| {
        tracing::info_span!(
            "http_request",
            method = %request.method(),
            path = %request.uri().path(),
        )
    })
}

/// Create the application router with all routes mounted.
pub fn create_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route(
            "/api/config",
            get(api::system::config_info).put(api::system::update_config),
        )
        .route(
            "/api/config/test-connection",
            post(api::system::test_connection),
        )
        .route(
            "/api/probes",
            get(api::probes::list_probes).put(api::probes::update_probes),
        )
        .route("/api/probes/reset", post(api::probes::reset_probes))
        .route("/api/traffic", get(api::traffic::query_traffic))
        .route("/api/oui/lookup", get(api::oui::lookup_oui))
        .route("/api/devices", get(api::devices::list_overrides))
        .route("/api/devices/{mac}", put(api::devices::update_override))
        .route("/api/auth/me", get(auth::me))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/sessions", get(auth::list_sessions))
        .route("/api/auth/sessions/{id}", delete(auth::revoke_session))
        .route("/api/auth/pairings", post(auth::create_pairing))
        .route("/ws", get(crate::ws::handler::ws_upgrade))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .route("/api/health", get(auth::health))
        .route("/api/ready", get(api::system::readiness_check))
        .route("/api/auth/status", get(auth::status))
        .route("/api/auth/login", post(auth::login))
        .route(
            "/api/auth/setup",
            post(auth::setup).layer(DefaultBodyLimit::max(4 * 1024)),
        )
        .route("/api/auth/pair", post(auth::pair))
        .route("/api/auth/oidc/start", get(oidc::start))
        .route("/api/auth/oidc/callback", get(oidc::callback))
        .merge(protected)
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(trace_layer())
        .with_state(state)
}

/// Router served only on the loopback setup listener.
pub fn create_setup_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/auth/setup-token", post(auth::issue_setup_token_http))
        .route(
            "/api/auth/setup",
            post(auth::setup_legacy).layer(DefaultBodyLimit::max(4 * 1024)),
        )
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(trace_layer())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf, sync::Arc};

    use axum::http::{header, StatusCode};
    use serde_json::json;

    use crate::{
        auth::{self, AuthSecurity, CSRF_COOKIE, SESSION_COOKIE},
        backends::RouterType,
        config_store::MergedConfig,
        db::TrafficDb,
        oidc::OidcManager,
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

    const PUBLIC_ORIGIN: &str = "https://routerview.test";
    const PASSWORD: &str = "correct horse battery staple";

    struct TestSetupServer {
        base_url: String,
        state: Arc<AppState>,
        directory: PathBuf,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestSetupServer {
        fn drop(&mut self) {
            self.handle.abort();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
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

    async fn test_app_state(directory: &std::path::Path) -> Arc<AppState> {
        let traffic_db = Arc::new(TrafficDb::open(&PathBuf::from(":memory:")).unwrap());
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
        let (setup_shutdown_tx, _) = tokio::sync::watch::channel(false);

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
            public_origin: PUBLIC_ORIGIN.into(),
            auth_security: Arc::new(
                AuthSecurity::new(vec!["127.0.0.1/32".parse().unwrap()]).unwrap(),
            ),
            oidc: Arc::new(OidcManager::new(None).unwrap()),
            setup_token_path: directory.join("setup-token"),
            setup_token_lock: std::sync::Mutex::new(()),
            setup_shutdown_tx,
            poller_control: poll_engine.control(),
            shutdown_tx,
            traffic_query_limit: Arc::new(tokio::sync::Semaphore::new(2)),
        })
    }

    async fn start_setup_server() -> (TestSetupServer, String) {
        let directory = std::env::temp_dir().join(format!(
            "routerview-setup-router-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let state = test_app_state(&directory).await;
        let issued = auth::issue_setup_token(&state.traffic_db, &state.setup_token_path)
            .unwrap()
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = super::create_router(state.clone());
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        (
            TestSetupServer {
                base_url: format!("http://{address}"),
                state,
                directory,
                handle,
            },
            issued.token,
        )
    }

    fn setup_body(token: &str) -> serde_json::Value {
        json!({
            "token": token,
            "username": "Admin",
            "password": PASSWORD,
        })
    }

    fn setup_request(
        client: &reqwest::Client,
        server: &TestSetupServer,
        token: &str,
        source: &str,
    ) -> reqwest::RequestBuilder {
        client
            .post(format!("{}/api/auth/setup", server.base_url))
            .header(header::ORIGIN, PUBLIC_ORIGIN)
            .header("x-real-ip", source)
            .json(&setup_body(token))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn public_setup_route_enforces_the_http_contract() {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let (server, token) = start_setup_server().await;

        let wrong_origin = client
            .post(format!("{}/api/auth/setup", server.base_url))
            .header(header::ORIGIN, "https://routerview.test/")
            .header("x-real-ip", "192.0.2.10")
            .json(&setup_body(&token))
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);

        let invalid_token = "A".repeat(43);
        let invalid = setup_request(&client, &server, &invalid_token, "192.0.2.11")
            .send()
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert!(!invalid.text().await.unwrap().contains(&invalid_token));

        let backed_off = setup_request(&client, &server, &invalid_token, "192.0.2.11")
            .send()
            .await
            .unwrap();
        assert_eq!(backed_off.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(backed_off.headers().contains_key(header::RETRY_AFTER));

        let oversized_token = "B".repeat(5 * 1024);
        let oversized = setup_request(&client, &server, &oversized_token, "192.0.2.12")
            .send()
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!oversized.text().await.unwrap().contains(&oversized_token));

        let created = setup_request(&client, &server, &token, "192.0.2.13")
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(
            created
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        let cookies: Vec<_> = created
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect();
        assert_eq!(cookies.len(), 2);
        assert!(cookies
            .iter()
            .any(|value| value.starts_with(&format!("{SESSION_COOKIE}="))
                && value.contains("; Secure; HttpOnly; SameSite=Strict")));
        assert!(cookies
            .iter()
            .any(|value| value.starts_with(&format!("{CSRF_COOKIE}="))
                && value.contains("; Secure; SameSite=Strict")
                && !value.contains("HttpOnly")));
        assert_eq!(
            created.json::<serde_json::Value>().await.unwrap(),
            json!({
                "username": "admin",
                "display_name": "admin",
                "role": "admin",
                "session_kind": "standard",
                "auth_method": "password",
                "provider_name": null,
                "capabilities": ["read", "configure", "manage_devices", "manage_sessions"],
            })
        );
        assert_eq!(
            server.state.traffic_db.admin().unwrap().unwrap().username,
            "admin"
        );
        assert_eq!(server.state.traffic_db.list_sessions().unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_public_setup_has_one_created_and_one_conflict() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let (server, token) = start_setup_server().await;

        let first = setup_request(&client, &server, &token, "192.0.2.20").send();
        let second = setup_request(&client, &server, &token, "192.0.2.21").send();
        let (first, second) = tokio::join!(first, second);
        let first = first.unwrap();
        let second = second.unwrap();
        let mut statuses = [first.status(), second.status()];
        statuses.sort_by_key(|status| status.as_u16());

        assert_eq!(statuses, [StatusCode::CREATED, StatusCode::CONFLICT]);
        let response_bodies = [first.text().await.unwrap(), second.text().await.unwrap()];
        assert!(response_bodies.iter().all(|body| !body.contains(&token)));
        assert_eq!(server.state.traffic_db.list_sessions().unwrap().len(), 1);
    }
}
