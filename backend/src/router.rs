use std::sync::Arc;

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::trace::TraceLayer;

use crate::state::AppState;
use crate::{api, auth, error};

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
        .route("/api/auth/pair", post(auth::pair))
        .merge(protected)
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Router served only on the loopback setup listener.
pub fn create_setup_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/auth/setup", post(auth::setup))
        .fallback(error::not_found)
        .method_not_allowed_fallback(error::method_not_allowed)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
