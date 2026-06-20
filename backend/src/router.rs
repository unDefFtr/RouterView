use std::sync::Arc;

use axum::{routing::{get, post, put}, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::api;
use crate::state::AppState;

/// Create the application router with all routes mounted.
pub fn create_router(state: Arc<AppState>) -> Router {
    // CORS — permissive for development
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/api/health", get(api::system::health_check))
        .route("/api/config", get(api::system::config_info).put(api::system::update_config))
        .route("/api/config/test-connection", post(api::system::test_connection))
        .route("/api/traffic", get(api::traffic::query_traffic))
        .route("/api/devices", get(api::devices::list_overrides))
        .route("/api/devices/{mac}", put(api::devices::update_override))
        .route("/ws", get(crate::ws::handler::ws_upgrade))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
