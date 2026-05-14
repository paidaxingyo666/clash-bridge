use axum::routing::{get, post, put};
use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::auth::handler as auth_h;
use crate::exit_node::handler as exit_h;
use crate::history::handler as history_h;
use crate::profile::handler as profile_h;
use crate::publish::handler as pub_h;
use crate::state::AppState;

pub fn build(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api = Router::new()
        // auth
        .route("/auth/register", post(auth_h::register))
        .route("/auth/login", post(auth_h::login))
        .route("/me", get(auth_h::me))
        // exit nodes (账户级资源)
        .route("/exit-nodes", get(exit_h::list).post(exit_h::create))
        .route(
            "/exit-nodes/:id",
            put(exit_h::update).delete(exit_h::delete),
        )
        // output profiles (核心)
        .route("/profiles", get(profile_h::list).post(profile_h::create))
        .route(
            "/profiles/:id",
            put(profile_h::update).delete(profile_h::delete),
        )
        .route("/profiles/:id/reset-token", post(profile_h::reset_token))
        .route("/profiles/:id/refresh-upstream", post(profile_h::refresh_upstream))
        .route("/profiles/:id/nodes", get(profile_h::list_upstream_nodes))
        .route("/profiles/:id/upstream", get(profile_h::get_upstream_yaml))
        .route("/profiles/:id/generate", post(profile_h::generate))
        .route("/profiles/:id/preview", get(profile_h::preview))
        // history
        .route("/profiles/:pid/history", get(history_h::list))
        .route("/profiles/:pid/history/:hid", get(history_h::get_yaml))
        .route(
            "/profiles/:pid/history/:hid/previous",
            get(history_h::get_previous_yaml),
        );

    Router::new()
        .nest("/api", api)
        .route("/sub/:token/clash.yaml", get(pub_h::public_subscription))
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
