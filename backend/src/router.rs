use std::sync::Arc;

use axum::routing::{get, post, put};
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::auth::handler as auth_h;
use crate::exit_node::handler as exit_h;
use crate::history::handler as history_h;
use crate::middleware::CfConnectingIpExtractor;
use crate::profile::handler as profile_h;
use crate::publish::handler as pub_h;
use crate::state::AppState;

pub fn build(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // /api/auth/register 和 /api/auth/login 套 IP 级限流, 其他 /api/* 不限
    // 每客户端 IP 平均每秒 1 次, 短时间内可累计到 burst_size(5) 次
    let auth_governor = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(5)
            .key_extractor(CfConnectingIpExtractor)
            .finish()
            .expect("invalid governor config"),
    );
    let auth_routes = Router::new()
        .route("/register", post(auth_h::register))
        .route("/login", post(auth_h::login))
        .layer(GovernorLayer {
            config: auth_governor,
        });

    let api = Router::new()
        .nest("/auth", auth_routes)
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
        .route("/sub/:token/:format", get(pub_h::public_subscription_fmt))
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
