mod auth;
mod config;
mod error;
mod exit_node;
mod generator;
mod history;
mod middleware;
mod parser;
mod profile;
mod publish;
mod router;
mod state;
mod user;

use std::net::SocketAddr;

use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::AppConfig;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = AppConfig::from_env()?;
    let bind: SocketAddr = cfg.bind_addr.parse()?;

    let state = AppState::new(cfg).await?;

    sqlx::migrate!("./migrations").run(&state.db).await?;

    profile::auto_refresh::spawn(state.clone());

    let app = router::build(state);

    info!("listening on {}", bind);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
