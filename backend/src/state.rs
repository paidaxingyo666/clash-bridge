use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::AppConfig;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<AppConfig>,
    pub http: reqwest::Client,
}

impl AppState {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let db = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&config.database_url)
            .await?;

        // 大量机场基于 User-Agent 决定返回 Clash YAML / base64 / 错误页面，
        // 这里假装是 mihomo 客户端拉取，以拿到 Clash YAML 格式。
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.upstream_fetch_timeout_secs))
            .user_agent("clash.meta/1.18.0")
            .build()?;

        Ok(Self {
            db,
            config: Arc::new(config),
            http,
        })
    }
}
