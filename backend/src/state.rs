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
            // 限制重定向跳数, 防订阅源把我们引去内网 / 无限重定向 (配合归一化层的 SSRF 单租户可信假设)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()?;

        Ok(Self {
            db,
            config: Arc::new(config),
            http,
        })
    }
}
