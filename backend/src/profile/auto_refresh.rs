use std::time::Duration;

use tracing::{info, warn};

use crate::profile::{repo, service};
use crate::state::AppState;

/// 后台定时拉所有 enabled profile 的上游, 内容变化则写入 upstream_history.
/// interval=0 时不启动。最小钳为 60 秒避免误配。
pub fn spawn(state: AppState) {
    let interval = state.config.auto_refresh_interval_secs;
    if interval == 0 {
        info!("auto refresh disabled (AUTO_REFRESH_INTERVAL_SECS=0)");
        return;
    }
    let interval = interval.max(60);
    info!("auto refresh enabled, interval = {}s", interval);
    tokio::spawn(async move {
        // 启动时不立即执行, 等第一个完整 interval
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // 立即触发的第一次 tick, 跳过
        loop {
            ticker.tick().await;
            match repo::list_all_enabled(&state.db).await {
                Ok(profiles) => {
                    info!(
                        "auto refresh: {} enabled profile(s) to fetch",
                        profiles.len()
                    );
                    for p in profiles {
                        if let Err(e) = service::refresh_upstream_by_profile(
                            &state.db,
                            &state.http,
                            &p,
                            service::TRIGGER_AUTO,
                        )
                        .await
                        {
                            warn!(
                                profile_id = %p.id,
                                profile_name = %p.name,
                                error = ?e,
                                "auto refresh failed"
                            );
                        }
                    }
                }
                Err(e) => warn!(error = ?e, "auto refresh: list_all_enabled failed"),
            }
        }
    });
}
