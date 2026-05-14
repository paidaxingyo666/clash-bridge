-- 上游订阅历史快照: 仅当内容 hash 与上一条不同才写入
CREATE TABLE IF NOT EXISTS upstream_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id    UUID NOT NULL REFERENCES output_profiles(id) ON DELETE CASCADE,
    yaml          TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    proxy_count   INT NOT NULL DEFAULT 0,
    -- 'manual' / 'auto'  (PG 里 trigger 是保留字，避开)
    trigger_kind  TEXT NOT NULL,
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_upstream_history_profile_time
    ON upstream_history(profile_id, fetched_at DESC);
