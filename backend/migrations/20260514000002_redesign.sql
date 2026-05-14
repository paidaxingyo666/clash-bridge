-- 重构：每条 output_profiles 是一条独立的"输出订阅"，自带 token

DROP TABLE IF EXISTS published_profiles;
DROP TABLE IF EXISTS bridge_rules;
DROP TABLE IF EXISTS user_subscriptions;

ALTER TABLE users DROP COLUMN IF EXISTS sub_token;

CREATE TABLE IF NOT EXISTS output_profiles (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                        TEXT NOT NULL,
    sub_token                   TEXT UNIQUE NOT NULL,

    upstream_url                TEXT NOT NULL,
    last_upstream_yaml          TEXT,
    last_upstream_fetched_at    TIMESTAMPTZ,
    last_upstream_fetch_status  TEXT,
    last_upstream_fetch_error   TEXT,

    -- 勾选的跳板节点 name 列表
    bridge_node_names           JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- 选用的 exit_nodes.id 列表
    exit_node_ids               JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- 自定义 rules 片段 (一行一条)，空表示用默认
    custom_rules                TEXT,

    enabled                     BOOLEAN NOT NULL DEFAULT TRUE,

    -- 缓存：上次 /api/profiles/:id/generate 的产物
    cached_yaml                 TEXT,
    cached_upstream_count       INT NOT NULL DEFAULT 0,
    cached_bridge_count         INT NOT NULL DEFAULT 0,
    cached_chain_count          INT NOT NULL DEFAULT 0,
    cached_missing_bridges      JSONB NOT NULL DEFAULT '[]'::jsonb,
    cached_at                   TIMESTAMPTZ,

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_output_profiles_user ON output_profiles(user_id);
