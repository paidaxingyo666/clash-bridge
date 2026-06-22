-- 透传上游订阅响应头的 subscription-userinfo (真实流量配额) 到客户端.
-- 拉取成功时把上游 subscription-userinfo 头原样存这里; 失败保留旧值 (COALESCE).
-- publish/handler.rs 的 /sub 响应优先用它作 subscription-userinfo 头, 空/NULL 才回退默认 0 骨架.
-- 顺带可存 profile-update-interval 等 (当前合并进同一字段, 仅取 subscription-userinfo).
ALTER TABLE output_profiles
    ADD COLUMN IF NOT EXISTS last_upstream_userinfo TEXT;
