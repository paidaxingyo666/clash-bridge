-- 让 output_profiles 记录上游订阅的输入格式 (auto/clash/base64/uri/sip008)
-- auto = 自动探测; 其余为显式指定, 跳过探测直接走对应 parser
-- 归一化层会把任意格式都转成 {proxies: [...]} 的 Clash YAML 再存 last_upstream_yaml
ALTER TABLE output_profiles
    ADD COLUMN IF NOT EXISTS upstream_format TEXT NOT NULL DEFAULT 'auto';
