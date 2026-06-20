-- 让 output_profiles 拉取上游订阅时可走某个 exit_node 当 socks5/http 代理
-- 用途: 上游订阅源对数据中心 IP 做了拦截 (如 huacloud 403), 通过用户的纯净住宅 IP 节点出去
-- 节点删除时只把这里置 NULL, profile 自动回退到直连
ALTER TABLE output_profiles
    ADD COLUMN IF NOT EXISTS fetch_via_exit_node_id UUID
        REFERENCES exit_nodes(id) ON DELETE SET NULL;
