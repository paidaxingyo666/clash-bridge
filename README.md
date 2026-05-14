# Clash Bridge

跳板节点订阅生成器：拉机场 Clash/Mihomo YAML 订阅 → 复制你的固定出口节点并加 `dialer-proxy` 指向勾选的跳板 → 注入回原 yaml，让客户端能切换走"跳板 → 固定出口 → Internet"链路。

## 架构

```
backend/         Rust + Axum + sqlx (PostgreSQL) — REST API + 订阅生成
frontend/        Next.js 15 App Router + TypeScript + Tailwind
deploy/          docker-compose 部署 (复用宿主已有 PostgreSQL)
```

链路设计：

- `/sub/:token/clash.yaml` — 公开订阅 URL. 客户端访问时**实时拉一次上游**机场订阅（带 30s 节流防止打爆机场 IP），解析后**注入式生成**：原 yaml 的 proxies / proxy-groups / rules 完全保留，仅追加链路节点 + 一个 `Bridge-Exit` select 分组 + 每个 exit 一个 `{exit}-auto` url-test 子组 + 一个跨出口跨跳板的 `Bridge-Exit-auto`. 失败时回退到 cached.
- 后台 tokio task 默认每 60 分钟轮询所有 enabled profile 自动刷新上游，**只在内容 hash 变化时**写入 `upstream_history` — 前端可以打开历史弹窗看任意两版 yaml diff.

## 本地开发

需要本地或 Docker 起一个 PostgreSQL.

```bash
cd backend
cp .env.example .env
# 编辑 .env: 填 DATABASE_URL / JWT_SECRET
cargo run
```

```bash
cd frontend
cp .env.example .env.local
# NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8080
npm install
npm run dev
```

数据库 migration 在 `backend/migrations/`, 后端启动自动 apply.

## Docker 部署

详见 [deploy/README.md](deploy/README.md)：

- 复用宿主已有 PostgreSQL 容器（在 `deploy/.env` 里配 `DATABASE_URL` 即可）
- 默认端口：backend `17877`, frontend `17878`
- 入口：`http://<your-host>:17878`

## 关键文件

| 路径 | 说明 |
|---|---|
| `backend/src/generator/yaml.rs` | 注入式生成核心算法 |
| `backend/src/profile/auto_refresh.rs` | 后台定时刷新 task |
| `backend/migrations/*.sql` | DB schema (sqlx auto migrate) |
| `frontend/components/profile-editor.tsx` | 弹窗式订阅配置编辑 (含节点勾选 + 预览 diff) |
| `frontend/components/yaml-diff.tsx` | 行级 yaml diff + 简易语法高亮 |
| `frontend/components/history-dialog.tsx` | 上游历史快照对比 |
| `deploy/docker-compose.yml` | 生产 compose 配置 |

## 当前 MVP 不做

- base64 节点订阅 / v2ray 风格
- 节点测速 / 故障转移策略
- relay (只用 dialer-proxy)
- 用户邀请码 / 注册开关
- 流量统计 / subscription-userinfo 真数据
