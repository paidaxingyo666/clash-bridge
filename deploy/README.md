# 生产部署 — 192.168.0.177

## 基础信息

| 项 | 值 |
|---|---|
| 主机 | `192.168.0.177` (Ubuntu 24.04) |
| 部署目录 | `/opt/clash-bridge` |
| Frontend URL | http://192.168.0.177:17878 |
| Backend API | http://192.168.0.177:17877 |
| 公开订阅 URL 形式 | `http://192.168.0.177:17877/sub/<token>/clash.yaml` |

## 数据库

复用宿主已运行的 `superagent-pg` (postgres:16-alpine) 容器，挂在 docker network `pg-docker_default`. **未占用**已有的 superagent / langfuse 等库，独立建了：

| 项 | 值 |
|---|---|
| 数据库 | `clash_bridge` |
| 用户 | `clash_bridge` (database owner) |
| 密码 | 见 `/opt/clash-bridge/deploy/.env` 的 `DATABASE_URL` |
| 主机内连接 | `psql -h 127.0.0.1 -p 5432 -U clash_bridge clash_bridge` |
| 容器间连接 | `superagent-pg:5432` (通过 `pg-docker_default` network) |

Schema 由 sqlx migration 自动创建：`users / exit_nodes / output_profiles / upstream_history / _sqlx_migrations`.

## 容器

| 容器 | 镜像 | 端口映射 | 说明 |
|---|---|---|---|
| `clash-bridge-backend` | `clash-bridge-backend:local` | `17877:8080` | Rust + Axum，启动时跑 migration，spawn auto-refresh task |
| `clash-bridge-frontend` | `clash-bridge-frontend:local` | `17878:3000` | Next.js 15 standalone-ish (next start) |

两个容器都设置了 `restart: unless-stopped`. backend 同时挂载到 `pg-docker_default` network 连 pg.

## 敏感信息

存放在 `/opt/clash-bridge/deploy/.env`（**禁止入 git**）：

```env
BACKEND_PORT=17877
FRONTEND_PORT=17878
NEXT_PUBLIC_API_BASE_URL=http://192.168.0.177:17877
PUBLIC_BASE_URL=http://192.168.0.177:17877
DATABASE_URL=postgres://clash_bridge:<密码>@superagent-pg:5432/clash_bridge
JWT_SECRET=<48 字节随机串>
```

本机也有一份副本在 `deploy/secrets.local.env` (gitignore 排除).

## 常用维护命令

> SSH 上服务器：`ssh root@192.168.0.177`

### 看状态 / 日志

```bash
cd /opt/clash-bridge/deploy
docker compose ps
docker compose logs -f backend       # 后端日志
docker compose logs -f frontend
docker compose logs --tail 200 backend
```

### 重启 / 停止

```bash
cd /opt/clash-bridge/deploy
docker compose restart backend
docker compose restart                # 全部重启
docker compose down                   # 停止 (保留镜像/网络)
docker compose up -d                  # 启动
```

### 改了代码后重新部署

本地：

```bash
# 在本机项目根目录
rsync -av --delete \
  --exclude backend/target --exclude frontend/node_modules \
  --exclude frontend/.next --exclude '.git' \
  --exclude 'deploy/secrets.local.env' \
  ./ root@192.168.0.177:/opt/clash-bridge/
```

服务器：

```bash
cd /opt/clash-bridge/deploy
docker compose build
docker compose up -d
```

### 进数据库

```bash
docker exec -it superagent-pg psql -U clash_bridge clash_bridge
```

如果忘了密码：在 superagent-pg 容器内以 superuser 重置：

```bash
docker exec -it superagent-pg psql -U superagent -d postgres \
  -c "ALTER USER clash_bridge WITH PASSWORD '<新密码>';"
# 然后改 deploy/.env 的 DATABASE_URL, docker compose up -d
```

### 重置 / 清空数据

```bash
docker exec -it superagent-pg psql -U superagent -d postgres -c "DROP DATABASE clash_bridge;"
docker exec -it superagent-pg psql -U superagent -d postgres -c "CREATE DATABASE clash_bridge OWNER clash_bridge;"
# 重启后端让它跑 migration
cd /opt/clash-bridge/deploy && docker compose restart backend
```

### 关闭后台自动刷新

`deploy/.env` 里加 `AUTO_REFRESH_INTERVAL_SECS=0`，然后 `docker compose up -d` 让 backend 重读 env.

## 排错

**前端访问 / 报错 "fetch failed"**: 浏览器 console 看是不是访问 `http://192.168.0.177:17877` 失败. 如果是, 检查 backend 是不是起来 (`docker compose ps`) 以及防火墙是否放行 17877.

**订阅 URL 在 Clash Verge 报 400 / 500**: 看 backend 日志. 常见原因：

1. `cached_yaml` 是空 — 第一次访问会实时拉上游, 看是否拉成功
2. 上游 URL 返回的不是 Clash YAML (UA 不识别) — backend 已用 `clash.meta/1.18.0` UA, 多数机场支持
3. 网络不通 — backend 在 docker 网络内, 出站访问机场 URL 需保证宿主网络出站正常

**JWT_SECRET 改了后老用户被踢**: 这是预期 — 改 secret 等于让所有现有 JWT 失效, 用户需要重新登录. 不影响订阅 URL 的 sub_token（订阅永久有效）.

## 回滚

镜像 tag 都是 `:local`，每次 build 覆盖. 如果新版本有问题：

```bash
# 用上一次能用的 commit 重新 rsync + build
git checkout <good-commit>
rsync ... 
docker compose build
docker compose up -d
```

(目前项目还没接 git remote, 建议先 git init 把本地 commit 历史固化.)
