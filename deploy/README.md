# Docker 部署

整套服务（backend + frontend）通过 docker-compose 部署，**复用宿主已有的 PostgreSQL 容器**作为数据库（不再单独跑一个 pg）。

> 下面用 `<your-host>` / `<server-ip>` / `<pg-container>` 等占位符代指你自己的环境。维护时把它们替换成实际值即可。

## 端口与入口

| 项 | 值 |
|---|---|
| Frontend URL | `http://<your-host>:17878` |
| Backend API | `http://<your-host>:17877` |
| 公开订阅 URL 形式 | `http://<your-host>:17877/sub/<token>/clash.yaml` |

端口在 `deploy/.env` 里 `BACKEND_PORT` / `FRONTEND_PORT` 可改。

## 数据库准备

假设宿主已经跑了一个 postgres 容器（设它叫 `<pg-container>`，所在 docker network 叫 `<pg-network>`）。下面用 superuser 在那个 pg 实例里建独立的 db / user：

```bash
docker exec -i <pg-container> psql -U <superuser> -d postgres <<SQL
CREATE USER clash_bridge WITH PASSWORD '<random-strong-password>';
CREATE DATABASE clash_bridge OWNER clash_bridge;
GRANT ALL PRIVILEGES ON DATABASE clash_bridge TO clash_bridge;
\c clash_bridge
GRANT ALL ON SCHEMA public TO clash_bridge;
SQL
```

Schema 由 sqlx migration 自动创建：`users / exit_nodes / output_profiles / upstream_history / _sqlx_migrations`.

## 配置 .env

```bash
cp deploy/.env.example deploy/.env
# 编辑 deploy/.env, 填上数据库密码 / JWT secret / 对外可访问的 host
```

如果你的 postgres 容器跟我们的 backend 不在同一个 docker network，要么改 `docker-compose.yml` 的 `networks.pgnet.name` 让 backend 也加入那个 network，要么改 `DATABASE_URL` 走 `host.docker.internal:5432` 之类宿主直连。

## 容器

| 容器 | 镜像 | 端口映射 | 说明 |
|---|---|---|---|
| `clash-bridge-backend` | `clash-bridge-backend:local` | `${BACKEND_PORT}:8080` | Rust + Axum，启动时跑 migration，spawn auto-refresh task |
| `clash-bridge-frontend` | `clash-bridge-frontend:local` | `${FRONTEND_PORT}:3000` | Next.js 15 (next start) |

两个容器都设置了 `restart: unless-stopped`。backend 同时挂到 pg 所在 network 通过容器名直连。

## 启动

```bash
cd deploy
docker compose build      # 首次 build, backend 编译需要几分钟
docker compose up -d
docker compose ps         # 验证两个容器都 Up
```

## 常用维护

```bash
cd deploy

docker compose ps
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs --tail 200 backend

docker compose restart backend
docker compose restart                # 全部
docker compose down                   # 停 (保留 image)
docker compose up -d                  # 起
```

### 改代码后重新部署

如果是本地开发把代码 rsync 到服务器：

```bash
rsync -av --delete \
  --exclude backend/target --exclude frontend/node_modules \
  --exclude frontend/.next --exclude '.git' \
  --exclude 'deploy/.env' \
  ./ <user>@<server-ip>:/opt/clash-bridge/
```

然后在服务器上：

```bash
cd /opt/clash-bridge/deploy
docker compose build
docker compose up -d
```

### 进数据库

```bash
docker exec -it <pg-container> psql -U clash_bridge clash_bridge
```

如果忘了密码，在 pg 容器内用 superuser 重置：

```bash
docker exec -it <pg-container> psql -U <superuser> -d postgres \
  -c "ALTER USER clash_bridge WITH PASSWORD '<new-password>';"
# 改 deploy/.env 的 DATABASE_URL, docker compose up -d
```

### 重置 / 清空数据

```bash
docker exec -it <pg-container> psql -U <superuser> -d postgres -c "DROP DATABASE clash_bridge;"
docker exec -it <pg-container> psql -U <superuser> -d postgres -c "CREATE DATABASE clash_bridge OWNER clash_bridge;"
# 重启后端让它跑 migration
docker compose restart backend
```

### 关闭后台自动刷新

`deploy/.env` 里加 `AUTO_REFRESH_INTERVAL_SECS=0`，然后 `docker compose up -d` 让 backend 重读 env。

## 排错

**前端访问 / 报错 "fetch failed"**: 浏览器 console 看是不是访问 `http://<your-host>:17877` 失败。如果是, 检查 backend 是不是起来（`docker compose ps`）以及防火墙是否放行 17877。

**订阅 URL 在 Clash Verge 报 400 / 500**: 看 backend 日志。常见原因：

1. `cached_yaml` 是空 — 第一次访问会实时拉上游，看是否拉成功
2. 上游 URL 返回的不是 Clash YAML（UA 不识别）— backend 已用 `clash.meta/1.18.0` UA, 多数机场支持
3. 网络不通 — backend 在 docker 网络内, 出站访问机场 URL 需保证宿主网络出站正常

**JWT_SECRET 改了后老用户被踢**: 这是预期 — 改 secret 等于让所有现有 JWT 失效, 用户需要重新登录. **不影响订阅 URL 的 sub_token**（订阅永久有效）.

## 回滚

镜像 tag 是 `:local`，每次 build 覆盖。回滚要靠 git：

```bash
git checkout <good-commit>
cd deploy && docker compose build && docker compose up -d
```
