# --- deps ---
FROM node:22-alpine AS deps
WORKDIR /app
# 国内 npm 镜像加速
RUN npm config set registry https://registry.npmmirror.com
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# --- builder ---
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN mkdir -p public
# NEXT_PUBLIC_* 必须在 build 时存在 (浏览器侧代码会被打入静态产物)
ARG NEXT_PUBLIC_API_BASE_URL
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL}
# rewrites 的反代 target 也在 build 时被烤进 .next, 必须 build 时设好
ARG BACKEND_INTERNAL_URL=http://backend:8080
ENV BACKEND_INTERNAL_URL=${BACKEND_INTERNAL_URL}
RUN npm run build

# --- runtime ---
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/node_modules ./node_modules

EXPOSE 3000
CMD ["npx", "next", "start", "-p", "3000", "-H", "0.0.0.0"]
