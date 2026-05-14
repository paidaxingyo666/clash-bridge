# --- builder ---
# rust:1.85-slim-bookworm 已含 ca-certificates 和 rustc 工具链.
# reqwest 用 rustls + webpki-roots (Cargo.toml 已配), 不依赖系统 OpenSSL/CA, 无需 apt install.
FROM rust:1.93-slim-bookworm AS builder

WORKDIR /build

# 国内 crates 镜像加速 (服务器到 crates.io 极慢, 这里用 USTC sparse 索引)
RUN mkdir -p /usr/local/cargo \
 && printf '[source.crates-io]\nreplace-with = "ustc"\n\n[source.ustc]\nregistry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"\n' > /usr/local/cargo/config.toml

# 用空 main 触发依赖层缓存
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs \
 && cargo build --release \
 && rm -rf src target/release/deps/clash_bridge*

# 真实源码 + migrations
COPY src ./src
COPY migrations ./migrations

RUN cargo build --release \
 && strip target/release/clash-bridge

# --- runtime ---
# rustls 全静态链接 TLS, 不需要 libssl/ca-certificates.
FROM debian:bookworm-slim AS runtime

WORKDIR /app

COPY --from=builder /build/target/release/clash-bridge /app/clash-bridge
COPY --from=builder /build/migrations /app/migrations

ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

ENTRYPOINT ["/app/clash-bridge"]
