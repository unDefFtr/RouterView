# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.91.1
ARG NODE_VERSION=24.4.0
ARG CADDY_VERSION=2.10.2
ARG PNPM_VERSION=10.24.0

FROM rust:${RUST_VERSION}-bookworm AS backend-builder
WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY backend/Cargo.toml backend/Cargo.toml
COPY backend/src backend/src

RUN --mount=type=cache,id=routerview-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=routerview-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=routerview-cargo-target,target=/workspace/target,sharing=locked \
    cargo build --locked --release --package routerview-backend \
    && install -Dm0755 target/release/routerview-backend /out/routerview-backend

FROM node:${NODE_VERSION}-bookworm-slim AS frontend-builder
WORKDIR /workspace/frontend

ARG PNPM_VERSION
ENV PNPM_HOME=/pnpm
ENV PATH=${PNPM_HOME}:${PATH}

RUN corepack enable && corepack prepare "pnpm@${PNPM_VERSION}" --activate
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN --mount=type=cache,id=routerview-pnpm-store,target=/pnpm/store,sharing=locked \
    pnpm config set store-dir /pnpm/store \
    && pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm build

FROM debian:bookworm-slim AS backend-runtime

ARG APP_UID=10001
ARG APP_GID=10001

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid "${APP_GID}" routerview \
    && useradd --system --uid "${APP_UID}" --gid routerview \
        --home-dir /var/lib/routerview --shell /usr/sbin/nologin routerview \
    && install -d -o routerview -g routerview -m 0750 \
        /var/lib/routerview /var/backups/routerview

COPY --from=backend-builder /out/routerview-backend /usr/local/bin/routerview-backend
COPY LICENSE /usr/share/licenses/routerview/LICENSE

ENV DB_PATH=/var/lib/routerview/routerview.db \
    RUST_LOG=info \
    SERVER_PORT=3001

USER ${APP_UID}:${APP_GID}
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:3001/api/health

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/routerview-backend"]

FROM caddy:${CADDY_VERSION}-alpine AS caddy-runtime

ARG APP_UID=10001
ARG APP_GID=10001

RUN addgroup -S -g "${APP_GID}" routerview \
    && adduser -S -D -H -u "${APP_UID}" -G routerview routerview \
    && mkdir -p /srv /data/caddy /config/caddy \
    && chown -R routerview:routerview /srv /data /config

COPY --chown=routerview:routerview deploy/Caddyfile /etc/caddy/Caddyfile
COPY --chown=routerview:routerview --from=frontend-builder /workspace/frontend/dist/ /srv/
COPY LICENSE /usr/share/licenses/routerview/LICENSE

ENV ROUTERVIEW_DOMAIN=routerview.local

USER ${APP_UID}:${APP_GID}
EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-check-certificate --quiet --spider \
        --header="Host: ${ROUTERVIEW_DOMAIN}" https://127.0.0.1/api/health

ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
