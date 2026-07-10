# RouterView

RouterView is a self-hosted MikroTik RouterOS monitoring dashboard. A Rust/Axum
service polls the router and stores traffic history in SQLite; a Vue application
consumes the REST and WebSocket APIs.

## Production deployment

The supported production topology is Caddy on ports 80/443 and an unexposed
backend on a private Docker network. Caddy issues a certificate from its local
CA, serves the frontend, and proxies `/api/*` and `/ws` to the backend.

Prerequisites: Docker Engine with Compose v2, a local DNS record for the chosen
name, and a host that can reach the router management network.

Use the Compose file from the same release as both images. For v0.2.0:

```bash
git clone --depth 1 --branch v0.2.0 \
  https://github.com/unDefFtr/RouterView.git routerview
cd routerview
cp .env.compose.example .env
install -d -m 0700 secrets
openssl rand -out secrets/routerview_master_key 32
chmod 0444 secrets/routerview_master_key
```

Edit `.env`, especially `ROUTERVIEW_DOMAIN` and `ROUTER_MANAGEMENT_CIDRS`, and
set both published images to the same exact version:

```dotenv
ROUTERVIEW_BACKEND_IMAGE=ghcr.io/undefftr/routerview-backend:0.2.0
ROUTERVIEW_CADDY_IMAGE=ghcr.io/undefftr/routerview-caddy:0.2.0
```

```bash
docker compose config --quiet
docker compose config --images
docker compose pull
docker compose run --rm --no-deps backend admin setup admin
docker compose up -d --no-build --wait --wait-timeout 180
docker compose ps
```

The GHCR packages are public and do not require `docker login`. Keep backend and
Caddy on the same exact version; do not use the moving `latest` tag for a
production deployment. The Caddy image already contains the matching frontend.
To build from source instead, leave the image variables unset and replace
`docker compose pull` with `docker compose build`. The final `up --no-build`
then uses the images selected by the explicit pull or build step.

The backend has no published port. Do not add one, and do not expose Caddy to
the public Internet. Trust Caddy's local root certificate on each client before
entering credentials. Initial administrator setup, CA installation, backup,
migration, restore, key rotation, and rollback procedures are documented in
[Operations](docs/operations.md).

The Compose topology pins Caddy to a private address and trusts only that `/32`
to supply the client address used by login backoff and WebSocket limits. Direct
deployments leave `TRUSTED_PROXY_CIDRS` empty. A custom reverse proxy must be
listed by its exact source network and must overwrite `X-Real-IP` with one
bare client IP; never trust a LAN range or pass through a client-provided chain.

## Development

Toolchains are pinned in `rust-toolchain.toml` and `.nvmrc`.

```bash
# Terminal 1
mkdir -p secrets
openssl rand -out secrets/routerview-dev-master-key 32
chmod 0600 secrets/routerview-dev-master-key
export ROUTERVIEW_MASTER_KEY_FILE="$PWD/secrets/routerview-dev-master-key"
export PUBLIC_ORIGIN=http://localhost:5173
cargo run --package routerview-backend -- admin setup admin
cargo run --package routerview-backend

# Terminal 2
cd frontend
corepack enable
corepack prepare pnpm@10.24.0 --activate
pnpm install --frozen-lockfile
pnpm dev
```

The backend binds port 3001 on all interfaces; keep that port firewalled from
untrusted networks. Vite listens on `http://localhost:5173` and proxies API and
WebSocket requests to the backend. `PUBLIC_ORIGIN` must exactly match the URL
used in the browser for authenticated mutations and WebSocket connections. The
administrator CLI is an offline writer: stop the backend before using
`admin reset-password` against the same database.

## Verification

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend typecheck
pnpm --dir frontend test --run
pnpm --dir frontend build
pnpm --dir frontend run licenses:test && pnpm --dir frontend run licenses:bundle
docker compose --env-file .env.compose.example config --quiet
```

Release builds are produced from the root `Dockerfile`; tracked frontend
archives are not used. Tagged releases publish amd64/arm64 backend and Caddy
images, a standalone Linux amd64 backend archive, a frontend archive, checksums,
artifact-specific SPDX SBOMs, a generated dependency inventory, and the
corresponding third-party license and notice texts. Container images expose the
texts below `/usr/share/licenses/routerview/third-party/`.

## License

RouterView is licensed under the [MIT License](LICENSE).
