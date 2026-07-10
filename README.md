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

```bash
cp .env.compose.example .env
install -d -m 0700 secrets
openssl rand -out secrets/routerview_master_key 32
chmod 0444 secrets/routerview_master_key
# Edit .env, especially ROUTERVIEW_DOMAIN and ROUTER_MANAGEMENT_CIDRS.
docker compose config --quiet
docker compose build
docker compose run --rm --no-deps backend admin setup
docker compose up -d
```

The backend has no published port. Do not add one, and do not expose Caddy to
the public Internet. Trust Caddy's local root certificate on each client before
entering credentials. Initial administrator setup, CA installation, backup,
migration, restore, key rotation, and rollback procedures are documented in
[Operations](docs/operations.md).

## Development

Toolchains are pinned in `rust-toolchain.toml` and `.nvmrc`.

```bash
# Terminal 1
mkdir -p secrets
openssl rand -out secrets/routerview-dev-master-key 32
chmod 0600 secrets/routerview-dev-master-key
export ROUTERVIEW_MASTER_KEY_FILE="$PWD/secrets/routerview-dev-master-key"
export PUBLIC_ORIGIN=http://localhost:5173
cargo run --package routerview-backend -- admin setup
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
cd frontend && pnpm install --frozen-lockfile && pnpm typecheck && pnpm test --run && pnpm build
docker compose --env-file .env.compose.example config --quiet
```

Release builds are produced from the root `Dockerfile`; tracked frontend
archives are not used. Tagged releases publish amd64/arm64 backend and Caddy
images, a standalone Linux amd64 backend archive, a frontend archive, checksums,
an SPDX SBOM, and a generated third-party dependency inventory.

## License

RouterView is licensed under the [MIT License](LICENSE).
