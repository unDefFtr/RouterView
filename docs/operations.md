# RouterView Operations Guide

This guide describes the supported single-site deployment: one Caddy edge
container, one internal backend container, SQLite storage, and a local network
administrator. RouterView is a management interface and must not be exposed to
the public Internet.

## Command status

The container starts the service by invoking `routerview-backend` without a
subcommand. The following maintenance commands are implemented:

- `routerview-backend admin setup [USERNAME]`
- `routerview-backend admin reset-password [USERNAME]`
- `routerview-backend db check`
- `routerview-backend db migrate`
- `routerview-backend db backup FILE`
- `routerview-backend db restore FILE`
- `routerview-backend db export-legacy FILE`
- `routerview-backend keys verify`
- `routerview-backend keys rotate --new-key-file PATH`

`db check` and `db backup` are read-only, online-safe operations. The daemon
holds an exclusive lifetime lock for all writers. Run `admin`, `db migrate`,
`db restore`, and `keys` commands only after stopping the backend. Never use
`docker compose exec` for those offline commands.

`USERNAME` is optional and defaults to `admin`, but the examples below pass it
explicitly. `admin setup` creates the initial username. `admin reset-password`
also sets the username to the supplied value, so pass the current username
unless intentionally renaming the administrator.

## Host preparation

1. Install Docker Engine and the Compose v2 plugin. Allocate free disk space of
   at least 2.2 times the current SQLite database size before an upgrade.
2. Give the host a stable LAN address. Create a DNS A/AAAA record, such as
   `routerview.local`, that resolves to that address from administrator devices.
3. Restrict inbound TCP 80/443 to the management LAN in the host firewall.
   RouterView does not require any other inbound port.
4. Copy `.env.compose.example` to `.env`. Set `ROUTERVIEW_DOMAIN` and narrow
   `ROUTER_MANAGEMENT_CIDRS` to the actual router management subnet.
5. Create the encryption key without putting its bytes in shell history:

   ```bash
   install -d -m 0700 secrets
   openssl rand -out secrets/routerview_master_key 32
   chmod 0444 secrets/routerview_master_key
   ```

Docker Compose implements a local file-backed secret as a bind mount and may
ignore the requested container UID/GID/mode. The key is therefore read-only but
world-readable while its parent directory is mode 0700. The private directory
prevents other host users from traversing to the file, while UID 10001 in the
container can read the mounted file. Do not place the key in a shared directory.

Keep an offline backup of this key. Losing it makes encrypted RouterOS
credentials unrecoverable. Never commit `.env`, `secrets/`, database files, or
backup files.

## Install and first setup

Use `compose.yaml` from the same Git release as the images. Mixing a newer
Compose model with older containers is unsupported.

### Published GHCR images

The v0.2.1 images are public and support `linux/amd64` and `linux/arm64`. Set
both image variables in `.env` to the same exact version:

```dotenv
ROUTERVIEW_BACKEND_IMAGE=ghcr.io/undefftr/routerview-backend:0.2.1
ROUTERVIEW_CADDY_IMAGE=ghcr.io/undefftr/routerview-caddy:0.2.1
```

Validate the resolved image names and pull them before running any one-shot
maintenance command:

```bash
docker compose config --quiet
docker compose config --images
docker compose pull
```

No GHCR login is required for these public packages. Production deployments
must use an exact version or OCI index digest, not the moving `latest` or `0.2`
tags. The backend and Caddy images must always be upgraded or rolled back
together. The Caddy image contains the frontend built from the same release.

### Local source build

To build the same checkout locally instead, leave `ROUTERVIEW_BACKEND_IMAGE`
and `ROUTERVIEW_CADDY_IMAGE` unset, then run:

```bash
docker compose config --quiet
docker compose build
```

The backend is attached to an internal application network and an outbound
router-access network, but it has no published port. Only Caddy publishes
80/443. Both containers run as UID/GID 10001 with read-only root filesystems,
`no-new-privileges`, and all capabilities dropped. The backend receives only
`NET_RAW` for ICMP probes.

The application network uses `172.31.254.0/29`; Caddy is pinned to
`172.31.254.2`, and `TRUSTED_PROXY_CIDRS` trusts only that address. This lets the
backend apply login and WebSocket source limits to the actual client while
ignoring forged forwarding headers on direct connections. If that subnet
conflicts with the host network, change the application subnet, both static
container addresses, and `TRUSTED_PROXY_CIDRS` together. For a different proxy,
use only its directly connected source network and configure it to overwrite
`X-Real-IP` with exactly one IP address. Do not trust an entire LAN or a
generic private-address range.

Initialize the first administrator before starting the daemon. The one-shot
container mounts the same database and master-key secret as the service:

```bash
docker compose run --rm --no-deps backend admin setup admin
docker compose up -d --no-build --wait --wait-timeout 180
docker compose ps
```

Do not replace this with `docker compose exec`: a running daemon owns the
database lock, so a second writer correctly refuses to start. If the daemon is
started before an administrator exists, it creates a 15-minute setup token and
loopback-only setup listener as a recovery mechanism. The token file is mode
0600 on the backend's private tmpfs, and Caddy always returns 404 for
`/api/auth/setup`; it is not a browser-facing endpoint.

A forgotten administrator password is recovered with an offline one-shot
container. Resetting it revokes all existing sessions and unused pairing codes:

```bash
docker compose stop caddy backend
docker compose run --rm --no-deps backend admin reset-password admin
docker compose up -d --no-build --wait --wait-timeout 180
```

Use the authenticated UI to set the RouterOS password. Do not add
`ROUTER_PASSWORD` to `.env`; the backend must encrypt it with the mounted master
key before storing it.

## OpenID Connect operations

OpenID Connect is optional and supplements the local administrator account. It
does not replace local setup, password recovery, or fixed-device pairing. Keep
the local administrator credential available offline before enabling SSO; it is
the recovery path when the identity provider or its network path is unavailable.

### Provider registration and role mapping

Create one confidential OpenID Connect web client that supports Authorization
Code Flow and PKCE S256. Pure OAuth 2.0 providers and provider-specific OAuth
adapters are not supported. Register exactly this callback, substituting the
configured `ROUTERVIEW_DOMAIN`:

```text
https://routerview.local/api/auth/oidc/callback
```

The backend derives this URI from `PUBLIC_ORIGIN`; it never derives it from the
request `Host` or forwarding headers. Do not register wildcard callbacks or a
second callback that uses plain HTTP.

Use the provider's exact issuer URL. It must be an absolute HTTPS URL without
userinfo, a query, or a fragment. Plain HTTP is accepted only for loopback
development. The issuer returned by Discovery must exactly match the configured
value, and the discovered authorization, token, UserInfo, and JWKS endpoints
must also use HTTPS outside loopback development.

RouterView always requests `openid profile email`. Put any provider-specific
scope required to release group membership in `OIDC_ADDITIONAL_SCOPES`; values
may be separated by commas or ASCII whitespace and are deduplicated. Configure
`OIDC_GROUPS_CLAIM` for a top-level claim whose value is an array of strings.
Set distinct `OIDC_VIEWER_GROUP` and `OIDC_ADMIN_GROUP` values:

- a member of the admin group receives the `admin` role;
- otherwise, a member of the viewer group receives the `viewer` role;
- a subject in neither group is denied; and
- a subject in both groups receives the `admin` role.

Authorization is tied to the exact provider issuer and `sub`. Display name,
preferred username, and email are presentation fields only and are never used
as authorization identities.

### Secret files and Compose activation

The client secret must be UTF-8, no larger than 4096 bytes, and non-empty after
trailing CR/LF removal. It is not accepted through an environment variable.
Create the file without putting the secret in argv, `.env`, or shell history:

```bash
install -m 0600 /dev/null secrets/routerview_oidc_client_secret
${EDITOR:-vi} secrets/routerview_oidc_client_secret
chmod 0444 secrets/routerview_oidc_client_secret
```

As with the master key, Compose implements the secret with a read-only bind
mount. Keep `secrets/` mode 0700; mode 0444 on the file lets UID 10001 read it
inside the container without making the parent directory traversable to other
host users. Store backup copies in a secret manager, not with database backups.

Copy the OIDC block from `.env.compose.example` into `.env`, then set:

```dotenv
COMPOSE_FILE=compose.yaml:compose.oidc.yaml
OIDC_ISSUER_URL=https://idp.example.com/application/o/routerview
OIDC_CLIENT_ID=routerview
OIDC_CLIENT_SECRET_SOURCE=./secrets/routerview_oidc_client_secret
OIDC_PROVIDER_NAME=Company SSO
OIDC_GROUPS_CLAIM=groups
OIDC_VIEWER_GROUP=routerview-viewers
OIDC_ADMIN_GROUP=routerview-admins
OIDC_ADDITIONAL_SCOPES=
```

`COMPOSE_FILE` makes ordinary `docker compose` commands use the same base and
OIDC overlay. Keep the exact same overlay combination for configuration checks,
pulls, one-shot maintenance, startup, inspection, backup, and shutdown. Validate
the effective model before recreating the backend:

```bash
docker compose config --quiet
docker compose config --images
docker compose up -d --no-build --wait --wait-timeout 180
```

For a provider whose certificate chains only to a private CA, place the CA
certificate and any intermediates in a PEM bundle. Do not put a client private
key or leaf-server private key in this file. Set the file mode to 0444 inside
the private `secrets/` directory so UID 10001 can read the bind mount. Add the
CA-only overlay and source:

```dotenv
COMPOSE_FILE=compose.yaml:compose.oidc.yaml:compose.oidc-ca.yaml
OIDC_CA_SOURCE=./secrets/routerview_oidc_ca.pem
```

The third overlay mounts the PEM bundle read-only and sets the in-container
`OIDC_CA_FILE`. There is no insecure TLS option. Keep using only the first two
files when the issuer chains to a public root; the CA file is then neither
required nor mounted.

### Network, time, and outage behavior

The backend uses the existing outbound `router_access` network for Discovery,
JWKS, token, and optional UserInfo requests. If the host or container network
has an egress policy, allow DNS plus HTTPS to every hostname advertised by the
provider. Do not add a backend host port, host networking, a broad proxy trust
range, or extra Linux capabilities. The OIDC client does not follow HTTP
redirects or inherit proxy environment variables.

Keep the Docker host clock synchronized with a reliable NTP source. Large clock
skew causes valid provider tokens to fail issuer-time checks. After startup,
verify the public status without exposing configuration details:

```bash
curl --fail --cacert routerview-local-ca.crt \
  "https://${ROUTERVIEW_DOMAIN}/api/auth/status"
```

Discovery runs in the background with bounded retry backoff. If the provider,
DNS, or outbound route fails, the login page marks SSO unavailable while local
password login and existing RouterView sessions continue working. `/api/health`
and `/api/ready` retain their existing process/router semantics and do not fail
only because the identity provider is down. Do not redirect either health check
to the provider.

The backend exchanges the authorization code and stores no provider token in
the browser. After login, authorization uses RouterView's local session cookie;
an IdP outage therefore does not invalidate an established session. RouterView
logout revokes only that local session and does not invoke provider logout.

### Rotation, disabling, and emergency revocation

Prefer a provider that permits two active client secrets during rotation. Add
the replacement at the provider, write it to a new private host file, point
`OIDC_CLIENT_SECRET_SOURCE` at that file, and recreate only the backend:

```bash
docker compose up -d --no-deps --no-build --force-recreate \
  --wait --wait-timeout 180 backend
```

Verify a new OIDC login before revoking and deleting the old secret. If the
provider cannot overlap secrets, schedule a maintenance window; local login and
existing sessions remain available during the cutover. A client-secret change
does not itself revoke existing RouterView sessions because provider tokens are
not used after login.

For a private-CA rotation, first build a PEM bundle containing every trust
anchor needed during the overlap. Point `OIDC_CA_SOURCE` at the staged bundle,
recreate the backend, and verify Discovery and a fresh login before rotating the
provider certificate. Remove the old anchor in a second backend recreation only
after the provider serves the new chain. Never work around a failed rotation by
disabling TLS verification.

Changing the issuer, client ID, group-claim name, or viewer/admin group mapping
changes the OIDC authorization-policy fingerprint and invalidates existing OIDC
sessions. A temporary provider outage does not. To disable SSO, set
`COMPOSE_FILE=compose.yaml`, validate the base model, and recreate the backend;
local password and pairing sessions remain available while OIDC sessions become
invalid:

```bash
docker compose config --quiet
docker compose up -d --no-deps --no-build --force-recreate \
  --wait --wait-timeout 180 backend
```

Disabling a subject or removing a group at the provider prevents authorization
at the next OIDC login, but it does not push revocation into an already-issued
RouterView session. For immediate individual revocation, change the provider
membership and revoke every matching session in RouterView's session page. For
an incident affecting all SSO users, disable OIDC as above. Resetting the local
administrator password remains the broad recovery action: it revokes all
RouterView sessions and all unused pairing codes.

An OIDC administrator may create a viewer fixed-device pairing. Creating an
administrator pairing still requires the local administrator password; never
enter an IdP password into that prompt.

## Trust the local CA

Caddy persists its CA under the `caddy_data` volume. After first start, export
the public root certificate:

```bash
docker compose cp \
  caddy:/data/caddy/pki/authorities/local/root.crt \
  ./routerview-local-ca.crt
```

Verify its SHA-256 fingerprint out of band before installing it. Import it only
into administrator devices that should trust this RouterView deployment:

- macOS: Keychain Access, System keychain, import the certificate, then set SSL
  trust to Always Trust.
- Windows: import into Local Computer > Trusted Root Certification Authorities.
- Debian/Ubuntu: place it under `/usr/local/share/ca-certificates/` with a
  `.crt` suffix and run `sudo update-ca-certificates`.
- Firefox with an independent trust store: import it under Authorities and
  enable website identification trust.

Remove the old root from client trust stores after a Caddy data-volume loss or
intentional CA rotation. Do not bypass certificate errors: doing so removes the
protection for administrator credentials and session cookies.

## Health and logs

`/api/health` is the process liveness endpoint used by Compose. `/api/ready`
returns 200 only after a recent successful poll; it returns 503 while the
poller is starting, degraded, stopped, or stale. Readiness exposes stable reason
codes and counters but not internal RouterOS or database error details.

```bash
docker compose ps
docker compose logs --since=15m backend
docker compose logs --since=15m caddy
curl --fail --cacert routerview-local-ca.crt \
  "https://${ROUTERVIEW_DOMAIN}/api/health"
curl --fail --cacert routerview-local-ca.crt \
  "https://${ROUTERVIEW_DOMAIN}/api/ready"
```

An unconfigured or unreachable router makes readiness fail without making
liveness fail. Use the authenticated settings UI and backend logs to diagnose
that state; do not point the Compose health check at `/api/ready`.

Logs must never contain RouterOS passwords, session tokens, CSRF tokens, setup
tokens, encryption keys, OIDC authorization codes, state, nonce, PKCE verifiers,
provider tokens, sensitive claims, or upstream response bodies. Export logs
before restarting when investigating a crash loop.

## Database backup and restore

`routerview_data` holds the live SQLite database. `routerview_backups` is a
separate volume mounted at `/var/backups/routerview`. Never copy only the main
database file while the service is running because committed rows may still be
in the WAL.

Create and verify an online backup through SQLite's backup API:

```bash
docker compose exec backend routerview-backend db check
docker compose exec backend routerview-backend db backup \
  /var/backups/routerview/routerview-$(date +%Y%m%dT%H%M%S).db
```

The backup command runs a full integrity and foreign-key check, copies a
consistent SQLite snapshot including committed WAL state, verifies schema and
row counts, writes through a temporary file, fsyncs, atomically renames, sets
mode 0600, and writes a SHA-256 manifest beside the backup. Copy both files to
offline storage. Regularly test restore on a disposable Compose project.

Restore is an offline maintenance operation. Stop both long-running containers
and run a one-off backend container against the same volumes:

```bash
docker compose stop caddy backend
docker compose run --rm --no-deps backend db restore \
  /var/backups/routerview/routerview-YYYYMMDDTHHMMSS.db \
  --backup-dir /var/backups/routerview
docker compose run --rm --no-deps backend db migrate \
  --backup-dir /var/backups/routerview
docker compose run --rm --no-deps backend db check
docker compose run --rm --no-deps backend keys verify
docker compose up -d --no-build --wait --wait-timeout 180
```

The explicit backup directory keeps the pre-restore recovery backup in
`routerview_backups` rather than under the live data volume. Restore does not
migrate an older schema or verify encrypted credentials, so all three offline
post-restore commands are required. Retain the recovery backup until the
restored instance passes readiness and traffic sampling checks.

## Upgrade and migration

1. Read the release notes, record the current output of
   `docker compose config --images`, and back up the master key separately.
2. Update the checkout to the target Git release so its `compose.yaml` matches
   the target containers. Prepare both target images without stopping the
   current deployment. For a GHCR deployment, update both image variables to
   the same exact version and pull them:

   ```bash
   docker compose config --images
   docker compose pull
   ```

   For a source deployment, build the checked-out release instead:

   ```bash
   docker compose build
   ```

   Never upgrade only one image or use `latest` for a production upgrade.
3. While the current backend is still running, create an online backup:

   ```bash
   docker compose exec backend routerview-backend db backup \
     /var/backups/routerview/pre-migration.db
   ```

4. Stop Caddy and the backend, then verify the active key and run the offline
   preflight and migration commands:

   ```bash
   docker compose stop caddy backend
   docker compose run --rm --no-deps backend keys verify
   docker compose run --rm --no-deps backend db check
   docker compose run --rm --no-deps backend db migrate \
     --backup-dir /var/backups/routerview
   docker compose run --rm --no-deps backend db check
   docker compose run --rm --no-deps backend keys verify
   ```

5. Start the stack and verify HTTPS login, WebSocket updates, RouterOS
   connectivity, the first exact traffic sample, and retained historical data:

   ```bash
   docker compose up -d --no-build --wait --wait-timeout 180
   docker compose ps
   ```

Migration refuses to proceed when integrity checks fail, available space is
below 2.2 times the database footprint, plaintext legacy credentials would be
copied into a backup, or a temporary migration table is inconsistent. The
separate `keys verify` steps make decryption a required operational precondition
and postcondition.

For a GHCR rollback, set both image variables to the previous exact version or
recorded digests and run `docker compose pull` before restoring and starting the
stack. Never mix backend and Caddy versions. Before any new-schema writes,
restore the pre-migration backup and start the previous images. After new-schema
writes, first export a compatibility database while the new binary is still
available:

```bash
docker compose stop caddy backend
docker compose run --rm --no-deps backend db export-legacy \
  /var/backups/routerview/routerview-legacy-export.db
```

The export contains legacy traffic, non-secret configuration, device overrides,
probe targets, quality metadata, and a checksum manifest. It intentionally
excludes administrators, sessions, pairing codes, and encrypted credentials;
recreate those on the older release. Never point an older binary directly at a
newer database, and never rely on `git revert` as a database rollback.

## Master-key verification and rotation

Key maintenance is an offline operation. The backend holds an exclusive
database lock for its full lifetime, so do not use `docker compose exec` for
these commands. Stop the service and run a one-shot container instead:

```bash
docker compose stop caddy backend
docker compose run --rm --no-deps backend keys verify
```

`keys verify` reads the database from `DB_PATH` and the active key only from
the file named by `ROUTERVIEW_MASTER_KEY_FILE`. It decrypts every encrypted
field and exits nonzero if the database is locked, the key is wrong, or any
encrypted row is corrupt. It refuses to create a database when `DB_PATH` does
not exist.

Rotate only during a maintenance window after taking a verified database
backup. Create a staged key without putting its bytes in argv or an environment
variable:

```bash
openssl rand -out secrets/routerview_master_key.next 32
chmod 0444 secrets/routerview_master_key.next

docker compose stop caddy backend
docker compose run --rm --no-deps \
  --volume "${PWD}/secrets/routerview_master_key.next:/run/secrets/routerview_master_key.next:ro" \
  backend keys rotate --new-key-file /run/secrets/routerview_master_key.next
```

The command first verifies every row with the active key, reencrypts all rows
in one immediate transaction, and decrypts and compares every written row
before commit. Any error rolls back the complete rotation. The new key's bytes
are accepted only through `--new-key-file`; there is no argv or environment
option for key material.

After a successful rotation, change `ROUTERVIEW_MASTER_KEY_SOURCE` in `.env` to
`./secrets/routerview_master_key.next`, verify with the newly mounted key, and
then restart the stack:

```bash
docker compose run --rm --no-deps backend keys verify
docker compose up -d --no-build --wait --wait-timeout 180
docker compose ps
```

Retain the old key and the pre-rotation database backup offline until the new
deployment and a new backup have both passed verification. Rolling back after
a committed rotation requires restoring that database backup together with the
old key; changing only the key file leaves the database undecryptable.

## ICMP and container security

The backend's `NET_RAW` capability is required only for ICMP latency probes. It
does not require `NET_ADMIN`, privileged mode, host networking, access to the
Docker socket, or a writable root filesystem. If a rootless runtime cannot grant
`NET_RAW`, disable ICMP probes or use supported unprivileged ping settings; do
not run the whole container as root.

The `router_access` bridge permits outbound access because RouterOS and probe
targets are outside Docker. Backend target validation remains mandatory:
resolved addresses must fall within `ROUTER_MANAGEMENT_CIDRS`, redirects and
proxy environment variables must not escape that policy, and insecure HTTP is
allowed only when explicitly enabled for a management subnet.

The Caddy-only `edge` bridge is intentionally not marked `internal`; Docker
Desktop does not reliably publish host ports for a container attached only to
internal networks. This also gives Caddy a general outbound route. On hardened
Linux hosts, use the `DOCKER-USER` chain to reject new outbound connections
sourced from the `routerview_edge` subnet while allowing `ESTABLISHED,RELATED`
traffic so published client connections can return normally. Apply an
equivalent container-egress policy on Docker Desktop or other runtimes. Caddy
reaches the backend over the separate internal `app` network.

## Disaster recovery checklist

Keep these items outside the Docker host:

- a recent verified SQLite backup and its SHA-256 checksum;
- the matching master key, stored separately from the database;
- `.env` without plaintext credentials;
- the OIDC issuer, client ID, callback, scopes, and role-group mapping;
- the OIDC client secret in a secret manager, separate from database backups;
- any private OIDC CA bundle and its verified fingerprint;
- the deployed image digests and release checksums;
- the Caddy root certificate fingerprint;
- a record of local DNS and firewall configuration.

Recovery is complete only after `keys verify`, `db check`, authenticated login,
WebSocket delivery, RouterOS polling, and a new traffic sample all pass. For an
OIDC-enabled recovery, also verify Discovery, one viewer login, one administrator
login, role enforcement, and the exact callback before revoking old credentials.
