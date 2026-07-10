# RouterView Operations Guide

This guide describes the supported single-site deployment: one Caddy edge
container, one internal backend container, SQLite storage, and a local network
administrator. RouterView is a management interface and must not be exposed to
the public Internet.

## Command status

The container starts the service by invoking `routerview-backend` without a
subcommand. The following maintenance commands are implemented:

- `routerview-backend admin setup [username]`
- `routerview-backend admin reset-password [username]`
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

Validate interpolation and build the images:

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
docker compose run --rm --no-deps backend admin setup
docker compose up -d
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
docker compose run --rm --no-deps backend admin reset-password
docker compose up -d
```

Use the authenticated UI to set the RouterOS password. Do not add
`ROUTER_PASSWORD` to `.env`; the backend must encrypt it with the mounted master
key before storing it.

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
tokens, encryption keys, or upstream response bodies. Export logs before
restarting when investigating a crash loop.

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
docker compose up -d --wait
```

The explicit backup directory keeps the pre-restore recovery backup in
`routerview_backups` rather than under the live data volume. Restore does not
migrate an older schema or verify encrypted credentials, so all three offline
post-restore commands are required. Retain the recovery backup until the
restored instance passes readiness and traffic sampling checks.

## Upgrade and migration

1. Read the release notes and back up the master key separately.
2. Pull or build the target images without stopping the current deployment.
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
   docker compose up -d
   docker compose ps
   ```

Migration refuses to proceed when integrity checks fail, available space is
below 2.2 times the database footprint, plaintext legacy credentials would be
copied into a backup, or a temporary migration table is inconsistent. The
separate `keys verify` steps make decryption a required operational precondition
and postcondition.

For rollback before any new-schema writes, restore the pre-migration backup and
start the previous images. After new-schema writes, first export a compatibility
database while the new binary is still available:

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
docker compose up -d
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
- the deployed image digests and release checksums;
- the Caddy root certificate fingerprint;
- a record of local DNS and firewall configuration.

Recovery is complete only after `keys verify`, `db check`, authenticated login,
WebSocket delivery, RouterOS polling, and a new traffic sample all pass.
