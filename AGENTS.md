# Coding Agent Instructions

This file applies to the entire RouterView repository. Follow explicit user
instructions first. Otherwise, treat the rules below as the default contract
for repository work.

## Repository Overview

RouterView is a self-hosted MikroTik RouterOS monitoring dashboard:

- `backend/` is a Rust 2021 Axum service using Tokio and `rusqlite`. It polls
  RouterOS, stores traffic history in SQLite, and exposes REST and WebSocket
  APIs.
- `frontend/` is a Vue 3, Pinia, Vite, TypeScript, and Vitest application.
- `compose.yaml`, `Dockerfile`, and `deploy/Caddyfile` define the supported
  production topology. Caddy serves the built frontend and proxies API and
  WebSocket traffic to the unexposed backend.
- `.github/workflows/` defines CI and release publication. `cliff.toml`
  controls generated GitHub Release notes.
- `docs/operations.md` is the source of truth for production operation,
  backup, restore, migration, key rotation, and rollback procedures.

Read the relevant implementation, tests, configuration, and documentation
before changing anything. Prefer established repository patterns and local
helpers over new abstractions or dependencies.

## Required Toolchain

- Use Rust `1.91.1` with the `rustfmt` and `clippy` components, as pinned in
  `rust-toolchain.toml`.
- Use Node.js `24.4.0`, as pinned in `.nvmrc`.
- Use pnpm `10.24.0`, as declared by `frontend/package.json`.
- pnpm is the only supported JavaScript package manager. Never use npm or
  Yarn, and never add `package-lock.json`, `npm-shrinkwrap.json`, or
  `yarn.lock`.
- Use `pnpm install --frozen-lockfile` unless the task explicitly changes
  frontend dependencies. Update `frontend/pnpm-lock.yaml` only through pnpm.
- Use Cargo's locked dependency graph for verification and release commands.
  Include `--locked` whenever the command supports it.

## Working Method

1. Start with `git status --short --branch`. Existing tracked changes and
   untracked files are user-owned unless the task explicitly says otherwise.
2. Search with `rg` and `rg --files`. Inspect nearby code and tests before
   choosing an implementation.
3. Keep edits within the task's ownership boundary. Do not combine feature
   work with unrelated refactors, formatting, dependency churn, or metadata
   updates.
4. Use structured parsers and APIs for structured data. Do not replace a
   reasonable parser with ad hoc string manipulation.
5. Add an abstraction only when it removes meaningful complexity or matches
   an existing repository pattern.
6. Scale tests to risk. Narrow changes need focused tests; shared, security,
   persistence, protocol, or workflow changes need broader coverage.
7. Use `apply_patch` for deliberate manual file edits. Formatting tools and
   mechanical generators may be used when their output is required and
   reviewed.
8. Default new source text to ASCII. Use non-ASCII text only when the product
   content or an existing localized file requires it.
9. Add comments only where intent or a non-obvious invariant would otherwise
   be difficult to recover from the code.

Never discard, overwrite, stage, commit, or clean up unrelated user changes.
Do not use `git stash` as a way to hide them. Do not run destructive commands
such as `git reset --hard`, forced file checkout, `git clean`, or equivalent
operations. If unrelated changes overlap the task, work with them or stop and
explain the conflict.

## Secrets and Generated Output

Never commit or expose:

- RouterOS, administrator, registry, or host credentials.
- Session, CSRF, setup, or pairing tokens.
- Encryption keys or key material, including bytes copied into command-line
  arguments, environment files, logs, or shell history.
- Real or local `.env` files, `secrets/`, databases, SQLite sidecars and lock
  files, backups, local CA certificates, or machine-specific configuration.
  Tracked example templates such as `.env.compose.example` and
  `backend/.env.example` are allowed when the task owns their documentation.
- Generated release directories, dependency inventories, SBOMs, checksum
  files, or other ignored operational output unless the task explicitly owns
  that artifact.

`RELEASE_NOTES.md` is ephemeral output from git-cliff and is not a tracked
changelog. Preserve an existing local copy and do not commit it unless the
user explicitly requests a policy change.

## Git Workflow

For repository edits, use a dedicated task branch. Prefer an isolated worktree
based on the current `origin/main`, especially when the primary worktree is
dirty. If the user already provided a task branch, continue on that branch
instead of creating a competing one.

Before creating the branch:

- Fetch the relevant remote ref when network access is available.
- Confirm the intended base commit.
- Do not alter the primary worktree to make it appear clean.

While working:

- Make small, single-purpose, reversible commits.
- Split configuration, implementation, tests, and documentation when they are
  independently useful or independently reversible. Do not split changes that
  would leave an invalid intermediate state.
- Review the complete diff and the staged diff before every commit.
- Run `git diff --check` before committing.
- Stage only files owned by the task.
- Do not amend, rebase, or rewrite user commits unless explicitly requested.

Unless the user has already explicitly requested a delivery step, stop after
verified commits and report the branch name and commit IDs. Do not merge into
`main`, push, create or move tags, publish packages, or publish a release
unless the user explicitly requests that delivery step.

When the user explicitly requests merge and push:

1. Fetch `origin/main` and check whether it advanced.
2. Require clean task and target worktrees apart from pre-existing user-owned
   files that are demonstrably unrelated.
3. Prefer a fast-forward merge. Do not force a merge strategy merely to hide
   divergence.
4. Push normally. Never force-push and never move or delete an existing
   release tag.
5. Monitor the resulting GitHub Actions run to completion and report failed
   jobs with actionable detail.
6. Remove the temporary worktree and local task branch only after verifying
   that every task commit is reachable from `main`.

## Commit Messages and Release Notes

Use Conventional Commit subjects in the form `type(scope): summary` when a
scope adds useful ownership context. Keep the subject focused and imperative.

`cliff.toml` gives commit types user-visible release semantics:

- `feat` and `perf` appear under `Features and Improvements`.
- `fix`, `security`, and `revert` appear under `Bug Fixes`.
- `doc`, `docs`, `refactor`, `style`, `test`, `chore`, `ci`, `build`, and
  `merge` are intentionally omitted from Release notes.
- Mark breaking changes with `!` or a `BREAKING CHANGE:` footer. Breaking
  changes are protected from normal skip rules.
- Unknown Conventional Commit types make git-cliff fail. Choose an existing
  type intentionally rather than inventing a type during release preparation.

Examples:

```text
feat(frontend): add router health summary
fix(auth): reject expired pairing codes
perf(traffic): reduce history query allocations
test(db): cover interrupted migration recovery
docs(ops): document exact-image rollback
ci(release): verify generated release notes
```

## Validation Baseline

Run the checks relevant to the changed surface. Do not claim a check passed if
it was skipped, interrupted, or only partially executed.

### Backend

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
```

Run focused tests during iteration, then run the complete backend baseline
before delivering changes to shared backend behavior, persistence, security,
configuration, polling, API, or WebSocket code.

### Frontend

```bash
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend typecheck
pnpm --dir frontend test --run
pnpm --dir frontend build
```

The production build includes the bundle-budget check. Add focused Vitest
coverage for changed behavior, including loading, error, empty, authorization,
and responsive state transitions where applicable.

### Licenses and Dependency Inventory

For dependency, packaging, or license changes, also run:

```bash
pnpm --dir frontend run licenses:test
pnpm --dir frontend run licenses:bundle
pnpm --dir frontend audit --prod --audit-level=high
```

Review both Cargo and pnpm lockfile changes. Do not suppress an audit finding
without documenting why the affected code is unreachable or the risk is
otherwise mitigated.

### Compose and Containers

At minimum, validate interpolation:

```bash
docker compose --env-file .env.compose.example config --quiet
```

Changes to `compose.yaml`, `Dockerfile`, Caddy, health checks, networks,
published ports, users, capabilities, filesystems, secrets, or runtime images
require an isolated Compose deployment test. Use a unique project name,
non-conflicting ports, networks, and temporary secrets. Verify:

- Both services reach the expected healthy state.
- `/api/health` returns HTTP 200 and the expected version.
- Caddy serves the frontend and proxies API traffic over HTTPS.
- Container user, read-only root filesystem, capabilities, security options,
  networks, and port bindings remain hardened.
- Expected readiness failures from an unconfigured or unreachable router are
  distinguished from liveness failures.

Always tear down the exact isolated project with volumes and orphans removed.
Never stop, recreate, inspect secrets from, or delete resources belonging to
an existing user deployment.

### GitHub Actions and Release Notes

For workflow changes, run actionlint. The currently verified invocation is:

```bash
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/*.yml
```

Every external `owner/repository@ref` Action reference must be pinned to a full
40-character commit SHA. Local Actions and reusable workflows referenced by a
relative `./` path are exempt. A human-readable version may appear only as an
adjacent comment. Preserve top-level `permissions: {}` and grant the minimum
permissions per job.

For `cliff.toml` or Release-note workflow changes, use git-cliff `2.13.1` and
test all of the following with temporary output outside the repository:

- A future SemVer tag includes only commits after the previous release tag.
- Non-release tags such as `backup/*` do not affect the range.
- Feature, performance, fix, and breaking-change groups render correctly.
- Skipped internal commit types do not appear.
- An all-internal release produces an explicit non-empty body.
- An unknown Conventional Commit type fails generation.
- `--current --strip header --no-exec` works from a tagged commit.

### Documentation-Only Changes

For documentation-only work, run `git diff --check` and verify each command,
path, image name, version rule, and configuration value affected by the edit.
Full application test suites are not required unless executable configuration
or user-visible runtime behavior also changed. State that limitation in the
completion report.

## Backend and Data Safety Invariants

- Preserve API, WebSocket, configuration, and database compatibility unless
  the task explicitly authorizes a breaking change and supplies a migration
  and rollback plan.
- The daemon holds an exclusive lifetime lock for writers. Run `admin`,
  `db migrate`, `db restore`, and key-management writer commands only after
  stopping the backend. Never replace these offline one-shot commands with
  `docker compose exec` against a running daemon.
- Keep online backup operations consistent with SQLite WAL state. Preserve
  integrity checks, foreign-key checks, manifests, atomic replacement,
  fsync behavior, permission hardening, and post-restore verification.
- Never let an older binary open a newer database directly. Preserve the
  compatibility-export and rollback rules in `docs/operations.md`.
- RouterOS credentials must be encrypted with the mounted master key before
  storage. Do not add plaintext password environment variables or fallback
  storage.
- Keep target validation constrained by `ROUTER_MANAGEMENT_CIDRS`. Redirects,
  DNS resolution, proxy variables, and probe targets must not bypass that
  boundary.
- Insecure RouterOS HTTP or TLS behavior must remain an explicit, narrow opt-in
  for a management network.
- Logs and errors must not contain passwords, encryption keys, session or CSRF
  tokens, setup tokens, pairing codes, or upstream response bodies.
- Preserve origin checks, authentication backoff, pairing limits, WebSocket
  source limits, cancellation, bounded queries, and graceful shutdown. Do not
  weaken a security or resource bound merely to make a test pass.

## Frontend Conventions

- Reuse the existing Vue, Pinia, router, composable, FeatherIcon, CSS token,
  and test patterns. Do not introduce a second state manager, icon library, or
  styling system without a demonstrated repository-wide need.
- RouterView is an operational dashboard, not a marketing site. Keep the first
  screen task-focused, information-dense, restrained, and easy to scan.
- Use the existing icon component for familiar actions. Do not add hand-drawn
  SVG controls when an existing icon is available.
- Keep fonts and other required assets local. Do not introduce runtime requests
  to external font or asset CDNs.
- Preserve keyboard access, focus behavior, semantic controls, useful labels,
  and accessible loading, empty, error, and disabled states.
- Avoid nested cards, decorative hero layouts, ornamental gradients or blobs,
  oversized panel typography, and unstable viewport-dependent dimensions.
- Ensure text and controls do not overlap at mobile or desktop widths. Use
  stable grid tracks, aspect ratios, and min/max constraints for fixed-format
  dashboard elements.
- For visual changes, inspect the running UI at representative desktop and
  mobile sizes in addition to automated tests. Check long labels, error text,
  loading transitions, and empty data without allowing layout shifts.

## Deployment and Container Invariants

- The backend must not publish a host port. Only Caddy publishes HTTP and
  HTTPS, and the supported deployment is for a trusted management network, not
  the public Internet.
- Containers run as UID/GID `10001:10001`, with read-only root filesystems,
  all capabilities dropped, and `no-new-privileges`. The backend receives only
  `NET_RAW` for ICMP probes. Do not add `NET_ADMIN`, privileged mode, host
  networking, Docker socket access, or a writable root filesystem.
- Keep the internal application network and the outbound router-access network
  separate. The Caddy edge network is the only network used for published
  ports.
- `TRUSTED_PROXY_CIDRS` must trust only Caddy's exact source address for the
  supported Compose topology. Never trust an entire LAN or a generic private
  range. A custom proxy must overwrite `X-Real-IP` with one bare client IP.
- Keep the master key in a host file under a private directory, mounted
  read-only through the Compose secret. Never generate it inside a tracked
  path or expose its bytes in environment variables.
- Keep Caddy's local CA persistent and require clients to trust its exported
  root certificate. Do not document bypassing certificate errors.

For GHCR deployment:

- Use `compose.yaml` from the same Git release as both images.
- Pin backend and Caddy to the same complete SemVer version or recorded
  digests. Never use moving `latest` or minor-version tags in production.
- The public GHCR packages do not require login. The Caddy image already
  contains the matching frontend.
- Pull explicitly, then start with `--no-build --wait`. Keep source builds as a
  separate path using an explicit `docker compose build`.
- Upgrade and roll back backend and Caddy together. Preserve the documented
  database backup, migration, compatibility-export, and credential-recreation
  requirements.

## Release and Supply-Chain Rules

- Release tags use complete `vX.Y.Z` SemVer syntax, optionally with a valid
  prerelease or build suffix accepted by `cliff.toml`, and must point to commits
  reachable from `origin/main`. Do not repoint an existing release tag.
- Keep the backend package version, frontend package version, Cargo lockfile,
  and release tag synchronized. Preserve `scripts/verify-release-version.mjs`.
- Container image tags omit the leading `v`; Git tag `vX.Y.Z` maps to image tag
  `X.Y.Z`.
- Keep backend and Caddy publication version-locked. A partial image release is
  not a valid production deployment.
- Preserve locked dependencies, checksum generation, SBOM generation,
  third-party license bundles, dependency inventory, secret scanning, and tag
  provenance checks.
- Generate the GitHub Release body from `cliff.toml`. Do not have a tag workflow
  commit generated changelogs or other files back to `main`.

## Completion Standard

Before reporting completion:

1. Review the final diff for scope, correctness, secrets, and accidental
   generated output.
2. Run the applicable validation matrix and ensure all long-running processes
   and test sessions have completed.
3. Confirm task commits contain only intended files.
4. Check final branch and worktree status without deleting user-owned files.
5. Report the branch, commit IDs, significant behavior changes, tests run,
   tests not run, and any residual risk or external verification still needed.

Do not describe a change as verified when only static inspection was performed.
If a required check cannot run because of the environment, state the exact
blocker and leave a reproducible command for the user.
