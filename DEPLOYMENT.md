# Deployment baseline

This is a baseline, not a production certification.

## Services

1. `crisisweave-platform` on an internal application network.
2. `crisisweave-worksites` on the same private network.
3. TLS reverse proxy/load balancer in front of the platform.
4. Persistent encrypted storage for operational/private databases.
5. Read-only verified incident and alert feeds, or an equivalent managed feed service.
6. Optional internal Prometheus scraper for the instrumented `/metrics` endpoint.

The platform should be the externally visible API boundary. Avoid exposing the worksites write API directly. Keep `/metrics` private even when the platform API has a public TLS hostname.

## Environment

Required:

- `CW_TOKEN_PEPPER`
- `CW_WORKSITES_URL`
- `CW_DB`
- `CW_PRIVATE_DB`
- `CW_WORKSITES_TOKEN` when upstream writes are protected

Recommended:

- `CW_TOKEN_TTL_HOURS=24`
- `CW_ALLOWED_ORIGIN=https://crisisweave.netlify.app` or another exact trusted frontend origin

Optional:

- `CW_VERIFIED_FEED`
- `CW_ALERTS_FEED`
- `CW_HOST`
- `CW_PORT`
- `CW_RATE_LIMIT_PER_MINUTE`

`CW_ALLOWED_ORIGIN` accepts a comma-separated list of exact HTTP(S) origins. Do not use `*` for the authenticated API.

## Runtime choice

The base CLI remains available:

```bash
python crisisweave_platform.py serve
```

The container uses the instrumented equivalent by default:

```bash
python prometheus_server.py
```

Both use the same application handler, RBAC, databases and worksite client. The instrumented variant adds `/metrics` with low-cardinality aggregate values only.

## Token operations

Issue short-lived credentials where possible. CLI-issued tokens default to 24 hours.

```bash
python crisisweave_platform.py issue-token coord-1 --ttl-hours 8
python crisisweave_platform.py list-tokens coord-1
python crisisweave_platform.py revoke-token tok_...
```

Deactivating a principal revokes all of its existing tokens. Reactivation does not revive old credentials.

## Storage and backup

Keep databases on persistent encrypted storage. Create backups with:

```bash
python crisisweave_platform.py backup --out /secure-backups
```

A successful backup run performs SQLite integrity checks and writes a SHA256 manifest. Before restoring, verify the selected file again:

```bash
python crisisweave_platform.py verify-backup /secure-backups/platform-....sqlite3
```

Keep backups off-host as well as on persistent storage, encrypt them, restrict access, and rehearse restoration. `crisisweave-infra/deploy/dr` documents a Litestream + restic recovery profile without embedding storage credentials.

## Private-record concurrency

Private records expose integer versions through `ETag`. Mutation clients that may race should send the last observed version using `If-Match`. Stale updates and deletes return `409` rather than overwriting newer state.

## Reverse proxy

Terminate TLS before the Python service and enforce request-size and timeout limits. Do not trust arbitrary forwarded client headers. Preserve or generate a request ID, but never log bearer tokens or private payloads.

The application itself also emits baseline security headers and request IDs. These are defense in depth, not a replacement for reverse-proxy policy. `crisisweave-infra/deploy/edge` contains a Caddy profile that blocks `/metrics` at the public edge.

## Failure behavior

`/healthz` checks both local databases. `/readyz` additionally checks the worksite service. Worksite upstream network failures are translated to `502` instead of dropping the client connection.

## Scaling

SQLite is suitable for this MVP and small single-instance deployments. Litestream can improve disaster recovery but does not provide multi-writer consensus. A real horizontal deployment should evaluate a shared transactional store such as managed PostgreSQL; rqlite remains an evaluated future candidate rather than an active dependency.

## Monitoring

The instrumented server exposes Prometheus-compatible aggregate metrics for:

- process uptime/build version
- responses grouped only by status class
- 401/403/429/5xx counts
- platform/private database health
- worksite-service health

It intentionally does not label metrics by user, organisation, worksite, request path, token, query or source URL.

Also monitor:

- `/healthz` and `/readyz` externally
- worksite upstream `502` rates
- storage capacity and WAL growth
- token issue/revoke/deactivate activity
- backup manifest creation and restore drills
- privileged audit activity

The Prometheus + blackbox_exporter profile in `crisisweave-infra/deploy/observability` is prepared but not deployed automatically.

## Identity and secrets

The local bearer-token system remains useful for the MVP and machine access. A real human-facing privileged deployment should add external IdP/MFA rather than inventing more authentication cryptography in this repository. `crisisweave-infra` tracks authentik + oauth2-proxy as the recommended OIDC deployment option and OpenBao as the self-hosted secret-management option.

## Rollback

Use immutable images tagged by commit SHA. Keep a known-good image available and snapshot databases before schema-changing releases. The platform performs additive token-table migrations for expiry/last-use metadata; still back up before deployment.
