# crisisweave-platform

Deployment and access-control layer for the public CrisisWeave stack.

This repository does **not** replace the specialist modules. It provides the boundary a deployable installation needs around them: organisation identity, role-based access control, token handling, private-data separation, an API gateway, audit records, rate limiting, health/readiness checks, backup verification, privacy-safe metrics and container configuration.

It is still an engineering MVP, not a certified humanitarian platform.

## Responsibilities

- roles: `admin`, `coordinator`, `volunteer`, `viewer`
- bearer tokens stored only as HMAC-SHA256 digests
- 24 hour token lifetime by default for CLI-issued credentials, configurable with `CW_TOKEN_TTL_HOURS`
- token listing and revocation plus principal activation/deactivation
- organisation-scoped private data and permissions
- optimistic concurrency for private records using `If-Match`/record versions
- gateway to `crisisweave-worksites`
- authenticated verified-incident and alert feeds
- coordinator-only worksite mutations
- private JSON records in a separate SQLite database
- append-only application audit records with secret-field redaction
- per-process rate limiting, `/healthz` and `/readyz`
- exact-origin CORS preflight support for authenticated browser clients
- request IDs and baseline security headers
- graceful `502` handling when the worksite service is unavailable
- SQLite online backups with SHA256 manifest and integrity checks
- privacy-safe Prometheus metrics through the instrumented server
- Docker baseline and a minimal `/admin` console
- published `openapi.yaml`
- no third-party Python packages

## Security boundary

`CW_TOKEN_PEPPER` is mandatory and must be at least 24 bytes. Keep it in a secret manager, never in Git.

The private SQLite file is separated and file/directory permissions are tightened where the OS supports them. **This is not application-level encryption.** Production survivor data needs encrypted storage, managed keys/KMS, protected backups, retention/deletion rules and a privacy review.

Bearer tokens are used instead of cookies. Cross-origin access is accepted only from exact origins configured in `CW_ALLOWED_ORIGIN`; multiple origins can be comma separated. Do not use a wildcard for the authenticated API.

The built-in rate limiter is per process. Multi-instance deployments need a shared limiter and shared authoritative data store.

## Quick start

Start `crisisweave-worksites` on `127.0.0.1:8787`, then:

```bash
export CW_TOKEN_PEPPER='replace-with-a-long-random-secret'
python crisisweave_platform.py init
python crisisweave_platform.py create-org demo-relief "Demo Relief"
python crisisweave_platform.py create-principal coord-1 --org demo-relief --name "Demo Coordinator" --role coordinator
python crisisweave_platform.py issue-token coord-1
python crisisweave_platform.py serve
```

For the same gateway plus Prometheus-compatible aggregate metrics, run:

```bash
python prometheus_server.py
```

The Docker image uses `prometheus_server.py` by default.

CLI-issued tokens expire after 24 hours by default. Use `--ttl-hours 8` for a shorter token or `--ttl-hours 0` only for an explicitly non-expiring development token.

The raw token is shown once. Store it securely.

## Token lifecycle

List issued token metadata without revealing token values:

```bash
python crisisweave_platform.py list-tokens coord-1
```

Revoke one token by its token ID:

```bash
python crisisweave_platform.py revoke-token tok_...
```

Deactivate a principal and revoke all of its current tokens:

```bash
python crisisweave_platform.py deactivate-principal coord-1
```

Reactivation does not restore revoked tokens; issue a new token afterwards.

## API

The machine-readable application contract is in [`openapi.yaml`](./openapi.yaml).

Unauthenticated:
- `GET /healthz`
- `GET /readyz`
- `GET /admin`
- trusted-origin `OPTIONS` preflight
- `GET /metrics` when running `prometheus_server.py`

Authenticated:
- `GET /api/v1/me`
- `GET /api/v1/organisation`
- `GET /api/v1/worksites`
- `GET /api/v1/worksites/<id>`

Coordinator/viewer/admin:
- `GET /api/v1/incidents`
- `GET /api/v1/alerts`

Coordinator/admin:
- `POST /api/v1/worksites/<id>/assign`
- `POST /api/v1/worksites/<id>/release`
- `POST /api/v1/worksites/<id>/transition`
- `GET|POST|DELETE /api/v1/private/<key>`
- `GET /api/v1/audit?limit=100`

The gateway ignores a client-supplied worksite `actor` and injects authenticated organisation/principal identity.

Private records return an `ETag` equal to their integer version. Clients that need safe concurrent updates can send that version with `If-Match`. A stale version returns `409` instead of silently overwriting newer data.

## Prometheus metrics

`prometheus_server.py` is a drop-in instrumented server using the same `PlatformHandler`, database and worksite client. `/metrics` exposes only low-cardinality aggregate data:

- process uptime and fixed build version
- response counts by `2xx`/`3xx`/`4xx`/`5xx`
- aggregate authentication failures, authorisation denials and rate limiting
- aggregate 5xx count
- platform/private database health
- worksite-service health

It deliberately does **not** use labels for principal IDs, organisations, worksite IDs, token prefixes, paths, query strings or source URLs.

`/metrics` is unauthenticated so Prometheus can scrape it on a private application network. A public reverse proxy should block this route; the Caddy profile in `crisisweave-infra` does so explicitly.

## Feeds

Point the gateway at outputs from the umbrella integrator:

```bash
export CW_VERIFIED_FEED=/path/to/artifact/verified.jsonl
export CW_ALERTS_FEED=/path/to/artifact/alerts.jsonl
```

Volunteers intentionally do not receive incident-intelligence access by default.

## Admin console

Open `/admin`, enter a bearer token, and connect. The token is kept only in page memory, not in cookies or `localStorage`.

## Backups and restore checks

Create online SQLite backups:

```bash
python crisisweave_platform.py backup --out ./backups
```

Each run writes a JSON manifest with SHA256 hashes and performs `PRAGMA integrity_check` before reporting success.

Verify a backup again before restoration:

```bash
python crisisweave_platform.py verify-backup ./backups/platform-YYYYMMDDTHHMMSSZ.sqlite3
```

Treat private backups with the same controls as the private database.

## Tests

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
```

The regression suite covers RBAC, token hashing, token expiry/revocation, principal deactivation, organisation-private-data isolation, optimistic concurrency, backup integrity, CORS preflight, request security headers, actor-spoof prevention, upstream outage handling and privacy-safe metrics.

## Production gaps

The repository now has a tested metrics surface, but a real deployment still needs an external identity provider/MFA, managed encrypted storage, shared authoritative state for multi-instance operation, distributed rate limiting, a deployed central monitoring stack, tested off-host disaster recovery, retention/deletion governance, organisation onboarding/offboarding, privacy/legal review and integrations with authoritative recovery systems.

Do not represent this repository as evidence that CrisisWeave is approved for emergency dispatch or production humanitarian use.
