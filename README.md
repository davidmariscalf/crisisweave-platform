# crisisweave-platform

Deployment and access-control layer for the public CrisisWeave stack.

This repository does **not** replace the specialist modules. It provides the boundary a deployable installation needs around them: organisation identity, role-based access control, token handling, private-data separation, an API gateway, audit records, rate limiting, health/readiness checks and container configuration.

It is still an engineering MVP, not a certified humanitarian platform.

## Responsibilities

- roles: `admin`, `coordinator`, `volunteer`, `viewer`
- bearer tokens stored only as HMAC-SHA256 digests
- organisation-scoped private data and permissions
- gateway to `crisisweave-worksites`
- authenticated verified-incident and alert feeds
- coordinator-only worksite mutations
- private JSON records in a separate SQLite database
- append-only application audit records
- rate limiting, `/healthz` and `/readyz`
- SQLite online backups
- Docker baseline and a minimal `/admin` console
- no third-party Python packages

## Security boundary

`CW_TOKEN_PEPPER` is mandatory and must be at least 24 bytes. Keep it in a secret manager, never in Git.

The private SQLite file is separated and file/directory permissions are tightened where the OS supports them. **This is not application-level encryption.** Production survivor data needs encrypted storage, managed keys/KMS, protected backups, retention/deletion rules and a privacy review.

Bearer tokens are used instead of cookies. Cross-origin access should be enabled only for an explicitly trusted origin. The built-in rate limiter is per process; multi-instance deployments need shared rate limiting.

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

The token is shown once. Store it securely.

## API

Unauthenticated:
- `GET /healthz`
- `GET /readyz`
- `GET /admin`

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
- `GET|POST /api/v1/private/<key>`
- `GET /api/v1/audit?limit=100`

The gateway ignores a client-supplied worksite `actor` and injects authenticated organisation/principal identity.

## Feeds

Point the gateway at outputs from the umbrella integrator:

```bash
export CW_VERIFIED_FEED=/path/to/artifact/verified.jsonl
export CW_ALERTS_FEED=/path/to/artifact/alerts.jsonl
```

Volunteers intentionally do not receive incident-intelligence access by default.

## Admin console

Open `/admin`, enter a bearer token, and connect. The token is kept only in page memory, not in cookies or `localStorage`.

## Backups

```bash
python crisisweave_platform.py backup --out ./backups
```

Treat private backups with the same controls as the private database.

## Tests

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
```

## Production gaps

A real deployment still needs an external identity provider or rigorous account lifecycle, TLS, managed encrypted storage, distributed rate limiting when scaled, central monitoring, tested restores, retention/deletion policy, token/key rotation procedures, organisation onboarding/offboarding, privacy/legal review, and integrations with authoritative recovery systems.

Do not represent this repository as evidence that CrisisWeave is approved for emergency dispatch or production humanitarian use.
