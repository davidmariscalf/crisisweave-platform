# Security policy and deployment notes

## Reporting

Do not publish real credentials, survivor data or exploitable deployment details in a public issue. Use a private disclosure channel maintained by the deployer.

The public CrisisWeave site publishes a `security.txt` contact for project-level reports. A real humanitarian deployment should provide its own monitored security contact and incident-response process.

## Secrets

The repository contains no production secrets. Deployers provide `CW_TOKEN_PEPPER` and, when needed, `CW_WORKSITES_TOKEN` through the runtime environment or a secret manager.

Never commit:

- bearer tokens
- peppers or API keys
- private keys
- `.env` files with real values
- production SQLite databases or backups
- survivor records

Rotating the pepper invalidates the ability to match all existing token digests, so reissue credentials as part of pepper rotation.

## Token lifecycle

CLI-issued tokens expire after 24 hours by default. Prefer shorter lifetimes for elevated roles.

Available controls:

- `list-tokens` exposes metadata only, never raw token values
- `revoke-token` invalidates one token
- `deactivate-principal` disables the principal and revokes all current tokens
- `activate-principal` restores the account but does not revive revoked tokens

Raw tokens are shown only when issued and are never stored in plaintext by the platform.

## Private data

`private.db` is separate from identity/audit storage. File and directory permissions are tightened where supported, but this is not encryption at rest. Use encrypted volumes or managed encrypted storage/KMS in production. Never copy survivor PII into public incident or worksite feeds.

Private records support optimistic concurrency using integer versions and `If-Match`. This prevents a stale browser/session from silently overwriting a newer private record when clients use the version check.

## Roles

- `admin`: full organisation permissions
- `coordinator`: worksite writes, private records, audit and incident intelligence
- `volunteer`: worksite read
- `viewer`: read-only worksites and incident intelligence

The bearer-token model remains an MVP/API identity system. Mature deployments should use external identity, MFA for privileged users, central lifecycle policy and revocation across all services.

## Network and browser boundary

Bind to loopback by default. External deployments should use TLS and a hardened reverse proxy.

CORS preflight is accepted only for exact origins configured through `CW_ALLOWED_ORIGIN`. The server does not intentionally support wildcard authenticated origins. Allowed request headers are restricted to `Authorization`, `Content-Type`, `If-Match` and `X-Request-ID`.

The API emits baseline anti-framing/content-type/referrer/permissions headers and request IDs. Reverse-proxy policy remains required in production.

A network failure in the worksite service is returned as an explicit `502`; it should not result in a client connection silently disappearing.

## Backups

The backup command performs `PRAGMA integrity_check`, computes SHA256 hashes and writes a manifest. This detects accidental corruption but is not an authenticity signature and does not encrypt the backup.

Keep private backups encrypted and off-host, restrict access, set retention limits and rehearse restores.

## Logging and audit

Audit metadata redacts keys containing token, secret, password, pepper or credential. Do not add private request-body logging or authorization-header logging.

Request IDs may be logged by a reverse proxy for correlation, but they must not contain private data.

## Remaining security gaps

Before real survivor data or authoritative operational use, add at minimum external identity/MFA, managed encrypted storage, shared state/locking for multi-instance operation, centralized monitoring, off-host disaster recovery, retention/deletion governance, privacy/legal review, dependency/deployment patch management and an incident-response owner.
