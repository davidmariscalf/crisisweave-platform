# Deployment baseline

This is a baseline, not a production certification.

## Services
1. `crisisweave-platform` on an internal application network.
2. `crisisweave-worksites` on the same private network.
3. TLS reverse proxy/load balancer in front of the platform.
4. Persistent encrypted storage for operational/private databases.
5. Read-only verified incident and alert feeds, or an equivalent managed feed service.

The platform should be the externally visible API boundary. Avoid exposing the worksites write API directly.

## Environment
Required: `CW_TOKEN_PEPPER`, `CW_WORKSITES_URL`, `CW_DB`, `CW_PRIVATE_DB`; and `CW_WORKSITES_TOKEN` when upstream writes are protected.

Optional: `CW_VERIFIED_FEED`, `CW_ALERTS_FEED`, `CW_HOST`, `CW_PORT`, `CW_RATE_LIMIT_PER_MINUTE`, `CW_ALLOWED_ORIGIN`.

## Storage and backup
Keep databases on persistent encrypted storage. Run `python crisisweave_platform.py backup --out /secure-backups` and test restores regularly.

## Reverse proxy
Terminate TLS before the Python service and enforce request-size and timeout limits. Do not trust arbitrary forwarded client headers.

## Scaling
SQLite is suitable for this MVP and small single-instance deployments. Horizontal deployments should move identity/audit/private storage to a managed transactional database and rate limiting to shared infrastructure.

## Monitoring
Monitor `/healthz`, `/readyz`, 401/403/429/5xx rates, storage capacity, backup/restore health and privileged audit activity.

## Rollback
Use immutable images tagged by commit SHA. Keep a known-good image available and snapshot databases before schema-changing releases.
