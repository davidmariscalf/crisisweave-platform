# CrisisWeave data lifecycle

CrisisWeave separates operational/public information from organisation-private records. A production operator must set an explicit retention period before accepting real private data.

## Private records

`maintenance.py` implements a fail-safe retention workflow. Its default mode is a dry run: it reports the number of organisation-private records older than the configured retention horizon without deleting anything.

Example dry run:

```bash
python maintenance.py \
  --db /data/platform.db \
  --private-db /data/private.db \
  --pepper "$CW_TOKEN_PEPPER" \
  --private-retention-days 90 \
  --token-retention-days 30
```

Apply the same policy only after review:

```bash
python maintenance.py \
  --db /data/platform.db \
  --private-db /data/private.db \
  --pepper "$CW_TOKEN_PEPPER" \
  --private-retention-days 90 \
  --token-retention-days 30 \
  --apply
```

The apply mode deletes only:

- private records whose `updated_at` is older than the private-data horizon
- already expired or revoked bearer-token metadata older than the credential horizon

It does not delete organisations, principals, active credentials, worksites or the audit trail. Every applied retention run writes a `maintenance.retention_prune` audit entry with aggregate deletion counts and policy horizons.

## Audit trail

The audit database is intentionally not automatically pruned by `maintenance.py`. Audit retention is a separate governance decision because shortening it can remove security and accountability evidence. If an organisation needs audit deletion for legal reasons, implement and approve that policy separately rather than reusing the private-record retention command.

## Backups

Deleting live records does not retroactively erase existing backups. Backup retention and destruction therefore must match the organisation's privacy policy. Off-host encrypted backups should have a documented expiration policy and a named recovery owner.

## Operational rule

Before production go-live, the infrastructure `go-live-check.py` requires `CW_DATA_RETENTION_DAYS` and named privacy, incident-response and backup owners. The configured number is a policy input; operators remain responsible for scheduling the maintenance command and backup expiration at the approved cadence.
