# Security policy and deployment notes

## Reporting
Do not publish real credentials, survivor data or exploitable deployment details in a public issue. Use a private disclosure channel maintained by the deployer.

## Secrets
The repository contains no production secrets. Deployers provide `CW_TOKEN_PEPPER` and, when needed, `CW_WORKSITES_TOKEN`. Rotate compromised bearer tokens immediately. Rotating the pepper requires reissuing tokens because stored digests depend on it.

## Private data
`private.db` is separate from identity/audit storage. File and directory permissions are tightened where supported, but this is not encryption at rest. Use encrypted volumes or managed encrypted storage/KMS in production. Never copy survivor PII into public incident or worksite feeds.

## Roles
- `admin`: full organisation permissions
- `coordinator`: worksite writes, private records, audit and incident intelligence
- `volunteer`: worksite read
- `viewer`: read-only worksites and incident intelligence

The bearer-token model is for an MVP/API deployment. Mature deployments should add external identity, MFA for privileged users and automated lifecycle/revocation.

## Network
Bind to loopback by default. External deployments should use TLS and a hardened reverse proxy. CORS should be enabled only for a trusted explicit origin.

## Logging
Audit metadata redacts keys containing token, secret or password. Do not add private request-body logging.
