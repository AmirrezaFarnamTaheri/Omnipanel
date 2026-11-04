# Node enrollment authority (bounded foundation)

This package implements token-scoped CSR issuance and certificate admission. Its `httpapi` subpackage defines a **non-deployed** TLS 1.3 enrollment handler, not a running public service. The code does not provision a private CA, automatically renew certificates, or authorize host commands. The Authority must execute in a separately authorized issuer process with protected signing keys. Production enrollment still requires an audited administrator approval and out-of-band token delivery channel.

- The token is 256 random bits, URL-safe encoded. The ledger stores **only its SHA-256 digest**, not plaintext. Grants last no more than 15 minutes and are bound to one authorized logical node UUID.
- The CSR must prove possession of the requested Ed25519 or P-256 key. CSR Subject, DNS names, and URI SAN claims do not authorize identity. The issued certificate contains exactly one node URI SAN, `spiffe://<configured-trust-domain>/node/<authorized-node-uuid>`, and is client-auth only with a lifetime capped at 24 hours.
- TokenStore.Commit must atomically consume the token **and** record the certificate serial, node and public-key fingerprint. If storage fails, no certificate is returned. The SQLStore implements this with a single database transaction, so an attempted duplicate enrollment cannot produce a second authorized certificate.
- AuthenticatePeer requires a TLS 1.3 ConnectionState already verified by Go TLS, the exact node URI SAN, and a live ledger Active lookup for node+serial+public key. The ledger must fail closed on a missing, revoked, expired or unknown record. **Never** accept forwarded client-certificate HTTP headers.
- SQLStore schema is introduced by PostgreSQL migration `db/migrations/0003_agent_enrollment.sql`; the issuer does not run DDL itself. SQLite is used **only** for isolated transaction/restart tests, not as proof of a deployed PostgreSQL issuer.

**Not implemented / not qualified:** a deployed HTTPS enrollment listener, shared/distributed rate-limiter implementation and edge abuse controls; private root/issuer provisioning, key storage and rotation; authenticated administrator grant issuance and delivery; certificate renewal, CA rollover or revocation propagation across multiple gateways; live enrollment gateway mTLS tests; production database failover and PITR. A trusted grant-issuance caller must additionally check node existence, approval, organization scope and audit the action. All M0/M1 production gates remain BLOCKED.

## Non-deploying HTTP and PostgreSQL test seams

`internal/pki/enrollment/httpapi` exports `New(issuer, limiter)`, requiring both
a protected issuer and a caller-injected fail-closed admission limiter. The
handler serves only `POST /v2/nodes/enroll`, accepts the approved bearer in
the `Authorization` header and exactly one JSON `csrPem` string, and refuses
non-TLS-1.3 requests, query credentials, duplicate JSON fields, oversized
bodies, ambiguous methods/content types and unsanitized error responses.
Direct client-certificate TLS is **not** possible before certificate issuance.
Forwarded certificate/IP headers do not authorize identity; the admission
limiter keys on the directly connected peer IP. Production deployment must
provide a shared limiter and additional edge abuse controls before exposing
a listener.

The separate `.github/workflows/enrollment-postgres.yml` CI gate boots a
disposable PostgreSQL 17 instance, runs migration 0003, and exercises the
same `SQLStore` against PostgreSQL for concurrent redemption, injected
certificate-write rollback, revocation, and schema constraints. These
tests do not prove runtime migrations, node approval/organization scope,
real key custody, multi-gateway revocation propagation, renewal or disaster
recovery. The `github.com/lib/pq` driver is pinned for tests only.
