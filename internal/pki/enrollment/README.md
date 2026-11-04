# Node enrollment authority (bounded foundation)

This package implements token-scoped CSR issuance and certificate admission. Its `httpapi` subpackage defines a **non-deployed** TLS 1.3 enrollment handler, not a running public service. The code does not provision a private CA, automatically renew certificates, or authorize host commands. The Authority must execute in a separately authorized issuer process with protected signing keys. Production enrollment still requires an audited administrator approval and out-of-band token delivery channel.

- The token is 256 random bits, URL-safe encoded. The ledger stores **only its SHA-256 digest**, not plaintext. Grants last no more than 15 minutes and are bound to one authorized logical node UUID.
- The CSR must prove possession of the requested Ed25519 or P-256 key. CSR Subject, DNS names, and URI SAN claims do not authorize identity. The issued certificate contains exactly one node URI SAN, `spiffe://<configured-trust-domain>/node/<authorized-node-uuid>`, and is client-auth only with a lifetime capped at 24 hours.
- TokenStore.Commit must atomically consume the token **and** record the certificate serial, node and public-key fingerprint. If storage fails, no certificate is returned. The SQLStore implements this with a single database transaction, so an attempted duplicate enrollment cannot produce a second authorized certificate.
- AuthenticatePeer requires a TLS 1.3 ConnectionState already verified by Go TLS, the exact node URI SAN, and a live ledger Active lookup for node+serial+public key. The ledger must fail closed on a missing, revoked, expired or unknown record. **Never** accept forwarded client-certificate HTTP headers.
- SQLStore schema is introduced by PostgreSQL migration `db/migrations/0003_agent_enrollment.sql`; the issuer does not run DDL itself. SQLite is used **only** for isolated transaction/restart tests, not as proof of a deployed PostgreSQL issuer.

**Not implemented / not qualified:** a deployed HTTPS enrollment listener, provisioned shared rate-limiter instance/HMAC key and edge abuse controls; private root/issuer provisioning, key storage and rotation; authenticated administrator grant issuance and delivery; certificate renewal, CA rollover or revocation propagation across multiple gateways; live enrollment gateway mTLS tests; production database failover and PITR. A trusted grant-issuance caller must additionally check node existence, approval, organization scope and audit the action. All M0/M1 production gates remain BLOCKED.

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


## Shared, PostgreSQL-backed bootstrap admission (not deployed)

`httpapi.NewPostgresLimiter(db, hmacKey, perPeerBudget, globalBudget)`
provides a concrete fail-closed `Limiter` that can be injected into the
existing enrollment handler. It requires an exactly 32-byte, fleet-shared
HMAC key from a separately protected secret manager. It stores HMAC-SHA256
digests of peer IPs, **never plaintext IPs**, using IPv4/IPv4-mapped IPv6
canonicalization. It uses the PostgreSQL clock for 60-second windows, not
the gateway process clock. A single transaction atomically charges the
fleet-wide budget and the specific peer; if either budget is exhausted
the transaction rolls back, and database errors never fall back to
in-process allowance. Request forwarding headers are ignored by the
enrollment handler.

Migration `db/migrations/0004_agent_enrollment_rate_limits.sql` adds the
shared hashed counters. The disposable PostgreSQL CI job exercises
separate limiter instances, concurrency at the global threshold, forwarded
header bypass attempts, database outage denial, and explicit pruning.
`PruneExpired` is a **trusted maintenance API**, not automatic GC: an
authorized periodic task must invoke it and monitor errors. No service
or public listener has been deployed.

**Operational blockers:** provisioning and rotating the shared HMAC
key, hardening gateway direct TLS termination and upstream trust boundary,
configuring per-peer/global budgets according to traffic and NAT,
running/prioritizing pruning, proving multi-region database availability,
and adding edge-wide abuse protections. A global PostgreSQL row serializes
enrollments within each minute; load-testing this contention is required
before production. This is not an admin-approved grant minting workflow.

## Approved administrator grant issuance (not deployed)

`internal/pki/enrollment/grants` adds an **internal-only** PostgreSQL
grant issuer; it is not an API route or automatic enrollment writer.
It verifies an actual legacy admin-session SHA-256 hash, owner role,
TOTP enrollment plus a separately populated, recent TOTP step-up record,
organization-specific `can_issue` permission, and an approved UUID-to-legacy
integer node binding. It also requires a **different** scoped owner to have
approved the binding, an active organization, and a legacy node still in
`pending_enrollment` state. The service uses the database clock and locks
the relevant authorization/approval rows to keep issuance decisions atomic.

Migration `db/migrations/0005_agent_admin_grants.sql` explicitly bridges the
legacy integer node ID to the agent's UUID, and adds grant operator scopes,
step-up records, issuance metadata and an append-only audit table. Token
issuance, hash-only storage, authorization metadata and audit creation are
**one transaction**; if any write fails, no bearer is returned and all writes
roll back. Pending grants are limited to one active grant per node, and a
repeated correlation cannot recover plaintext previously delivered.
The old unguarded `SQLStore.CreateGrant` Go method is removed from production;
an isolated fixture helper remains available to existing tests.

The PostgreSQL integration job exercises scoped permission, live/expired
sessions, MFA step-up, a second admin's approval, suspended organizations,
quarantined nodes, concurrent issuance and injected audit-write failure.
The integration test uses **minimal faithful auth/node table fixtures**
instead of certifying the entire legacy `0001_initial.sql` migration.
No public admin grant route, trusted approval writer, out-of-band token
delivery, fully qualified legacy-to-v2 migration, or secure step-up
verification service is deployed. Existing `SQLStore.Lookup` still needs
scope/status revalidation when a node is suspended *after* grant issuance.
Those missing pieces block actual production enrollment.

## Redemption-time authorization and certificate admission (non-deploying)

`enrollment.NewApprovedSQLStore(db)` is the **required production
TokenStore** for any future public enrollment issuer. Unlike the old raw
`SQLStore` ledger used in SQLite/postgres isolation tests, it refuses
bearers without an audited `agent_grant_issues` record and current approval.
It checks that the organization is active, the legacy node is still pending
enrollment, the UUID binding is approved, the issuer remains a scoped owner,
the independent approver remains a scoped owner, and the issuing session
has not expired. The grant must be unconsumed and within its database-clock
expiration window.

The initial lookup is not final authorization. `Commit` **rechecks the
same policy under PostgreSQL row locks**, atomically consumes the token,
registers the certificate serial/key fingerprint, and rechecks expiration
before returning. Approval or quarantine changes racing issuance are
serialized with that commit; if approval is revoked after issuance, `Active`
immediately rejects the certificate because it checks the current binding,
organization and legacy node status in addition to the serial/key ledger.
Previously admitted nodes may be `active` or `draining`, whereas
`quarantined` or revoked nodes fail closed.

The original `NewSQLStore` remains a **low-level test/fixture ledger** for
backward-compatible transaction tests; wiring it to a public enrollment
listener would bypass these authorization checks. There is still **no
deployed gateway**, so this adapter is a mandatory future wiring contract,
not proof of production enforcement. Neither a trusted approval/step-up
writer nor revocation propagation across multiple live gateways is present.
