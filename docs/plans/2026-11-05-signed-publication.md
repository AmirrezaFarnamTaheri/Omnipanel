# OmniPanel v2 — preapproved signed publication transaction

**Status:** engineering foundation on unified PR #2, not a deployed publisher, trusted approval writer or release gate.

## Scope

The `internal/control/desiredpublish` Go package consumes already-signed desired-state envelopes and a one-time, separately authorized publication approval. Migration `0009_agent_signed_publication.sql` adds:

- A dedicated `agent_desired_publish_permissions` table, **not** a reused enrollment-grant permission. Publication requires two distinct owner administrators with live TOTP-enabled roles and organization-scoped proposal/approval capabilities.
- `agent_desired_publish_approvals` scoped to organization, UUID node, authorized epoch, structural and membership sequences and SHA-256 of the **exact envelope bytes**; expired, revoked, mismatched, already-consumed and unapproved records fail closed. An UPDATE trigger permits only one-time consumption; deletion or modification of original scope is forbidden.
- `agent_desired_publish_audit` and `agent_desired_publish_outbox`, both append-only with foreign keys to the immutable revision and approval history.
- No automatic GRANT to PUBLIC; the production security administrator must provision and audit **separate** PostgreSQL roles before any deployment.

The publisher verifies the Ed25519 signature and exact runtime qualification under a separately provisioned trusted epoch, with immutable copies of trusted signer keys and capability maps. It does not expose its own signer or private key. It locks the approval and approved node binding, checks live organization/node/admin capability state, reads the current head, requires the **next** structural revision in the same epoch and nondecreasing membership cursor, and commits approval consumption, immutable revision, monotonic head, audit and outbox through **one transaction**. A failed step rolls all changes back.

An approval row is **not proof of a human approval ceremony** by itself. It must only be created by a separately secured, authenticated, audited and independently reviewed approval writer with dual-operator approval and protected credentials. The session-bound two-stage approval library and a guarded non-deployed HTTP adapter exist, but a production identity provider, independently protected TOTP opener, operator UI, process deployment and verified database roles remain UNIMPLEMENTED. The publisher library is not exposed on an HTTP route.

## Two-stage independently authenticated approval writer (migration 0010)

`internal/control/desiredapproval` now implements a non-HTTP, separate two-stage service:

1. **Propose:** authenticate a live administrator from a canonical 32-byte session bearer (the database stores only SHA-256), require owner status, a publication-only `can_propose` permission and a recent trusted anti-replay TOTP step-up, verify the signed manifest against independently pinned signer/epoch/build trust, and commit an immutable proposal with the exact envelope, digest, node, organization, sequences and initiating session hash/counter. Proposal TTL is bounded to 1–10 minutes.
2. **Review:** authenticate a *different* active owner with publication-only `can_approve` permission and their own recent trusted TOTP step-up; revalidate the original proposer's still-live session, original credential hash/counter, binding, organization and signed envelope; return a private byte copy of the exact signed envelope and its digest for informed review.
3. **Approve:** require the second session plus explicit confirmation of that digest; atomically insert a one-use scoped approval and immutable decision record. The approval expires no later than the original proposal, with a maximum additional five-minute window. A failed decision insert rolls back the approval.
4. **Publish:** the publisher's existing single transaction now rejects a bare approval row; it requires the matching immutable proposal and decision, exact hashes and sequences, and both original live session credential hashes and independently verified TOTP counters before committing revision, head, audit and outbox. Logout or session ID recycling cannot resurrect a pending authorization.

Migration `0010_agent_desired_dual_approval.sql` adds append-only `agent_desired_publish_proposals` and `agent_desired_publish_decisions`. Approval writers have no signer private key; publishers have no operator session token input or authority to approve their own work. Proposing and reviewing remain protected library operations with a bounded, non-deployed HTTP adapter; there is no publicly deployed administration endpoint.

**Important remaining limits:** A proposed intent is still only as trustworthy as its configured signer/qualified builds. The HTTP adapter enforces TLS 1.3, same-origin and HMAC-CSRF at its own boundary; deployment must still integrate real login, safe display of exact reviewed intent, shared abuse controls and separately provisioned runtime database roles. `StepUpService` still needs an externally protected production TOTP secret opener and key custody. Production deployment, real human-session integration, role grants and end-to-end conformance are NOT yet verified.

## Bounded administrator HTTP adapter (5 November continuation)

`internal/control/desiredapproval/httpapi` is now an isolated Go adapter for the library's authenticated `Propose`, `Review` and `Approve` operations. **It is not a deployed admin API or an identity provider.** The three operations and a CSRF token endpoint are deliberately isolated from the node enrollment/desired-state endpoints:

| Method | Path | Response / boundary |
| --- | --- | --- |
| `GET` | `/v2/admin/desired/csrf` | Short-lived HMAC token bound to the existing bearer session and configured HTTPS origin; live owner session required |
| `POST` | `/v2/admin/desired/proposals` | Server-generated random proposal UUID, exact signed envelope, organization/node IDs and bounded 60–600-second intent lifetime; returns a receipt |
| `GET` | `/v2/admin/desired/proposals/{uuid}` | Privately returns the signed envelope (base64-encoded JSON `[]byte`), immutable digest and exact target metadata after independent reviewer authorization |
| `POST` | `/v2/admin/desired/proposals/{uuid}/approval` | Reviewer must submit the exact lowercase 64-hex digest of the inspected signed envelope; underlying library enforces independent owner/TOTP and durable decision |

Every request requires direct TLS 1.3, exact configured HTTPS `Origin` and `Host`, a canonical 32-byte URL-safe bearer token in one Authorization header, no cookies, and online session validation. Cross-site Fetch Metadata is denied. Mutations additionally require a single `X-Omni-CSRF` header with a constant-time-checked, five-minute-window, session+origin-scoped HMAC. No CORS credential grants are emitted. Responses set `Cache-Control: private, no-store`, `Referrer-Policy: no-referrer`, `nosniff` and restrictive CSP.

Request JSON is bounded and rejects duplicate top-level keys, unknown fields, trailing JSON and unsupported content encodings. Backend authorization errors are mapped to generic problem responses; no bearer, CSRF key, signed content or database error is reflected. A separate `SQLSessionChecker` checks the live owner and TOTP-enabled login by **hashed** bearer in PostgreSQL, failing closed on DB errors. It does not bypass the approval library's independent TOTP verification.

**Operational and security limits:** deploy the adapter only behind a directly authenticated TLS 1.3 server with separately provisioned 256-bit or stronger CSRF secret; the operator UI must securely hold bearer and CSRF tokens in memory (never URL, logs or persistent browser storage). Real login, logout propagation, protected TOTP secret opener, session cookie policy, shared abuse limiter, audit correlation, permission-separated DB credentials, deployment health/observability and operator UI review of the exact signed intent remain unimplemented. A CSRF token never authorizes a publication by itself.

Unit tests locally exercised the HTTP adapter under race detection and `go vet` against an isolated shape-compatible `desiredapproval` stub, with an initial failing test before the adapter was implemented. GitHub blob SHA comparisons confirmed the committed files are byte-identical to those locally tested files. Full repository Go, PostgreSQL and deployed-browser tests remain **required**, not inferred from the isolated test harness.

## Loopback administrator runtime and credential loading (5 November 2026)

A separately deployable, deliberately **loopback-only** `cmd/omnipanel-admin` process now wires the protected `desiredapproval/httpapi` adapter to the existing proposal and reviewer services. It **does not sign manifests**, issue administrator logins, verify TOTP secrets itself, or expose node-control endpoints.

Startup loads an owner-only JSON configuration and protected files for the TLS key, HMAC-CSRF secret, signer/qualified-build/epoch trust, and three distinct PostgreSQL DSNs. `internal/control/adminruntime` enforces absolute regular-file paths without final-component symlink traversal, owner-only secret permissions, strict duplicate/unknown-key JSON, a current hostname-matched certificate, a minimum 256-bit CSRF key, exact external signer public keys and runtime qualification. The service requires a non-root operating-system account, an explicit loopback bind, TLS 1.3, bounded HTTP read/write/header deadlines, and a shutdown handler.

PostgreSQL DSNs must use dedicated, different application usernames with `sslmode=verify-full` and an explicit parseable PEM trust root. Only the known `sslmode` and `sslrootcert` URI parameters are accepted, preventing uncontrolled `options`, `sslcert`, `sslkey`, or search-path overrides. Each connection is authenticated and checked at startup against `current_user` and PostgreSQL role privilege flags by `VerifyPostgresRole`, rejecting superuser, CREATE ROLE, CREATE DATABASE, replication and row-level-security bypass privileges. Dedicated pools are used for login-session checking, proposal creation and reviewer/approval operations.

**Evidence:** the runtime configuration and entrypoint were tested with `go test -race -count=1 ./...`, `go vet ./...`, and Go formatting in an isolated module using interface-compatible stubs for existing manifest and approval services. A test first reproduced an unsafe PostgreSQL DSN accepting extra connection options, then verified that a strict parameter allowlist rejected them. Committed Git blobs were SHA-checked against those local files. These tests **do not** establish that the full repository, real PostgreSQL GRANTs, TLS integration or deployment passes. The final PR-head GitHub Actions workflows are the next acceptance checks.

**Still required before deployment:** audited PostgreSQL table/column GRANTs and hardened search paths, protected provisioning and rotation for all credentials, external TOTP verification/key custody, independent signing-key service, real operator UI and session/logout workflow, shared rate limiting and network/access policies, process packaging, metrics, external security review, incident/restore drills and native agent apply/rollback. Do not treat this executable as production-qualified.

## Database privilege boundary

| Component | Intended privileges |
|---|---|
| Node gateway | `SELECT` on `agent_desired_current` only, separate read-only PostgreSQL identity |
| Proposer service (future deployed role) | Authentication joins on live sessions/TOTP and publication permissions; bounded `INSERT` on immutable proposals only |
| Reviewer service (future deployed role) | Read immutable proposals plus live sessions/step-ups; `INSERT` scoped approvals and immutable decisions, never sign or publish |
| Publisher (future service role) | Bounded `SELECT` on live session/step-up, proposal and decision provenance; `UPDATE(consumed_at)` on approved row; `INSERT` revisions/audit/outbox, `INSERT/UPDATE` monotonic head, necessary sequence privileges |
| Outbox delivery worker (future) | Read queued immutable outbox facts and write separate delivery acknowledgements; no revision/head mutation |
| Migration owner | DDL only; never used for live application traffic |

Role provisioning, key custody, session-bound approval provenance, delivery acknowledgement tables and audited epoch-recovery workflow remain separate release-blocking work.

## Test coverage and acceptance limits

- `publisher_test.go` tests invalid trust configuration, malformed request IDs, tampered signatures, unauthorized node and trusted epoch mismatch.
- The publisher `postgres_integration_test.go` applies migrations **0001–0010 in order** in a unique schema on a disposable local PostgreSQL 17.6 database. It checks first publication, replay refusal, exact envelope digests, concurrent same-revision approvals, live organization/proposal/binding revocation, audit failure injection and rollback, retry after rollback, and append-only audit/outbox/approval history.
- The fixture grants **no enrollment-issuer rights** to test administrators, establishing independent publication authority. The separate `desiredapproval/postgres_integration_test.go` exercises two distinct session-bound TOTP proofs, immutable proposal review, digest mismatch, revoked rights/organization, failed decision rollback and logout invalidation.
- `enrollment-postgres.yml` includes the publisher's PostgreSQL integration test. `contracts.yml` includes its Go files in the formatting check and runs the full Go race/vet suite.

**Do not mark these tests passed until the exact final PR SHA's workflows report success.** Synthetic signatures and a disposable database cannot establish operator approval, independent signer custody, audited production database roles, external node apply/rollback, payment-grade accounting, disaster recovery or M0/M1 release qualification.

## Remaining work

1. Deploy and independently review the two-stage approval library behind a CSRF/origin-protected operator API with real protected TOTP key custody, transaction-role separation, session logout/replay and concurrent human approval qualification.
2. Provision production roles, mutual TLS, protected signing service and immutable trusted epoch outside the database snapshot.
3. Build a deployable publisher process and independent outbox dispatcher with acknowledgements, retry/idempotency and incident observability.
4. Deploy the agent/gateway and test safe native apply, watchdog-confirm rollback, client and provider interoperability and PITR/epoch recovery.
5. Retain the historical development-secret rotation requirement and all blocked production gates until independently evidenced.
