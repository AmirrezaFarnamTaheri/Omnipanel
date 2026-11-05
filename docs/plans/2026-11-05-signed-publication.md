# OmniPanel v2 — preapproved signed publication transaction

**Status:** engineering foundation on unified PR #2, not a deployed publisher, trusted approval writer or release gate.

## Scope

The `internal/control/desiredpublish` Go package consumes already-signed desired-state envelopes and a one-time, separately authorized publication approval. Migration `0009_agent_signed_publication.sql` adds:

- A dedicated `agent_desired_publish_permissions` table, **not** a reused enrollment-grant permission. Publication requires two distinct owner administrators with live TOTP-enabled roles and organization-scoped proposal/approval capabilities.
- `agent_desired_publish_approvals` scoped to organization, UUID node, authorized epoch, structural and membership sequences and SHA-256 of the **exact envelope bytes**; expired, revoked, mismatched, already-consumed and unapproved records fail closed. An UPDATE trigger permits only one-time consumption; deletion or modification of original scope is forbidden.
- `agent_desired_publish_audit` and `agent_desired_publish_outbox`, both append-only with foreign keys to the immutable revision and approval history.
- No automatic GRANT to PUBLIC; the production security administrator must provision and audit **separate** PostgreSQL roles before any deployment.

The publisher verifies the Ed25519 signature and exact runtime qualification under a separately provisioned trusted epoch, with immutable copies of trusted signer keys and capability maps. It does not expose its own signer or private key. It locks the approval and approved node binding, checks live organization/node/admin capability state, reads the current head, requires the **next** structural revision in the same epoch and nondecreasing membership cursor, and commits approval consumption, immutable revision, monotonic head, audit and outbox through **one transaction**. A failed step rolls all changes back.

An approval row is **not proof of a human approval ceremony** by itself. It must only be created by a separately secured, authenticated, audited and independently reviewed approval writer with dual-operator approval and protected credentials. That service remains UNIMPLEMENTED. This library is not exposed on an HTTP route.

## Two-stage independently authenticated approval writer (migration 0010)

`internal/control/desiredapproval` now implements a non-HTTP, separate two-stage service:

1. **Propose:** authenticate a live administrator from a canonical 32-byte session bearer (the database stores only SHA-256), require owner status, a publication-only `can_propose` permission and a recent trusted anti-replay TOTP step-up, verify the signed manifest against independently pinned signer/epoch/build trust, and commit an immutable proposal with the exact envelope, digest, node, organization, sequences and initiating session hash/counter. Proposal TTL is bounded to 1–10 minutes.
2. **Review:** authenticate a *different* active owner with publication-only `can_approve` permission and their own recent trusted TOTP step-up; revalidate the original proposer's still-live session, original credential hash/counter, binding, organization and signed envelope; return a private byte copy of the exact signed envelope and its digest for informed review.
3. **Approve:** require the second session plus explicit confirmation of that digest; atomically insert a one-use scoped approval and immutable decision record. The approval expires no later than the original proposal, with a maximum additional five-minute window. A failed decision insert rolls back the approval.
4. **Publish:** the publisher's existing single transaction now rejects a bare approval row; it requires the matching immutable proposal and decision, exact hashes and sequences, and both original live session credential hashes and independently verified TOTP counters before committing revision, head, audit and outbox. Logout or session ID recycling cannot resurrect a pending authorization.

Migration `0010_agent_desired_dual_approval.sql` adds append-only `agent_desired_publish_proposals` and `agent_desired_publish_decisions`. Approval writers have no signer private key; publishers have no operator session token input or authority to approve their own work. Proposing and reviewing operations remain library functions, not public endpoints.

**Important remaining limits:** A proposed intent is still only as trustworthy as its configured signer/qualified builds. A live HTTP service must independently enforce login origin, CSRF, safe display of exact reviewed intent, request replay controls and separate runtime database roles. `StepUpService` still needs an externally protected production TOTP secret opener and key custody. Production deployment, real human-session integration, role grants and end-to-end conformance are NOT yet verified.

## Database privilege boundary

| Component | Intended privileges |
|---|---|
| Node gateway | `SELECT` on `agent_desired_current` only, separate read-only PostgreSQL identity |
| Proposer service (future deployed role) | Authentication joins on live sessions/TOTP and publication permissions; bounded `INSERT` on immutable proposals only |\n| Reviewer service (future deployed role) | Read immutable proposals plus live sessions/step-ups; `INSERT` scoped approvals and immutable decisions, never sign or publish |
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
