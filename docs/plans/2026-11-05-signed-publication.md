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

## Database privilege boundary

| Component | Intended privileges |
|---|---|
| Node gateway | `SELECT` on `agent_desired_current` only, separate read-only PostgreSQL identity |
| Trusted approval writer (future) | Narrow `INSERT` to publication approvals only after independently proven administrator ceremony |
| Publisher (future service role) | Bounded `SELECT` on required live authorization rows and approval, `UPDATE(consumed_at)` on approval, `INSERT` on immutable revisions, `INSERT/UPDATE` on head, `INSERT` on audit and outbox, necessary sequence privileges |
| Outbox delivery worker (future) | Read queued immutable outbox facts and write separate delivery acknowledgements; no revision/head mutation |
| Migration owner | DDL only; never used for live application traffic |

Role provisioning, key custody, session-bound approval provenance, delivery acknowledgement tables and audited epoch-recovery workflow remain separate release-blocking work.

## Test coverage and acceptance limits

- `publisher_test.go` tests invalid trust configuration, malformed request IDs, tampered signatures, unauthorized node and trusted epoch mismatch.
- `postgres_integration_test.go` applies migrations **0001–0009 in order** in a unique schema on a disposable local PostgreSQL 17.6 database. It checks first publication, replay refusal, exact envelope digests, concurrent same-revision approvals, live organization/proposal/binding revocation, audit failure injection and rollback, retry after rollback, and append-only audit/outbox/approval history.
- The fixture grants **no enrollment-issuer rights** to the test administrators, establishing that publication uses its independently scoped rights rather than implicit grant-issuance authority.
- `enrollment-postgres.yml` includes the publisher's PostgreSQL integration test. `contracts.yml` includes its Go files in the formatting check and runs the full Go race/vet suite.

**Do not mark these tests passed until the exact final PR SHA's workflows report success.** Synthetic signatures and a disposable database cannot establish operator approval, independent signer custody, audited production database roles, external node apply/rollback, payment-grade accounting, disaster recovery or M0/M1 release qualification.

## Remaining work

1. Build a separate session-bound dual-operator approval writer with a trusted TOTP or equivalent protected factor, provenance, race control, CSRF/origin boundary, and independent identity.
2. Provision production roles, mutual TLS, protected signing service and immutable trusted epoch outside the database snapshot.
3. Build a deployable publisher process and independent outbox dispatcher with acknowledgements, retry/idempotency and incident observability.
4. Deploy the agent/gateway and test safe native apply, watchdog-confirm rollback, client and provider interoperability and PITR/epoch recovery.
5. Retain the historical development-secret rotation requirement and all blocked production gates until independently evidenced.
