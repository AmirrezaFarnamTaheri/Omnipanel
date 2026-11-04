# Node-scoped signed desired-state gateway — bounded Go increment

**Date:** 5 November 2026  
**Target:** consolidated PR #2; **status:** foundation under CI verification, not deployed and not M0/M1 accepted.

## Purpose

Join the existing mTLS node polling client, online certificate-revocation ledger, and signed manifest verification through a narrow Go HTTP endpoint. The new handler lives in `internal/agent/gateway/desiredapi`, separate from the non-deploying client in `internal/agent/gateway`.

No unsigned or unqualified desired state may be served. The control plane cannot treat a client-provided node identifier, client-provided epoch or forwarded client-certificate header as authority.

## Explicit trust boundaries

1. Terminate TLS 1.3 using Go's TLS stack configured with `RequireAndVerifyClientCert` and the separately provisioned node CA. The handler itself requires `tls.ConnectionState.VerifiedChains` and refuses missing or malformed client identity.
2. Authenticate the SPIFFE node identity with `enrollment.AuthenticatePeer`, invoking the database-backed `CertificateChecker.Active` on **every** request. This read-only interface must be deployed with a role that cannot create grants, issue certificates, mutate trusted step-ups or revoke node approval.
3. Read the latest immutable snapshot **only by authenticated node ID**. The `Source.Latest` interface and its epoch must be implemented using one server-side, node-scoped transactional read; the HTTP query cannot choose another tenant, node or source.
4. Require `Verifier.AuthorizedEpoch` from protected, independently provisioned gateway configuration. Never copy it from the PostgreSQL head, a snapshot body, or an HTTP poll. Database PITR must not reauthorize an old, properly signed epoch without a separately approved epoch-recovery procedure.
5. Reject wrong epochs, rollback / advanced cursors, extra or ambiguous parameters, noncanonical numeric sequences and unexpected methods. Never serve an unspecified or empty snapshot as successful.
6. Validate the stored envelope with the current provisioned Ed25519 trusted signers, exact qualified builds, supported capabilities, node and epoch **before** returning 200 **or** 204. An invalid record is a fail-closed service error.
7. Emit a bounded signed JSON envelope with `Cache-Control: private, no-store`. Never expose credential material in errors. A 204 reports unchanged *signed intent* only and never proves native application or connectivity.

## Verification

The tests exercise matching and conflicting cursors, tampered signatures, query ambiguity, wrong epoch, missing/invalid TLS chain, revoked credentials, source outages and non-GET requests. An additional local integration test uses a real TLS 1.3 server requiring verified client certificates and the existing outbound mTLS client. The test verifies that revocation blocks a subsequent desired-state request.

**Do not infer success from this document:** the exact final branch SHA's Go race/vet/format, PostgreSQL, TypeScript and local Sing-box checks are independently authoritative. No external lab, real signer custody, restored PostgreSQL schema or deployed service is supplied by these synthetic/local fixtures.

## PostgreSQL signed-state increment (5 November)

Migration `0008_agent_signed_desired.sql` adds:

- `agent_desired_revisions`: bounded, immutable node/epoch/sequence signed-envelope history.
- `agent_desired_heads`: a foreign-key-constrained current pointer. Same-epoch sequence regression, head deletion and silent epoch replacement are refused by triggers.
- `agent_desired_current`: a security-barrier view joining head + history + node approval + active organization + legacy-node lifecycle into one MVCC statement. The view does **not** authorize a publisher or an independently managed epoch recovery.
- Explicit `PUBLIC` privilege revocation on the new tables/view.

`SQLSource.Latest` uses a parameter-bound node identifier, reads only the view, and refuses missing/malformed/oversized metadata. The handler matches both structural and membership sequences and the epoch from the stored head to the verified Ed25519 manifest. No database metadata alone is a signature authority.

**Deploy-time role contract (operator-owned, not automated by this migration):** grant the independently provisioned gateway database role `USAGE` on its schema and `SELECT` only on `agent_desired_current`. Do not grant that role direct access to `agent_desired_revisions`, `agent_desired_heads`, enrollment grants, private key material, admin sessions or publisher audit/outbox tables. CI exercises a random `NOLOGIN` reader role with view-only access. Underlying Postgres roles, owner privileges, connection secret custody and grants must be reviewed before deployment.

The `postgres_integration` test applies all migrations 0001–0008 to a new randomized schema on disposable PostgreSQL, then exercises node isolation, online binding/organization/node denial, immutability, monotonic heads, signed metadata mismatch, and restricted role access. **Passing these tests is not evidence of a deployed or approved publishing pipeline.** The test still requires successful exact-head CI.

## Next executable integration steps

- Build the **audited, independently authorized** signed-revision publisher and transactional intent/outbox writer. The read-only SQL source and view are implemented, but publisher authorization, signature/key custody and live DB-role provisioning remain unimplemented.
- Build an independently deployed `cmd/omni-agent-gateway` process with protected server certificate and signer trust custody, mTLS renewal/revocation, timeouts and operator/agent identity separation. Never use the prototype Next.js administrator sessions for node auth.
- Connect a deployed `cmd/omni-node` daemon to its existing outbound client and protected SQLite journal, then implement native validation, staged apply, independent watchdog/commit-confirm rollback and observed last-good promotion. A successful GET remains distinct from a successful runtime application.
- Establish real reference-client and provider evidence before relaxing any `gate-*` release condition.

Keep the historical development key rotation warning, external M0 lab, Hysteria2 comparison, authoritative accounting, subscription/client conformance, Vite cutover, disaster recovery and independent security sign-off **BLOCKED** until proven.
