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
4. Reject wrong epochs, rollback / advanced cursors, extra or ambiguous parameters, noncanonical numeric sequences and unexpected methods. Never serve an unspecified or empty snapshot as successful.
5. Validate the stored envelope with the current provisioned Ed25519 trusted signers, exact qualified builds, supported capabilities, node and epoch **before** returning 200 **or** 204. An invalid record is a fail-closed service error.
6. Emit a bounded signed JSON envelope with `Cache-Control: private, no-store`. Never expose credential material in errors. A 204 reports unchanged *signed intent* only and never proves native application or connectivity.

## Verification

The tests exercise matching and conflicting cursors, tampered signatures, query ambiguity, wrong epoch, missing/invalid TLS chain, revoked credentials, source outages and non-GET requests. An additional local integration test uses a real TLS 1.3 server requiring verified client certificates and the existing outbound mTLS client. The test verifies that revocation blocks a subsequent desired-state request.

**Do not infer success from this document:** the exact final branch SHA's Go race/vet/format, PostgreSQL, TypeScript and local Sing-box checks are independently authoritative. No external lab, real signer custody, restored PostgreSQL schema or deployed service is supplied by these synthetic/local fixtures.

## Next executable integration steps

- Implement and review a PostgreSQL `Source.Latest` with node+epoch transactional scope, immutable signed snapshots, least-privilege service database roles and audit/outbox ownership. Add production-shape PostgreSQL integration and independent query/role tests.
- Build an independently deployed `cmd/omni-agent-gateway` process with protected server certificate and signer trust custody, mTLS renewal/revocation, timeouts and operator/agent identity separation. Never use the prototype Next.js administrator sessions for node auth.
- Connect a deployed `cmd/omni-node` daemon to its existing outbound client and protected SQLite journal, then implement native validation, staged apply, independent watchdog/commit-confirm rollback and observed last-good promotion. A successful GET remains distinct from a successful runtime application.
- Establish real reference-client and provider evidence before relaxing any `gate-*` release condition.

Keep the historical development key rotation warning, external M0 lab, Hysteria2 comparison, authoritative accounting, subscription/client conformance, Vite cutover, disaster recovery and independent security sign-off **BLOCKED** until proven.
