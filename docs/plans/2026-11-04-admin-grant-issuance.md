# OmniPanel v2 — bounded administrator-issued enrollment grants

**Target:** unified PR #2, `arena/a1949059-omnipanel`.  
**Date:** 4 November 2026. **Status:** implementation, CI evidence pending.

## Invariants

- Bind node UUIDs to existing integer `nodes.id` through an explicit,
  separately approved and organization-scoped registry.
- Require an actual owner session hash matching the existing auth schema,
  2-hour idle and 12-hour absolute limits, a recent TOTP step-up record,
  an organization-scoped `can_issue` privilege, and a different owner with
  a scoped `can_approve` privilege.
- Only `pending_enrollment` legacy nodes in active organizations may mint.
  The request cannot supply an actor ID, role or approval claim.
- Grant bearer is returned only after the token digest, metadata and
  append-only audit record commit in one database transaction.
- Repeated correlations and concurrent active-node grants return conflict,
  not the old plaintext bearer.
- No HTTP route, production signer, approval writer, certificate renewal or
  privileged node operation is added.

## Verification ledger

- [x] Inspect existing v1 admin/session schema and v2 UUID token ledger.
- [x] Observe local red tests for missing storage and invalid input against
  explicit stubs.
- [x] Implement minimal protected Go library and observe local race/vet green.
- [x] Add PostgreSQL 0005 migration, legacy bridge and atomic audit.
- [x] Add PostgreSQL negative, rollback and concurrency tests.
- [x] Remove exported ungated SQLStore grant creation API from production.
- [x] Wire existing PostgreSQL CI and Go formatting gate.
- [ ] Verify final PR-head PostgreSQL race tests, Go vet/gofmt, frontend
  contracts, and source-pinned Sing-box smoke.
- [ ] Review the full legacy 0001 migration, secure trusted approval/step-up
  writers, grant revocation at redemption and production DR separately.

**All production gates: BLOCKED.** This is an inspectable foundation only.
