# OmniPanel v2 — logout-safe enrollment revocation

**Baseline:** Unified PR #2 at `9839e68`, branch
`arena/a1949059-omnipanel`. **Date:** 4 November 2026.

## Defect

Migration 0005 referenced `admin_sessions(id)` from
`agent_grant_issues.session_id` with `ON DELETE RESTRICT`. After any grant
had been issued, administrator logout (deleting the session row) failed
with a foreign-key violation. Cascading the deletion would instead destroy
issuance history, and dropping the reference without a compensating
control would let a recycled session serial id re-authorize an old bearer.

## Scope

- Forward-only migration `0006_agent_grant_logout_revocation.sql`:
  - add `session_token_hash` to `agent_grant_issues`, backfilled from the
    still-referenced session (the 0005 RESTRICT key guarantees it exists),
    then enforce NOT NULL and the 64-hex credential format;
  - drop the session-id RESTRICT foreign key; the recorded id and hash
    remain immutable historical facts;
  - make `agent_grant_issues` append-only like `agent_grant_audit`.
- `grants.Service.Issue` records the session credential hash atomically
  with the grant, issuance metadata and audit entry.
- `ApprovedSQLStore` joins `admin_sessions` on both the recorded id and
  the exact credential hash at lookup and again under the commit locks.
  Logout invalidates outstanding tokens; a reused session id with a fresh
  credential cannot resurrect them.
- Semantics pinned by the regression: step-up rows cascade on logout;
  already-issued node certificates survive administrator logout (node
  admission depends on binding/organization/node status); issuance and
  audit history reject UPDATE/DELETE and survive logout verbatim.
- Correct the one-line gofmt failure in the grants PostgreSQL integration
  test and add migration 0006 to the PostgreSQL workflow path filters.

## Evidence and gate checklist

- [x] Reproduce red locally on disposable PostgreSQL 16.2: logout under
  the 0005 schema fails with the `agent_grant_issues_session_id_fkey`
  foreign-key violation.
- [x] Apply 0006 over pre-existing issuance history: credential-hash
  backfill is correct, logout succeeds, issue/audit rows are preserved and
  reject mutation.
- [x] Extended tagged PostgreSQL regression: the outstanding token is
  denied at lookup and at commit after logout and remains unconsumed; a
  recycled session id is denied; fresh relogin issuance works; the
  previously enrolled certificate stays admitted.
- [x] Local Go race/vet, CI-list gofmt, TypeScript contracts, provenance,
  typecheck and lint (one pre-existing image warning).
- [ ] Run the PostgreSQL 17.6 tagged integration on the final PR head.
- [ ] Confirm final-head Go race/vet/gofmt, TypeScript and pinned Sing-box.
- [ ] Review the committed diff/security boundary and update PR evidence.

## Not implemented

The authenticated session/logout HTTP writer, trusted MFA step-up and
approval writers, secure one-time token delivery, issuer key custody,
certificate rotation/revocation distribution and the deployed control
plane remain independently blocked. The regression executes the same
session-row deletion a future session service will perform. No production
capability promotion or merge is authorized by this document.
