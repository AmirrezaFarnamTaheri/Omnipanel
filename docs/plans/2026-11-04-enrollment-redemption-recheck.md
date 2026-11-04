# OmniPanel v2 — redemption-time authorization gate

**Baseline:** Unified PR #2 at `8464b1c`, branch
`arena/a1949059-omnipanel`. **Date:** 4 November 2026.

## Scope

- Introduce `ApprovedSQLStore` implementing the existing
  `enrollment.TokenStore` interface. Use the same PostgreSQL-issued
  grants and append-only audit from migration 0005.
- A token cannot redeem if its node UUID binding was revoked, its
  organization suspended, its legacy node quarantined, the issuer or
  second approver lost authorization, or the issuing session expired.
- Recheck everything inside the same PostgreSQL transaction that consumes
  the bearer and registers the certificate. Lock approval rows to avoid
  time-of-check/time-of-use authorization bypasses.
- `Active` must reject already-issued certificates for a currently
  quarantined/revoked node or suspended organization. An allowed node may
  transition to active/draining.
- Keep `SQLStore` as a clearly labeled unchecked transaction-test
  primitive. Only `ApprovedSQLStore` is suitable for future runtime
  issuer wiring. No hosted endpoint is introduced.

## Evidence and gate checklist

- [x] Review current PR head, grant issue schema, legacy node mapping, and
  certificate transaction paths.
- [x] Add real PostgreSQL regression for revoked binding after token lookup.
- [x] Observe red: revoked binding still minted certificate through raw
  SQLStore in Actions run 41858179355 (expected test failure).
- [x] Implement protected lookup, atomic commit and online admission.
- [x] Add denial cases for revoked operator/approver scope, suspended org,
  quarantined node, expired issuer session and valid post-enrollment state.
- [ ] Run PostgreSQL tagged integration on final PR head and confirm all
  test cases, including original enrollment and limiter tests.
- [ ] Confirm final-head Go race/vet/gofmt, TypeScript and pinned Sing-box.
- [ ] Review committed diff/security boundary and update PR evidence.

## Not implemented

The trusted MFA-step-up/approval writers, safe one-time token delivery,
provisioned issuer key custody, production HA/PITR, public gateway wiring,
certificate rotation and privileged apply/rollback remain independently
blocked. No production capability promotion or merge is authorized.
