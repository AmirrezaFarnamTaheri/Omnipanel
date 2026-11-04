# OmniPanel v2 — verified enrollment MFA step-up

**Target:** open unified PR #2, `arena/a1949059-omnipanel`.
**Baseline:** commit `b58d314` with foundation/PostgreSQL/Reality-Vision
CI green. **Date:** 4 November 2026.

## Security invariants

- An owner session must be authenticated using its existing SHA-256 bearer
  digest; require live idle/absolute session lifetime and TOTP enrollment.
- The trusted verifier, never an HTTP caller, determines the admin and
  step-up time. The TOTP secret is opened only by an injected identity-bound
  external key custodian and wiped from working buffers.
- RFC 6238 six-digit TOTP with ±one 30-second window, a persistent
  per-admin monotonic counter, and a PostgreSQL-clocked 5-attempts/5-minute
  account budget. Replay across sessions and datastore outage fail closed.
- Legacy manually recorded step-ups migrate to `verified_source=legacy`
  and cannot authorize a new certificate enrollment grant.
- Keep the service internal-only, with no root operations, public admin
  HTTP handler, key file, or certificate issuer deployment.

## Evidence checklist

- [x] Review actual legacy admin/session and TOTP secret structure;
  verify the latest PR head and green baseline.
- [x] Observe local red/green against RFC 6238 and replay tests:
  local `go test` failed with the behavior stub, then
  `go test -race -count=1 .` and `go vet .` passed.
- [x] Add fail-closed `StepUpService` using DB session identity and an
  externally injected secret-opening interface.
- [x] Add forward-only PostgreSQL migration 0007; make grant issuance
  depend on recorded trusted verification.
- [x] Add real PostgreSQL integration cases for untrusted legacy rows,
  bad factors, verified step-up, replay, role demotion and attempt cap.
- [ ] Verify final-head PostgreSQL tagged integration, Go race/vet/gofmt,
  TypeScript contracts and signed Sing-box smoke.
- [ ] Review DB grants/row ownership for prod and secure KMS/KEK custody,
  admin origin/CSRF checks, approval writes, token delivery, and
  production migration/PITR separately.

**Production gates:** remain BLOCKED. This increment is non-deploying.
