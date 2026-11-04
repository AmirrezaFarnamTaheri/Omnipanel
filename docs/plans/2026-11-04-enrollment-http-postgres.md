# Bounded enrollment HTTP and PostgreSQL execution plan

**Baseline:** OmniPanel v2 unified PR #2, on `arena/a1949059-omnipanel`.
**Date:** 4 November 2026. **Status:** implementation and CI verification.

## Scope and invariants

Create an unhosted, intentionally narrow bootstrap enrollment handler and a
real PostgreSQL transaction test gate. The token must be minted by an
authorized operator workflow outside this handler; CSR and forwarded headers
never authorize identity. TLS 1.3 is mandatory for the bootstrap exchange;
it cannot require a client certificate before issuance. The issuer signs
only with a separate key-custody service, and grant redemption is atomic
with recorded credential creation. HTTP status/CSRs are not evidence of
agent application, connection health, or recovery.

## Implementation / verification checklist

- [x] Inspect current signed-polling / PKI code, OpenAPI and migration schema.
- [x] Red/green local handler tests: one-time bearer/CSR exchange, spoofed
  certificate/IP headers, strict JSON, size and compression bounds, TLS 1.3,
  limiter failure/denial, and generic non-leaking errors.
- [x] Add `internal/pki/enrollment/httpapi` as an interface-injected handler,
  with no grant-minting or privileged operations.
- [x] Document `POST /v2/nodes/enroll` as a distinct bearer-based bootstrap
  operation; retain mTLS on the signed node-polling endpoint.
- [x] Add tagged real PostgreSQL integration tests for migration 0003, replay,
  atomic consumption, concurrent calls, rollback, revocation and constraints.
- [x] Add isolated PostgreSQL GitHub Actions service and pinned test-only
  `github.com/lib/pq` dependency.
- [ ] Inspect final-head Go race/vet/gofmt, OpenAPI/contracts, PostgreSQL
  integration and existing signed Sing-box runtime CI results.
- [ ] Perform independent deployment security review before planning admin
  approval, issuer key custody or listener exposure.

## Explicitly blocked

This increment **does not** create a production issuing service, approved
operator grant API, real shared limiter, certificate renewal or delivered
revocation across gateways. It does not replace the current agent mTLS
polling contract, promote any applied revision, or implement node rollback.
No automatic production-gate promotion or merge is authorized.
