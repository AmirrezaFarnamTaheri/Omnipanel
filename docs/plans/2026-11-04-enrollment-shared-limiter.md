# OmniPanel v2 — shared enrollment abuse-control increment

**Target:** unified PR #2, branch `arena/a1949059-omnipanel`.  
**Scope:** implement a bounded PostgreSQL-backed admission limiter for the
already unhosted `POST /v2/nodes/enroll` bootstrap API.

## Decisions

- Enforce **both** global and canonical peer-IP quotas per 60-second
  PostgreSQL-clocked window, atomically, even across separate gateway
  instances. A closed/slow database fails closed; no process-local fallback.
- Require a pre-provisioned 256-bit shared HMAC key. Never store raw IP
  addresses, bearer tokens, private keys or CSR contents in the quota table.
- Perform no grant creation, CA signing, host operations, nor service start
  in the limiter; keep trusted maintenance separate from HTTP traffic.
- Use the dedicated local disposable PostgreSQL CI job. The test is not a
  production HA, key rotation, rate-limit tuning or DR qualification.

## Verification ledger

- [x] Inspect the current enrollment handler injection interface and CI.
- [x] Observe red tests against a deliberately unimplemented limiter.
- [x] Implement constructor validation, HMAC IP normalization and fail-closed
  storage gate; observe local green Go race tests and vet.
- [x] Add PostgreSQL migration 0004 and multi-instance/concurrency/forwarded
  header/database outage integration tests.
- [x] Extend the existing PostgreSQL CI to run the new migration and test.
- [ ] Verify **final PR head** Go race, gofmt/vet, TypeScript contracts,
  PostgreSQL, and Sing-box runtime CI. Record links after results.
- [ ] Independent security review of external issuer/PKI and approved
  operator grant API (not part of this increment).

**Deployment state:** BLOCKED. No runtime gateway is configured or deployed.
