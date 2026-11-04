# OmniPanel v2 — four-panel selective adoption increment

**Baseline:** Unified PR #2, fed by the stacked enrollment-hardening PR.
**Date:** 4 November 2026. **References:** S-UI `19302d1`, 3X-UI `83ea59f`,
Hiddify-Manager `9974dc3` (panel submodule `6f3e4457`, CC BY-NC-SA 4.0,
excluded), 1Panel `30381a3`. Fork heads re-verified unchanged on this date.

## Scope

Implement the next bounded adoptions from
`docs/research/four-panel-integration-assessment.md` as independent,
tested code — never copied sources, installers or submodules:

1. **S-UI stats-drain lessons → `internal/agent/metering`.** A fail-closed
   traffic accumulator: destructive-drain retention on storage failure,
   per-user folding (bounded pending window, explicit capacity error),
   absolute-total flush for idempotent upsert stores, plus OmniPanel's
   generation contract (stale-generation refusal, idempotent drain replay,
   counter-regression and overflow refusal). Race-tested.
2. **1Panel socket ownership checks → journal hardening.**
   `internal/agent/state.Open` verifies caller uid ownership of the parent
   directory and journal, and refuses hostile `-wal`/`-shm` sidecars
   (symlink, non-regular, permissive or foreign-owned) before SQLite opens
   them. Non-POSIX stat fails closed.
3. **3X-UI deterministic host ordering → subscription regressions.** New
   contract tests pin byte-stable emission, exact IR-order preservation,
   stable per-format exclusion diagnostics and refusal of
   diagnostic-carrying IRs across sing-box, Xray, Mihomo and URI formats.
4. **Hiddify-Manager → boundary re-verification.** The manager repo's
   service separation is already reflected in the lab generation layout
   and isolated subscription budget; the separately licensed panel
   submodule stays excluded. No code adoption from it is legal or planned.

## Evidence and gate checklist

- [x] Re-fetch all four forks at pinned revisions; confirm heads unchanged
  and the Hiddify panel gitlink/license boundary intact.
- [x] `internal/agent/metering` unit + concurrency tests with `-race`.
- [x] Journal sidecar/ownership tests (symlink, group/world-readable,
  directory sidecar, fabricated foreign uid, private sidecar acceptance).
- [x] Subscription determinism/exclusion contract tests (TypeScript).
- [x] Foundation gofmt gate extended to the new metering package.
- [ ] Final-head CI: Go race/vet/gofmt, TypeScript contracts, PostgreSQL
  enrollment and pinned Sing-box smoke.
- [ ] Review the consolidated diff and update PR #2 evidence.

## Not implemented / still blocked

Durable metering delivery, restart rehydration and native runtime counter
wiring; privileged helper IPC; deployable agent/control plane; hot-revocation
lab evidence; Hiddify panel behaviors requiring the NC-licensed source;
1Panel Pro multi-node, app-store or general server administration. All
production acceptance gates remain BLOCKED. This increment claims foundation
code and tests only.
