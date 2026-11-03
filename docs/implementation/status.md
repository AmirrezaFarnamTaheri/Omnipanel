# Implementation and verification status

As of 2026-11-03. **No M0 walking-skeleton, M1 or M2 acceptance is claimed.**

## This increment

Implemented and locally exercised:

- Strict Draft 2020-12 schemas for desired-state envelope, endpoint IR, lab
  evidence, candidate runtime, exact client release and metering registries.
- Contract preflight: unknown-field/version rejection, safe integers, dependency
  graph validity, effective socket conflict checks and validity ordering.
- Pure ingress planner: TCP/UDP independence, IPv4/IPv6 wildcard and mapped-IP
  conflicts, explicit IPv6-only semantics, literal binding validation.
- Lab evidence loader: exact runtime/version/digest/platform matching, required
  claims, exact client-release references, metering contract references, 90-day
  freshness, latest-result handling, duplicate/ambiguous results, bounded local
  artifacts/digests and artifact symlink escape rejection. Passing accounting
  evidence needs measured bidirectional payloads within its declared error bound
  (at most 5% in this initial lab harness, not a billing SLA).
- Fail-closed legacy admission and subscription filtering: empty reviewed-build
  qualification set; historical notes cannot activate any driver or strict quota.
  Corrected BPB unmanaged-source labeling and removed its hard-quota candidacy.
- Candidate v2 OpenAPI and documented target architecture/threat model.

These are contracts and test infrastructure, **not a real network service**.
The schemas intentionally cover a narrow initial vocabulary; they do not define
all future membership, enrollment, quota, protocol or upgrade operations.

## Gate status

| Command | Status / meaning |
| --- | --- |
| `make check-contracts` | Local schema compilation + registry/unsigned fixture validity |
| `make test-contracts` | Local deterministic unit tests; includes synthetic evidence in isolated temporary directories |
| `make gate-lab` | BLOCKED: no pinned builds, verified client/metering entries or real runtime evidence |
| `make gate-control` | BLOCKED: Go secure service/DB/auth migration and integration harness missing |
| `make gate-agent` | BLOCKED: deployable agent/helper/drivers/recovery/lease harness missing |
| `make gate-subscription` | BLOCKED: native validators and real client conformance missing |
| `make gate-resilience` | BLOCKED: independent providers, real vantages/failover/soak missing |
| `make gate-security` | BLOCKED: hardening, key lifecycle, security verification missing |
| `make gate-dr` | BLOCKED: funded backup/PITR+key restore and epoch drill missing |

TypeScript typecheck passes. ESLint passes with two existing image-optimization
warnings. The obsolete Go scaffold (which had stale imports and constructors) has been
removed rather than shipped as a plausible agent. A verified Go implementation
remains outstanding. No runtime binaries, private
VPSs, paying users, provider diversity or representative clients were available
for connectivity or production verification.

The old pg-mem E2E script was retired because it bypassed real transaction/
concurrency primitives and its admission assumptions conflict with fail-closed
runtime qualification. Real database and networking tests remain outstanding.

`npm audit` reports 22 unresolved vulnerabilities in the legacy dependency tree
(19 moderate, 2 high, 1 critical at inspection), including Next.js/PostCSS/sharp.
New direct harness dependencies are patch-pinned; this change is not dependency
security sign-off. Upgrade or retire the affected prototype dependencies with
regression checks before any exposure. Never run an uncontrolled major-version
`audit fix --force` as a substitute for review.

## Next bounded increments

1. **Task 1 real lab:** provision Ubuntu 24.04 amd64 lab node and reference client;
   select exact signed runtime builds; implement typed render/validate/driver
   contracts; prove one user Reality/Vision L3, revocation/session effects,
   attributable counters, outbound agent pull/report and last-good recovery.
   Compare both Hysteria2 implementations, including UDP impairment and reload
   generations. Record native validators and redacted reproducible transcripts.
2. **Contract freeze and Task 2:** patch-pin a supported Go toolchain/PostgreSQL,
   implement service entrypoints with isolated identities, organization-
   scoped schema, MFA/bootstrap/RBAC/CSRF, endpoint-secret lifecycle, concurrent
   revisions/idempotency, transactional outbox+audit, signer/PKI and mTLS enrollment.
   Generate server/client types; migrate static UI to Vite without independent auth.
3. **Task 3:** SQLite WAL journal and metering queues, typed helper, independent
   systemd units, generation configs, external commit-confirm watchdog, separate
   structural/membership streams, accounting continuity/dedup and measured local
   entitlement behavior. No hard quota until bounded lease/session tests pass.
4. **Task 4 M1:** two independent providers/ASNs, real multi-vantage L2/L3 probes,
   client compatibility/conformance, authenticated independent mirror, canary
   rollout, load/chaos/24h soak, keys+PITR restore and compromise runbooks.
5. **M2 separately:** XHTTP, CDN, one-hop relay, approved alternate egress and
   restricted external BPB. Gate each before including it in subscriptions.

Do not publish production golden configs, support claims, quota bounds, uptime,
RPO/RTO or benchmark numbers until the corresponding real evidence exists.

## Repository consolidation and cleanup

The stacked foundation PRs were unified without merging either into the default
branch. Removed non-operational milestone-specific integrations, fabricated demo
runtime state, the duplicate login route with hard-coded demo credentials, the
no-op settings mutation and the non-buildable Go scaffold. Settings are now
explicitly read-only, and the main navigation reports prototype status rather
than a fabricated operational signal. The historical optional-integration SQL
migration remains in place to avoid breaking already-migrated databases.

A tracked development key was removed from the working tree. Revoke or rotate
keys and affected credentials in any environment that consumed it; Git history
still contains the prior blob until separately remediated. No production safety
claim follows from the cleanup. End-to-end validation requires CI and a real
networking laboratory.
