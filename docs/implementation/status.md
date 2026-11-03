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

- Local runtime smoke harness added under `lab/runtime/`: a source-pinned
  Sing-box v1.14.4 build with `with_v2ray_api`, isolated server/client network
  namespaces, real Reality/Vision TCP proxy traffic and per-user counter
  comparison. The original GitHub attestation step failed because GitHub does
  not support storing attestations for user-owned private repositories. The
  replacement keyless Cosign/Sigstore workflow signs the binary and metadata,
  verifies exact workflow/ref identity and artifact digest, and retains both
  bundles. Its first CI execution is pending. Even when green, this is local
  runtime evidence only, not M0 acceptance or external client qualification.
- Go `internal/manifest` verification core: strict typed envelope and canonical
  digest checking, Ed25519 trust, node/epoch authorization, time and replay
  checks, exact-build capability gating, dependency/port preflight and focused
  adversarial tests. This does not apply configuration or run an agent.

These are contracts and test infrastructure, **not a real network service**.
The schemas intentionally cover a narrow initial vocabulary; they do not define
all future membership, enrollment, quota, protocol or upgrade operations.

## Gate status

| Command | Status / meaning |
| --- | --- |
| `make check-contracts` | Local schema compilation + registry/unsigned fixture validity |
| `make test-contracts` | Local deterministic unit tests; includes synthetic evidence in isolated temporary directories |
| `make test-go` | Go manifest-verifier tests (including race detector) and vet; synthetic signer/manifest, no host actions |
| `make test-provenance` | Fail-closed verifier tests with mocked Cosign CLI; actual Sigstore signature verification is performed in the runtime workflow |
| `make test-runtime` | Pending CI execution; local namespace-only Reality/Vision, raw TCP and per-user counter smoke; not M0 acceptance |
| `make gate-lab` | BLOCKED: no external VPS, reference application, agent pull/report, Hysteria2 comparison or reviewed production evidence |
| `make gate-control` | BLOCKED: Go secure service/DB/auth migration and integration harness missing |
| `make gate-agent` | BLOCKED: deployable agent/helper/drivers/recovery/lease harness missing |
| `make gate-subscription` | BLOCKED: native validators and real client conformance missing |
| `make gate-resilience` | BLOCKED: independent providers, real vantages/failover/soak missing |
| `make gate-security` | BLOCKED: hardening, key lifecycle, security verification missing |
| `make gate-dr` | BLOCKED: funded backup/PITR+key restore and epoch drill missing |

TypeScript typecheck passes. ESLint passes with two existing image-optimization
warnings. The obsolete Go scaffold (which had stale imports and constructors) has
been removed. A standalone Go manifest-verification library and local Sing-box
runtime smoke are now present, but no deployable Go agent or control-plane
implementation exists. No public VPSs, representative mobile/desktop clients,
provider diversity or production topology are available for external connectivity
or production verification. The local runtime smoke result is pending CI. The previous build-attestation
failure is documented above; the replacement Cosign workflow must complete
real keyless signing and verification before the namespace smoke can run.

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


The local runtime smoke is intentionally separate from the evidence gate. It
uses a source-pinned custom Sing-box build and a synthetic local echo target. Its
report is written under ignored `.data/lab-runtime/evidence/`; it is not copied
into `capabilities/runtime.json`, `capabilities/clients.json` or the reviewed
lab evidence registry. A green smoke workflow does not make the runtime
production-qualified.

## Selective S-UI / 3X-UI integration increment

The source audit and adoption decisions are documented in
`docs/research/source-project-review.md` and ADR 0002. Both reference projects
declare GPL-3.0 and their READMEs warn against production use. No source code was
copied or vendored.

Implemented:
- `src/lib/protocol-compatibility.ts` provides a narrow explicit matrix for
  sing-box/Xray VLESS Reality/Vision over TCP and sing-box/standalone Hysteria2
  over UDP. It validates server name, Reality public key, short ID, flow and
  fingerprint before subscription IR admission.
- `src/lib/subscription.ts` now excludes incompatible endpoint configurations
  with an explicit reason before any emitter can see them, rejects paths
  unsupported by the requested output format, and requires verified exact-release
  client compatibility evidence before client-specific admission. VLESS/Reality/Vision keeps one
  canonical protocol ID across Sing-box and Xray rather than a stale
  runtime-specific alias.
- `internal/agent/sessions` tracks opaque runtime session IDs, endpoint-principal
  identity and credential generation. It distinguishes successful closure from
  sessions that can only be blocked from opening new routed flows. Close callbacks
  run outside the registry lock; idle sessions are pruned and failed closers are retried.

The new Go registry and TypeScript compatibility tests are synthetic unit tests.
The session registry is not yet connected to Sing-box, Xray or Hysteria2 drivers;
the protocol matrix is not exact-build qualification. No new runtime, client,
metering or production capability is activated by this increment.

Deferred from the source review: deterministic host ordering and per-format
exclusions, client-side balancer documents/observatory, event streaming, bulk
lifecycle/renewal and dry-run-first S-UI/3X-UI migration.

## Runtime provenance blocker (4 November 2026)

[Runtime smoke run 41735253666](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41735253666)
built the pinned Sing-box artifact, then failed at GitHub's `attest-build-provenance`
step: `Feature not available for user-owned private repositories`. Go setup,
Linux dependencies, script checks and compilation passed; **no real networking,
revocation or accounting tests ran** in that workflow. This is an external
attestation-persistence limitation, not proof of runtime failure or success.

Do not skip provenance verification, mark the runtime qualified, or weaken the
production gates. A supported GitHub repository arrangement or an independently
verifiable signed-artifact workflow must be selected and reviewed before this
provenance task can be completed. Driver interfaces and pure rendering may be
unit-tested independently, but cannot be applied by an agent without such evidence.

## Capability-gated Go driver interface (foundation only)

The `internal/drivers` Go package introduces typed inputs and outputs for
runtime rendering, native validation, preflight, structural application,
membership, health, metering, revocation, rollback and diagnostics. The
`Unsupported` adapter returns a typed `ErrUnsupportedCapability` for **all**
operations. Unit tests exercise every method and prevent false-success no-ops.

This is a contract skeleton, **not** a Sing-box/Xray/Hysteria2 runtime adapter.
No binary has been accepted, rendered or applied, and no native validation,
quota guarantee, ingress policy, real session revocation or lab gate is passed.
The separately approved and authenticated runtime-driver implementations must
supply these behaviors, with explicit release evidence.
