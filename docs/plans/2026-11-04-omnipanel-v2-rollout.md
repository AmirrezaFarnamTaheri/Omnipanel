# OmniPanel v2 Go/Vite Migration and Integration Implementation Plan

> **For agentic workers:** Use the host's available task-by-task implementation workflow. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the unified OmniPanel v2 foundation into a verifiable Go control plane, independently managed Go agent, and static React/Vite operator UI without weakening existing identity, accounting, or deployment contracts.

**Architecture:** PR #2 is the single consolidated prerequisite and remains unmerged until its own foundation checks are reviewed. Apply a strangler migration: replace Next.js routes with separate Go services behind explicit contracts, move canonical data access to PostgreSQL, use a SQLite-WAL node journal, then cut the frontend over to static Vite only when equivalent authorization and workflows pass parity tests. Enable independently evidenced runtime drivers and operational features in successive small, reviewable increments.

**Tech Stack:** Patch-pinned Go, chi, pgx/sqlc, OpenAPI-generated types, PostgreSQL 17, SQLite WAL, React, TypeScript, Vite, Tailwind/shadcn, systemd, OpenTelemetry, Prometheus-compatible metrics.

## Global Constraints

- Keep administrative intent, structural desired state, membership desired state, and observed state distinct.
- Use one `control_plane_epoch` and separately ordered `structural_sequence` and `membership_sequence` per node. Immutable rollback is a new higher revision, not history rewriting.
- The node agent initiates authenticated communication, verifies a trusted signed structured manifest, and never accepts arbitrary shell commands, binaries, paths, or unrestricted root operations.
- Preserve independent runtime systemd units and agent-local last-known-good state. Network changes require a crash-surviving commit-confirm watchdog.
- Maintain node-scoped credentials, trust anchor separation, operator MFA, object-scoped RBAC and audit; only Go authorizes after cutover.
- Meter user traffic once at the declared authoritative runtime; deduplicate by node/installation epoch/core generation/meter stream/sequence and explicitly report discontinuities. No hard quota without measured bounded enforcement, including established sessions.
- Preserve client cryptographic identity, exact-release compatibility evidence, deterministic subscription output, and explicit exclusion diagnostics. Unknown capability is unsupported.
- Require two providers/ASNs and independently verified L2/L3 paths for M1; a local namespace smoke run is not a client/VPS production gate.
- Do not rewrite already-published `db/migrations/0001_initial.sql` or `0002_m2.sql`. Create forward-only migrations, dual-read during conversion only when necessary, and test production-shape restore before cutover.
- Do not add Redis, Kafka, NATS, Kubernetes, or a universal HAProxy to M1 without separate evidence.
- **Licensing:** OmniPanel's intended license is GPL version 3, as approved by the project owner. Use `GPL-3.0-only` for OmniPanel's original code and retain all compatible third-party notices, license files and source provenance. S-UI, 3X-UI and 1Panel source reuse requires preserving authorship, notices and provenance. The pinned Hiddify Panel submodule is separately CC BY-NC-SA licensed; do not copy that source or its templates into GPL-distributed OmniPanel without separate authorization.

---

## Repository baseline verified 2026-11-04

- Unified open [PR #2](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/2) is based on `main`. It contains foundational TypeScript Next.js/Drizzle code, contract schemas, Go `internal/manifest` verification, an in-memory `internal/agent/sessions` registry and `lab/runtime/` scripts.
- `src/lib/capabilities.ts`, `src/lib/protocol-compatibility.ts` and `src/lib/subscription.ts` contain **prototype** compatibility and subscription logic; they are reference behavior for parity tests, not the final authorization or data model.
- The legacy `src/db/schema.ts` and two SQL migrations are canonical for any existing prototype database, but they do not yet implement all v2 organization, PKI, accounting and recovery requirements.
- `cmd/omni-admin`, `cmd/omni-agent-gateway`, `cmd/omni-sub`, `cmd/omni-node`, `cmd/omni-helper`, `internal/drivers` and `web/` do not yet exist on PR #2. Every path below in those trees is **proposed**.
- `make check-contracts`, `make test-contracts` and `make test-go` run foundation checks; production gates intentionally exit BLOCKED. `make test-runtime` requires a privileged Linux lab environment.
- On head `0b3932f`, the foundation verification workflow succeeded but the local runtime-smoke run failed at the **build-attestation** step. The real connectivity and accounting smoke steps were skipped. Diagnose this before trusting lab evidence; do not mark any runtime production qualified.

## Transition strategy and one-PR rule

The current stacked changes remain in **one** open PR (#2); do not reopen superseded PR #1 or create another overlapping foundation PR. Put this plan and necessary review fixes in #2. Once #2 is accepted and merged, subsequent small feature PRs may target `main`; if implementation must start before merge, stack narrowly on the exact PR #2 head and disclose the dependency. Do not merge or close #2 without review.

The Next.js application stays a **non-production prototype** throughout migration. Do not expose it as a live fallback to a Go control plane. For each operator workflow, establish OpenAPI request/response parity and RBAC/audit tests, then switch traffic to Go. Remove the old Next.js server/actions/Drizzle implementation only after the Vite static UI and Go APIs cover the necessary flows and all dependent imports are gone. Avoid a dual-authority interval.

## Reviewed source-project selection

| Candidate capability | Source reference | Target boundary | Admission rule |
| --- | --- | --- | --- |
| Live-session authorization and revocation | S-UI | `internal/agent/sessions` + runtime adapters | Existing streams vs new streams separately measured; no unsupported hard disconnect claim |
| Xray protocol/transport predicates and per-format exclusions | 3X-UI | `internal/capability`, `internal/subscription` | Typed errors for unsupported core/transport/client releases |
| Domain/CDN access-path modeling, sync tombstones, ACME lifecycle | Hiddify Manager/Panel | `internal/domain`, `internal/subscription`, `internal/certificates` | **Design reference only** for CC BY-NC-SA panel code; direct/CDN TLS boundaries explicit |
| Host metrics, safe firewall inventory, job/backups, notifications | 1Panel | `internal/observability`, `internal/networking`, `internal/jobs`, `internal/backup` | Narrow managed operations, no generic root shell; TLS verification on remote backup |
| S-UI and 3X-UI user/inbound import | S-UI, 3X-UI | `internal/importers` (M3) | Dry-run, explicit provenance; imported counters never become billable exact usage |
| Relay, WARP, ingress demux and external sources | Reference projects | `internal/relays`, `internal/egress`, `internal/external` (M2) | Separate operator approvals, failure semantics, security and account-boundary gates |

Detailed Hiddify/1Panel observations and license boundaries are recorded in `docs/research/hiddify-1panel-review.md`.

## Delivery sequence and interfaces

Each row is a distinct future review gate, **not** a claim of an implemented feature. Proposed paths will be added only with corresponding tests and ownership.

| Order | Deliverable | Consumes | Produces | Required evidence |
| --- | --- | --- | --- | --- |
| 1 (M0) | Reproducible runtime provenance and safe driver contracts | `contracts/desired-state.schema.json`, `internal/manifest`, `lab/runtime` | `internal/drivers`, exact-build runtime evidence | Signed artifact provenance, native validators, real reference-client connectivity; Hysteria2 comparison |
| 2 (M1) | Go secure control plane | OpenAPI, canonical IR, qualified builds | `cmd/omni-admin`, `cmd/omni-agent-gateway`, `cmd/omni-sub`, `internal/auth`, `internal/store`, `db/migrations/0003_*.sql` | PostgreSQL transactions, idempotency, MFAs/RBAC/object access, mTLS, atomic audit/outbox |
| 3 (M1) | Durable agent and safe reconciliation | Signed manifests, per-node identity, qualified drivers | `cmd/omni-node`, `cmd/omni-helper`, `internal/agent/state`, `internal/agent/reconcile` | Independent systemd lifecycle, SQLite WAL, failure-injection 20/20, external rollback watchdog |
| 4 (M1) | Authoritative accounting and entitlements | Driver counter/revocation measurements, local journals | `internal/agent/metering`, `internal/agent/leases`, `internal/accounting`, `internal/entitlements` | 1,000 duplicate/replay cases produce zero duplicate charges, every gap classified, leases bounded |
| 5 (M1) | Client compiler and secure distribution | IR, exact client/version evidence, endpoint principals | `internal/subscription`, separate `omni-sub`, `web/features/subscriptions` | Deterministic output, strict security-field preservation, real client imports, cross-user isolation, mirror auth |
| 6 (M1) | Operational foundation | Node observations, signed revisions, PostgreSQL jobs | `internal/health`, `internal/observability`, `internal/jobs`, `internal/backup`, `internal/certificates` | Multi-vantage L2/L3 health, alert thresholds, backup+independent KEK restore, renewal/rollback tests |
| 7 (M1) | Go/Vite operator cutover | Go OpenAPI/auth, audited behavior parity | `web/`, removal of Next.js/Drizzle after parity | MFA/session/CSRF tests, RBAC, redacted previews, current user/node/subscription workflows |
| 8 (M1) | Independent exit qualification | Two providers, client matrix, durable agent | `tests/e2e`, `tests/chaos`, `runbooks`, `deploy/production` | New-connection failover, 24h soak, load envelope, PITR+keys+new epoch, rollback |
| 9 (M2+) | Individually gated integrations | Stable M1 driver/IR/policy contracts | Xray/XHTTP, CDN WS/TLS, relay, approved alternate egress, restricted BPB | Independent versioned evidence per topology and security boundary |

### Canonical database strategy

The prototype's `nodes`, `inbounds`, `endpoint_principals`, `meter_streams`, `meter_observations`, `usage_aggregates`, `usage_quality_intervals`, `structural_revisions`, `membership_events`, `outbox_jobs` and `audit_log` are migration inputs, not a reason to preserve the Next.js ORM. Proposed forward-only `db/migrations/0003_organization_identity.sql`, `0004_node_pki_revisions.sql` and `0005_accounting_quality.sql` each have scope-limited backfills and transaction/restore tests. Split them further if deployment tests reveal different locking or backfill risk.

Migrate identity and node scope first, then signer/epoch/revision state, then accounting streams and authoritative attribution, before switching data writes. Never infer new organization ownership from a foreign-key join without a tested backfill. Any surviving `0002_m2.sql` tables remain inert until separate M2 gates; do not drop historical migrations to make the tree look tidy. Preserve zero-downtime compatibility only where actually verified.

### Dependency and release gates

Use the existing commands until replaced by tested Go equivalents:

```sh
npm ci
make check-contracts
make test-contracts
make test-go
npm run typecheck
npm run lint
# Privileged, network-namespace Linux lab with exact installed tooling:
make test-runtime
# Must remain blocked until their evidence is real:
make gate-lab
make gate-control
make gate-agent
make gate-subscription
make gate-resilience
make gate-security
make gate-dr
```

Do not change a gate to exit successfully merely because a unit test passes. M1 is not complete until two independent exits, real authenticated probes, account-safe billing, security and full restore with keys are verified. M2 features remain separate and must not silently appear in production subscriptions.

## Known risks and open decisions

1. **Runtime attestation is failing at the current PR head**; diagnose permissions/signing/backend in the failed workflow, do not bypass provenance to green CI. Private-repository attestations may require repository configuration or a different independently verifiable signer.
2. The historical `.data/kek` blob was once tracked; deleting it from a later tree does not revoke the key. Identify impacted environments, rotate credentials and plan separate Git-history remediation only after coordination.
3. Root `LICENSE` uses GPL-3.0-only for original OmniPanel code. Perform a file-level provenance, attribution and compatibility audit before reusing third-party sources; treat non-GPL-licensed Hiddify Panel code as reference only. Hiddify Panel's pinned CC BY-NC-SA source must not be transplanted by assumption.
4. Product/security must approve quota class, offline lease/grace, existing-session revocation promises, supported exact clients, mirror trust, private-network egress exceptions and automated rotation scope.
5. Operations must fund two independent provider/ASN exits, second subscription host, backups/keys and external probe vantages. RPO/RTO/availability remain test targets rather than promises.
6. Verify the production migration/rollback window, imported-data retention/erasure and cutover policy before disabling the legacy application.

**Next executable increment:** [Runtime Evidence and Driver Contract Plan](2026-11-04-runtime-evidence-and-driver-contract.md). Future workstream plans should be written from observed repository and lab results rather than inventing unverified APIs or capabilities.
