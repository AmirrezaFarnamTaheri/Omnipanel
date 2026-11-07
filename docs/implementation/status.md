# OmniPanel v2 — Implementation & Gate Verification Status

## 1. Executive Summary

OmniPanel v2 contains partially integrated fail-closed control-plane and node-reconciliation contracts across its Go packages (`internal/...`, `cmd/omnipanel-admin`) and its TypeScript/Next.js + PostgreSQL control plane (`src/...`, `contracts/...`, `db/migrations/...`).

- **Fail-Closed Runtime Admission**: `QUALIFIED_BUILDS` in `src/lib/capability-policy.ts` remains empty (`{}`) until external multi-host lab evidence (`make gate-lab`) is supplied and reviewed. The qualification map remains empty, so new endpoints must fail closed. Existing legacy data and external deployment paths require separate audit; this is not production qualification.
- **Deterministic Contract & Unit Verification**: The project defines `npm run check:contracts`, `npm run test:contracts`, `npm run typecheck`, `npm run lint`, `npm run build`, `make test-go`, and `make test-provenance`. Verify each against the current commit's CI run; previous green runs do not qualify changed code.
- **Clean-Room Four-Panel Recomposition**: Lessons from S-UI, 3X-UI, Hiddify Manager, and 1Panel are implemented as pure, auditable contracts with zero copied third-party code and zero raw host shell execution.

---

## 2. Implemented Subsystem Matrix

| Subsystem | Go Foundation (`internal/*`) | TypeScript Control Plane (`src/lib/*`) | Verification |
| --- | --- | --- | --- |
| **Signed Desired-State (`ed25519-jcs-v1`)** | `internal/manifest` | `src/lib/desired-approvals.ts`, `src/lib/revisions.ts` | Schema + Ed25519 signature + monotonic epoch/sequence checks |
| **Dual-Operator Publication Approval** | `internal/control/desiredapproval`, `internal/control/desiredpublish` | `src/lib/desired-approvals.ts`, `src/lib/governance-store.ts` | Distinct owner proposer/approver, SHA-256 digest binding, one-time consumption |
| **Enrollment Authority & Trusted Step-Up** | `internal/pki/enrollment`, `grants`, `httpapi` | `src/lib/enrollment-grants.ts`, `src/lib/totp.ts` | RFC 6238 replay counter, 2h idle recheck, logout revocation, 60s HMAC peer limiter |
| **Journaled Reconciler & Watchdog** | `internal/agent/reconcile`, `internal/agent/state` | `src/lib/reconcile-watchdog.ts` | 8-stage SQLite WAL state machine, commit-confirm deadline, autonomous LKG rollback |
| **Live Session Registry & Revocation** | `internal/agent/sessions` | `src/lib/session-registry.ts` | Explicit `closed` (TCP closer) vs `muted_unclosable` (QUIC/Hysteria2) accounting |
| **Durable WAL Metering** | `internal/agent/metering` | `src/lib/durable-metering.ts`, `src/lib/metering.ts` | Persist-before-ack WAL checkpointing, process-generation reset detection, gap recording |
| **Bounded SyncFeed** | `internal/agent/syncfeed` | `src/lib/syncfeed.ts` | Contiguous sequence cursors, empty-payload tombstones, 64-bit BE length-prefixed SHA-256 |
| **Host Resource Observability** | `internal/observability` | `src/lib/observability.ts` | CPU/Memory/Filesystem/Net telemetry strictly separated from L0–L3 proxy health |
| **Backup Task Ledger & PITR/KEK Drills** | `internal/backup` | `src/lib/backup-tasks.ts`, `src/lib/backup-providers.ts` | Monotonic task state machine, AES-256-GCM DEK/KEK unsealing, epoch advancement |
| **Firewall & Certificate Boundaries** | `internal/drivers` | `src/lib/firewall-inventory.ts`, `src/lib/certificate-inventory.ts` | Read-only `nftables` ownership split (`invokesHostShell: false`) & isolated TLS trust domains |
| **Subscription Compiler & Importer** | `internal/drivers/singbox` | `src/lib/subscription.ts`, `src/lib/panel-importer.ts` | Deterministic IR ordering, RFC headers, dry-run S-UI/3X-UI importer (`historical_non_billable`) |

---

## 3. Production Gate Status (`Makefile`)

| Target | Milestone | In-Repo Contract Suite | External Lab Gate | Remaining External Requirement |
| --- | --- | --- | --- | --- |
| `make gate-lab` | M0 | Contract suite only | **BLOCKED** | Public VPS + external client transcript + reviewed runtime build entry in `QUALIFIED_BUILDS` |
| `make gate-security` | M1 | Contract suite only | **BLOCKED** | End-to-end live Go daemon mTLS + step-up penetration test transcript |
| `make gate-agent` / `make gate-resilience` | M1 | Contract suite only | **BLOCKED** | Root Linux `nftables` / `systemd` fault-injection rollback transcript |
| `make gate-subscription` | M1 | Contract suite only | **BLOCKED** | Live real-client subscription/revocation and 1 GiB Sing-box + Hysteria2 metering within ±0.5% accuracy |
| `make gate-dr` | M1 | Contract suite only | **BLOCKED** | External PostgreSQL `pg_wal` archive restore & live mTLS agent epoch cutover |
| `make gate-control` | M1 | Contract suite only | **BLOCKED** | End-to-end Go control-to-agent commit and live S-UI / 3X-UI SQLite cutover verification |
| M2 acceptance (not implemented as a Make target) | M2 | Not qualified | **BLOCKED** | All M0 and M1 external gates and production migration completed |
