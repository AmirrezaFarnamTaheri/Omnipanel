# OmniPanel v2 — Implementation & Gate Verification Status

## 1. Executive Summary

OmniPanel v2 enforces a fail-closed control-plane and node-reconciliation baseline across both its Go packages (`internal/...`, `cmd/omnipanel-admin`) and its TypeScript/Next.js + PostgreSQL control plane (`src/...`, `contracts/...`, `db/migrations/...`).

- **Fail-Closed Runtime Admission**: `QUALIFIED_BUILDS` in `src/lib/capability-policy.ts` remains empty (`{}`) until external multi-host lab evidence (`make gate-lab`) is supplied and reviewed. No unqualified runtime build can be admitted for new endpoints or emitted in subscriber configurations.
- **Deterministic Contract & Unit Verification**: All 7 JSON Schemas + OpenAPI (`npm run check:contracts`), 100 TypeScript contract tests (`npm run test:contracts`), Go manifest/driver/agent/control-plane packages (`make test-go`), and Sigstore/Cosign provenance tests (`make test-provenance`) are verified in-repo.
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
| `make gate-lab` | M0 | PASS | **BLOCKED** | Public VPS + external client transcript + reviewed runtime build entry in `QUALIFIED_BUILDS` |
| `make gate-m1-security` | M1 | PASS | **BLOCKED** | End-to-end live Go daemon mTLS + step-up penetration test transcript |
| `make gate-m1-rollback` | M1 | PASS | **BLOCKED** | Root Linux `nftables` / `systemd` fault-injection rollback transcript |
| `make gate-m1-metering` | M1 | PASS | **BLOCKED** | Live 1 GiB Sing-box + Hysteria2 transfer soak within ±0.5% accuracy |
| `make gate-m1-dr` | M1 | PASS | **BLOCKED** | External PostgreSQL `pg_wal` archive restore & live mTLS agent epoch cutover |
| `make gate-m1-migration` | M1 | PASS | **BLOCKED** | Live S-UI / 3X-UI SQLite database cutover verification |
| `make gate-m2` | M2 | PASS | **BLOCKED** | All M0 and M1 external hardware gates completed |
