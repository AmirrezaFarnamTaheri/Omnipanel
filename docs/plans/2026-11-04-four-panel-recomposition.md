# Four-panel decomposition and recomposition increment

**Date:** 2026-11-04. **Scope:** bounded independent contracts informed by pinned source review; no upstream code copied, installers executed, or production services deployed.

## Source investigation

See [`docs/research/four-panel-file-level-map.md`](../research/four-panel-file-level-map.md) for the file-level source-to-target map. The reviewed areas include S-UI's destructive stats drain and session registry; 3X-UI's stable host ordering, common subscription metadata headers, calendar expiry tests and protocol predicates; Hiddify-Manager's split source/generated/service architecture, panel submodule and optional L4 service; and 1Panel's owner-checked local socket, backup task records, monitoring, firewall adapters, cron and storage behavior. Findings remain bounded by the pinned revisions and static-review limits documented in the assessment.

## Implemented

- [x] Add provider-neutral backup/restore lifecycle model in `internal/backup`.
- [x] Encode retry attempts, monotonic timestamps, constrained transitions, immutable success, stable bounded error codes and digest-required completion.
- [x] Test backup failure/retry/success, restore verification, error-code validation and clock regression using Go race tests.
- [x] Include new package in Foundation's explicit gofmt gate.
- [x] Document source mapping, exclusions, target decomposition and evidence limits.

## Deferred (separate increments)

- [x] Persistent SQLite WAL task repository with private-directory/database/sidecar checks and restart persistence; PostgreSQL transactional outbox, leases and multi-process crash recovery remain deferred.
- [ ] Backup byte-transfer providers, envelope encryption and independent key recovery.
- [ ] PostgreSQL PITR + key restore drills; current model does not verify recoverability.
- [x] Read-only node resource snapshot validation/freshness contract (`internal/observability`); firewall inventory contract remains deferred.
- [x] Subscription metadata header validation/encoding and pure exclusive-vs-inclusive expiry presentation tests; optional Support-Url/Profile-Web-Page-Url/Announce emitters require validated HTTPS/header-safe metadata. Integration with user-admin configuration remains deferred.
- [x] Bounded durable metering checkpoint/outbox rehydration in the protected SQLite WAL node journal; native runtime drain wiring, remote transactional delivery and session revocation remain deferred.
- [x] Hiddify-inspired bounded node cursor/tombstone page validation contract (`internal/agent/syncfeed`); authentication, persistence, application, and certificate inventory remain deferred.

## Verification

Local `go test -race -count=1 ./internal/backup` and `go vet ./internal/backup` passed on Go 1.27.3 for the persistent repository implementation, including restart persistence, private path/sidecar rejection, and WAL/FULL PRAGMA checks. Full CI on the final PR head remains required. This ledger neither performs a backup nor unblocks `gate-dr`, `gate-agent`, or any production gate.
