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

- [ ] Persistent task repository / transactional outbox, lease and crash recovery.
- [ ] Backup byte-transfer providers, envelope encryption and independent key recovery.
- [ ] PostgreSQL PITR + key restore drills; current model does not verify recoverability.
- [ ] Read-only node resource inventory and firewall inventory contracts.
- [ ] Subscription metadata header additions and pure calendar expiry presentation tests.
- [ ] Metering durable outbox/rehydration and native runtime session revocation.
- [ ] Hiddify-inspired node cursor/tombstone and certificate inventory contracts.

## Verification

Local `go test -race ./internal/backup` passed on Go 1.27.3. Full CI on the final PR head remains required. This contract neither performs a backup nor unblocks `gate-dr`, `gate-agent`, or any production gate.
