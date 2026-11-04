# OmniPanel v2 — durable S-UI-inspired metering checkpoint

**Target:** unified PR #2. **Reviewed refs:** 1Panel `30381a3` (`dev-v2`), 3X-UI `83ea59f` (`main`), S-UI `19302d1` (`main`), Hiddify-Manager `9974dc3` (`dev`); all four branch refs were re-fetched on 5 November and remained unchanged. The Hiddify-Panel submodule remains excluded. This adopts behavior through an independent implementation, not copied source.

## Source lesson and bounded target

S-UI's stats drain can be destructive, so failures must retain observations; its bounded fold avoids an unbounded pending batch. OmniPanel already had a generation-aware in-memory accumulator with absolute-total flush semantics. This increment adds protected, restart-surviving checkpoints through the existing owner-only SQLite WAL node journal:

- persist accepted counter drains before reporting success to a caller, so a destructive runtime adapter can acknowledge only after durable commit;
- rehydrate totals, last generation/sequence/counters and dirty state on restart;
- retain an outbox after destination failure and checkpoint clean state after successful absolute-total delivery;
- fail closed on checkpoint corruption, unknown schema fields/version, oversized state, duplicates, invalid totals/last-counter relationship, or capacity exhaustion;
- bound tracked replay state and dirty users separately.

## Verification

- [x] Unit tests for restart rehydration, absolute totals, failed destination delivery, persistence failure rollback/retry, invalid checkpoint refusal, and tracked-user capacity.
- [ ] Final-head CI: Go race/vet/gofmt, TypeScript contracts, PostgreSQL enrollment and pinned Sing-box smoke.

## Limits

This is a durable local checkpoint/outbox contract. It does not wire native runtime counters, prove that a runtime drain is acked only after `AcceptDurable`, provide a remote transactional meter, runtime session revocation, exactly-once delivery, billing-grade accounting or production durability/restore evidence. Destination delivery is at-least-once and requires idempotent absolute-total upserts. Production gates remain BLOCKED.
