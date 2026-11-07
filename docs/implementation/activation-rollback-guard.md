# Durable activation rollback guard (prerequisite, not a runtime supervisor)

This phase extends the private node-scoped SQLite WAL journal with a crash-recoverable singleton **activation guard**. It is deliberately a safety prerequisite for future supervised Sing-box activation, not an implementation of active configuration switching, native health, a commit-confirm watchdog, or remote node acknowledgments.

## Invariants

1. `ReserveActivation` accepts only an exact signed desired-state revision already present as `VERIFIED` in the node's protected journal, with a matching authorized node/epoch, manifest digest, component-candidate digest and monotonic structural/membership counters.
2. A canonical, locally persisted `sha256:<64 lowercase hex>` last-known-good reference must already exist. No new production API is provided to seed a known-good reference; a future supervisor and bootstrap process must establish and verify that baseline independently.
3. A single `activation_guard` record is committed with `synchronous=FULL` in SQLite WAL mode **before** any future process could attempt activation. Its expiration timestamp is bounded to 1–120 seconds. It cannot be overwritten, extended or made to disappear because the agent restarted, the timestamp elapsed, or a new proposal arrived.
4. `UnconfirmedActivation` returns the same metadata after closing and reopening the journal. Any pending guard is a rollback requirement, **not** evidence of successful deployment.
5. `RecoverActivation` is fail-closed: a separately supplied trusted `RecoveryOperator` must restore the exact previously recorded known-good reference and independently observe it healthy before deleting the guard in a transaction. Restore failure, unhealthy result, observer error, cancellation, or concurrent modifications leave recovery required. Errors avoid including runtime config or private credentials.
6. None of these APIs touches the existing `applied_structural`, `applied_membership`, `applied_digest` or `last_good_ref` cursor fields, switches a process, or sends an applied ACK. The state still cannot claim that verified intent is deployed.

## Test evidence

- TDD red run: [Foundation #42404774074](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42404774074) — tests for guard persistence and verified recovery failed on intentionally unimplemented methods, after formatting repair.
- TDD green run: [Foundation #42405058572](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42405058572) — Go race tests including SQLite restart, concurrent reservations, invalid input, and failed/successful recovery cases.

## Follow-up gates before operational activation

- Provide a reviewed, policy-qualifying **full configuration compiler** that enforces deny-protected egress and pins exact build/candidate bytes. Passing `sing-box check` alone proves syntax, not allowed destinations.
- Provision an independently verified known-good baseline and a root/privileged helper isolated from the unprivileged polling service, with a minimal authenticated IPC contract and capability-based host authorization.
- Run an **independent watchdog** which can restore last known good after process death, timeout, failed health, service crash, or host restart even if the polling agent is unavailable. This journal only persists the requirement; a stored deadline is not an active timer.
- Make health an actual observed native service/network test; mock supervisor interfaces in unit tests are not release evidence. Implement atomic applied cursor advancement and control-plane ACK only after successful health and one-time commit confirmation.
- Execute real root Linux host-fault injection, firewall/route fail-closed validation, and external client/VPS M0 acceptance with reproducible logs. None is certified by this journal change.

**Integration:** This PR is stacked on the native preflight/staging [PR #16](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/16); [PR #13](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/13) should be integrated first because it supplies the reviewed security baseline. Outstanding external gates are tracked in [issue #14](https://github.com/AmirrezaFarnamTaheri/Omnipanel/issues/14).
