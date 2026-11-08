# Kernel-bound Sing-box listener health witness

**Status:** Implemented as a local Linux host safety check, verified by real
`/proc` unit tests and the signed root/systemd/SIGKILL lab. **Not an
independent cryptographic generation or external reference-client attestation.**

This milestone extends [PR #20](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/20).
The prior check required an exact approved configuration hash, an active fixed
systemd unit and a SOCKS5 denial of a protected metadata destination. An
unrelated process speaking the same SOCKS5 responses could still be mistaken
for the intended native service. The root supervisor now additionally verifies
the kernel ownership of the listener.

## Evidence required before `ObserveKnownGood` returns healthy

1. Re-read and verify the root-approved immutable generation bytes and the
   exact SHA-256 of the currently protected `active.json`.
2. Recheck the configured systemctl executable digest and verify
   `systemctl is-active --quiet omnipanel-singbox.service`.
3. Query **only** the fixed service with
   `systemctl show --property=MainPID --value omnipanel-singbox.service`.
   A missing, zero, unparseable, nonnumeric or timed-out MainPID is rejected.
4. Read the service's Linux `/proc/PID/stat` start time, check that its network
   namespace matches the supervisor's network namespace, and hash the actual
   running `/proc/PID/exe` inode. Its SHA-256 must equal the root-provisioned
   pinned Sing-box binary digest.
5. In the service's `/proc/PID/net/tcp` table find **exactly one** IPv4
   `LISTEN` inode for the configured `127.0.0.1:port` health endpoint. Reject
   missing or ambiguous duplicate listeners. Verify that the exact inode is
   owned by a socket descriptor in `/proc/PID/fd`; a different PID using the
   same executable bytes does **not** satisfy health.
6. Re-read the process start time to reject a PID that was replaced during
   observation. Finally, request a bounded SOCKS5 no-auth handshake and
   explicit ruleset denial of `CONNECT 169.254.169.254:80`. Connection or
   transport failures cannot be treated as proof of protected egress.

All paths and command arguments are derived from locally root-provisioned
configuration or fixed Linux procfs paths, not from watchdog IPC. The root
server's existing caller UID/GID, allowlisted SHA-256 generation, Unix peer
credential and bounded request checks remain mandatory.

## Test evidence

- **TDD RED:** [Foundation #42453428378](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42453428378) — legitimate owner and identical-executable child-process tests failed against an intentionally fail-closed process verifier; the root health path failed to invoke its witness.
- **GREEN on implementation commit:** [Foundation #42453592358](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42453592358) — contracts, native command linking, formatting, full Go race tests and vet.
- **GREEN on implementation commit:** [Signed runtime #42453592378](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42453592378) — Sigstore verified pinned Sing-box, real root/systemd native rollback after SIGKILL, kernel-verified service listener ownership, and Reality/Vision/accounting smoke.

The unprivileged Linux tests use a real TCP listener and spawn a separate
process running **the exact same executable** to verify that executable hash
alone is not sufficient without a matching socket inode and PID. Other unit
tests keep their synthetic systemd boundary; the signed host lab exercises
the real systemd process-to-listener chain.

## Limitations and remaining release gates

This is an OS-kernel-backed **host-local** identity witness, not a proof that
the running process loaded the exact approved in-memory configuration, that
every private network destination is denied, or that a user reference client
can establish Reality/Vision. It trusts root, systemd, the host kernel and
procfs. Process state can change after observation, so follow-up production
controls still need continuous independent monitoring and an authenticated,
nonce-bound external client/data-path challenge. The trust and service
config-access design must also be evaluated under production permissions.

No applied cursor, known-good bootstrap, native candidate activation,
commit-confirm ACK, external VPS, M0/M1/M2 acceptance, DR or full routing
qualification is granted by this change.

Outstanding mandatory gates remain tracked by
[issue #14](https://github.com/AmirrezaFarnamTaheri/Omnipanel/issues/14).
Review dependencies: #13 → #16 → #17 → #18 → #19 → #20 → this PR;
#15 independently provides the unprivileged mTLS poller. Do not merge before
its stacked base or infer production readiness from local smoke evidence.
