# Root-side Sing-box rollback supervisor (restricted service boundary)

**State:** Root-owned Unix RPC server, pinned local rollback backend, and
root-only CLI implemented with unprivileged fixture tests. **Not production
qualified, not deployed, and not a general config-activation API.**

This change is stacked on [PR #18](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/18)
and implements the root-side peer of the independent, non-root watchdog.

## Authorization invariants

1. The process `omnipanel-supervisor` must run with **effective UID 0**.
   It loads one protected JSON provisioning file, requiring an absolute
   canonical path, a non-symlink regular file owned by root with mode `0600`,
   and a root-owned **0700** parent directory. It rejects unknown keys,
   duplicate keys (including case aliases), trailing data, oversized JSON,
   unqualified generation references, and remote health endpoints.
2. The Unix socket is created only inside a root-owned directory with no
   group/other write permission. A group-traversable parent must belong to
   the dedicated watchdog group. The socket is root-owned with mode `0660`
   and its group is set to the pinned watchdog GID. The server refuses to
   unlink or replace any **preexisting** socket path.
3. **SO_PEERCRED** must match the pinned watchdog UID **and** GID on each
   connection. Requests are bounded, single-line JSON, with exactly the
   `version`, `operation` and `reference` fields. Only protocol v1
   `restore-known-good` and `observe-known-good` exist. The reference
   must be in an immutable, root-provisioned SHA-256 allowlist.
4. Errors produce no shell output, host file paths, or secret configuration
   bytes to the caller. A valid request never authorizes a new desired
   configuration, dynamic systemd service name, command-line argument,
   arbitrary executable, or mutable policy exception.

## Pinned rollback-generation layout

Provision the following directories with root ownership and mode `0700`:

- `/var/lib/omnipanel/supervisor/generations/` — immutable/approved
  `<lowercase-sha256-hex>.json` complete Sing-box configs, each `0600`.
- `/etc/omnipanel/sing-box/` — writable only to root, containing the
  atomically replaced `active.json` (mode `0600`).
- `/etc/omnipanel/supervisor-private/` — `supervisor.json` (mode `0600`).
- `/run/omnipanel-supervisor/` — root-owned, mode `0750`, group set to
  the watchdog's group; socket `restore.sock` is created with mode `0660`.

Root provisioning must independently review the exact native runtime
version, digest, full config, protected egress policy, and baseline health
**before** adding its digest to the allowlist. The watchdog cannot add an
approved generation through an IPC request.

## Local provisioning example

The values below are illustrative and **not valid release attestation or
enrollment credentials**. Replace the IDs, binary SHA-256s, allowlisted
generation, and ports only after root-side provisioning review.

```json
{
  "SocketPath": "/run/omnipanel-supervisor/restore.sock",
  "WatchdogUID": 1001,
  "WatchdogGID": 1001,
  "AllowedGenerations": [
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  ],
  "Native": {
    "GenerationDirectory": "/var/lib/omnipanel/supervisor/generations",
    "ActiveConfigPath": "/etc/omnipanel/sing-box/active.json",
    "SingBoxBinary": "/usr/local/bin/sing-box",
    "SingBoxBinaryDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "SystemctlBinary": "/usr/bin/systemctl",
    "SystemctlBinaryDigest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "HealthAddress": "127.0.0.1:9091"
  }
}
```

The hard-coded systemd target is `omnipanel-singbox.service`. Its
`ExecStart` must load precisely the root-protected active configuration.
The runtime unit must also have **legitimate access** to `active.json`;
a non-root Sing-box process cannot directly read a root-owned `0600`
file. Provision a separately reviewed and tested configuration delivery
mechanism before attempting host deployment. This PR intentionally
**does not ship a deployable root systemd unit** or relax file secrecy.

Launch only in a reviewed root environment:

```sh
omnipanel-supervisor --config /etc/omnipanel/supervisor-private/supervisor.json
```

## What restore and observation actually do

For an exact, allowed `sha256:<digest>` request, the backend:

1. Opens the matching root-owned, non-symlink source file with `O_NOFOLLOW`
   and verifies its complete bytes match the allowed SHA-256.
2. Rehashes and checks the pinned native Sing-box executable and pinned
   systemctl executable (root-owned, non-writable by group/others).
3. Writes a private temporary config, `fsync`s it, and executes the native
   binary with fixed arguments `check -c <temporary-config>` using no shell
   and a bounded timeout. All native stdout/stderr are discarded.
4. After a successful syntax check, atomically renames the config to
   `active.json`, syncs the directory, then runs **only**
   `systemctl restart omnipanel-singbox.service`.
5. Replies `ok:true` to restore only if the fixed service restart command
   succeeds. It does **not** assert `healthy:true` from that result.
6. On a separate observe request, rechecks the approved generation file,
   verifies active config SHA-256, queries `systemctl is-active --quiet
   omnipanel-singbox.service`, and performs a bounded SOCKS5 greeting plus an explicit rejected CONNECT
   to the protected link-local metadata destination (169.254.169.254:80) on
   the root-configured loopback listener. A generic listening port cannot
   satisfy this check. An absent service, changed generation,
   tampered binary, failed unit state, or unavailable listener refuses
   positive host readiness.

The independent node journal remains authoritative: failed restore/health
attempts leave its `activation_guard` pending. The root helper has **no
ability to advance the applied cursor, issue an ACK, or create LKG trust**.

## Evidence limitations and release blockers

The automated tests use local fake Sing-box and systemctl executables
with a real protected filesystem and synthetic SOCKS5 responder; they exercise the
actual root helper code via an unprivileged owner-injection test seam. Those
fixtures are **not** proof that an installed systemd unit, actual Reality
client, route, firewall, or egress policy is healthy.

In particular, `systemctl is-active` plus a local SOCKS5 ruleset-denial
probe is **limited host/process/data-path readiness**, not generation-bound
network attestation. An unrelated SOCKS5-compatible responder might still
satisfy the probe if root provisioning were misconfigured. The next
acceptance gate must replace/augment it with
an independently authenticated, generation-bound end-to-end health witness
and prove restored client traffic and protected routes under root Linux
fault injection. A passing unit test or a successful local SOCKS5 handshake
cannot close M0.

The following remain **BLOCKED**:

- Real root-owned systemd unit installation, permissions, restart and
  kill/reboot/retry fault injection with signed native Sing-box builds.
- Deny-protected egress policy compiler, fail-closed firewall/routing
  qualification, proven reference-client health, and external VPS M0.
- Durable **applied** cursor advancement, signed node acknowledgments,
  commit-confirm success and multi-node orchestration.
- M1/M2 Hysteria2, full quota enforcement, DR/PITR, migration and release
  protection.

Track the remaining gates in
[issue #14](https://github.com/AmirrezaFarnamTaheri/Omnipanel/issues/14).
Merge dependencies: **#13 → #16 → #17 → #18 → this PR**; #15's node
poller is independently reviewed. Do not deploy this change to production
or infer M0 acceptance from its CI.
