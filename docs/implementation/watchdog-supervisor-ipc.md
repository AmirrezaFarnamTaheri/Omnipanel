# Independent watchdog and root-supervisor IPC

**Status:** client-side watchdog scheduling and IPC protocol implemented and unit-tested.
**Not implemented:** a privileged root supervisor server, native process replacement,
policy-qualified config activation, real service-health witness, or applied-state ACK.

This change is stacked on [PR #17](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/17)
and inherits its protected, singleton SQLite `activation_guard`.

## Trust model

- `omnipanel-watchdog` is **not root**. It runs in a separate service/process
  from the node polling agent but opens the same owner-private SQLite journal
  with the exact locally configured node ID and authorized epoch.
- The watchdog verifies a locally installed Unix socket path and expects a
  root-owned socket in a root-owned, non-group-writable directory. Each
  connection verifies `SO_PEERCRED` UID 0 independently. It accepts no
  operator-controlled server UID override, shell command, remote address,
  absolute host path or runtime configuration bytes.
- The watchdog speaks only **protocol version 1**, with fixed
  `restore-known-good` and `observe-known-good` operations and exact
  canonical `sha256:<64 lowercase hex>` last-known-good generation references.
  The supervisor response must echo version, operation and reference.
- Each operation uses a fresh Unix stream, a maximum 3-second deadline, a
  maximum 4096-byte response and fail-closed JSON decoding. A supervisor that
  hangs, returns invalid JSON, provides an unmatched generation reference,
  or reports unhealthy leaves the persisted guard pending.

## Wire contract (for a separately reviewed server)

Each connection carries exactly one JSON request and one JSON response,
followed by server close.

**Restore known good:**

```json
{"version":1,"operation":"restore-known-good","reference":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
```

A successful response echoes the request and sets `"ok":true`. This by
itself **does not** clear the guard. The watchdog then opens another local
connection to issue:

```json
{"version":1,"operation":"observe-known-good","reference":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
```

Only the separately trusted supervisor may respond with matching
`"version":1`, `"operation"`, `"reference"`, `"ok":true`, and
`"healthy":true` **after actually observing the restored generation**.
The agent journal's `RecoverActivation` transaction clears the pending
guard only after those steps. No applied cursor is advanced.

The privileged server must independently enforce caller UID/GID, an allowlist
of locally pinned known-good configurations, safe file ownership, fixed
systemd unit targets, protected routing/firewall policy, and a real health
witness. **This repository does not yet implement that server or its native
host operations.** Merely satisfying this JSON shape is not acceptance evidence.

## Startup and fail-closed behavior

```sh
omnipanel-watchdog \
  -node-id 62c478bb-47c3-4dc6-a363-a2fbde813810 \
  -epoch ea2429da-7540-4e40-ae70-38fd3f19794b \
  -journal /var/lib/omnipanel-node/private/node.sqlite \
  -supervisor-socket /run/omnipanel/root-supervisor.sock \
  -interval 250ms
```

The example IDs are placeholders, **not valid enrollment credentials**.
The process refuses to start as root, accepts no positional arguments,
requires bounded checks (10 ms to 1 s), refuses an absent/untrusted root
socket **before opening the journal**, and logs only status and a failure
boolean rather than raw runtime diagnostics or configuration.

Recovery rules:

1. **No guard:** `idle` (not a healthy/applied attestation).
2. **Guard not yet expired:** `armed`; never interrupt a still-valid
   commit-confirm interval.
3. **Expired guard:** request exact LKG restoration and fresh health check;
   retry on IPC, journal or health failure without deleting the guard.
4. **Restoration and observation succeed:** the journal clears only the
   matching guard. The applied sequence, membership, digest and
   last-known-good baseline are unchanged.

The standalone service must be kept alive by a separately reviewed
systemd unit with `Restart=always` and a bounded restart delay. That unit
must run under the same dedicated unprivileged account that owns the
private journal, with no capabilities, `NoNewPrivileges=yes`, and access
only to the protected journal and root supervisor socket. A root-owned
socket directory could use mode `0750`, with socket `0660` granted only
to the dedicated watchdog group. **No ready-to-deploy unit is installed
here** because the root supervisor server and host acceptance gates do not
yet exist.

## Verification

- [TDD red: watchdog/IPC implementations absent](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42406836842)
- [TDD red: independent executable startup absent](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42407318516)
- [First Go race-test green](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/42407494828)

The workflow also checks formatting of the new files, builds the watchdog
executable and reruns the Go race suite. Inspect the exact current PR head
before making merge or release claims.

## Required operational proof before activation

1. Review and implement a **root-owned, least-privilege supervisor server**
   that applies only qualified/pinned generations; enforce authorization
   on both the IPC client and server sides.
2. Prove the known-good baseline was provisioned and health-verified
   independently, not self-declared by a signed manifest or operator flag.
3. Test real Linux/systemd restart, kill-9, rollback deadline, firewall and
   routing behavior with actual pinned Sing-box processes and witnessed
   restored health.
4. Add true commit confirmation, atomic applied cursor advancement and
   durable signed node ACK **only after** a real successful activation.
5. Perform external public VPS/reference-client M0 and later M1/M2
   acceptance. Contract checks or fake socket responses cannot replace
   those results.
