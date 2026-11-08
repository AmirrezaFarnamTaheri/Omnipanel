# Signed root-host Sing-box rollback acceptance lab

**Scope:** disposable GitHub-hosted Ubuntu runner with real root-owned systemd
service, verified native Sing-box executable, and the production root supervisor
and unprivileged watchdog IPC client. This is a **local root-host test**, not a
public VPS/reference-client acceptance result or production deployment guide.

## What the lab proves

Only after Sigstore confirms the signed Sing-box build and builder identity, the
runtime workflow builds the same-commit root supervisor binary and executes
\`lab/runtime/run-root-supervisor-host-smoke.sh\` with an explicit CI-only
\`OMNI_ALLOW_EPHEMERAL_ROOT_SMOKE=1\` switch. It refuses a pre-existing
\`omnipanel-singbox.service\` and only creates a disposable unit under
\`/run/systemd/system\`. A trap stops that unit, removes it, reloads systemd and
removes the temporary root-owned files.

The root provisioning fixture includes a 0600 generation file pinned to its
SHA-256; exact native Sing-box and systemctl executable SHA-256 digests; and a
root-owned, mode 0600 provisioning file. The root supervisor serves one fixed
Unix socket under a protected root-owned parent, restricted to the dedicated
unprivileged runner UID/GID. A non-root process uses the real Go
\`supervisoripc.Client\` to perform the sequence:

1. A different initial active generation is rejected as a known-good witness.
2. Root supervisor validates exact allowed generation bytes with the pinned
   native \`sing-box check -c\` and atomically restores \`active.json\`.
3. Fixed \`omnipanel-singbox.service\` starts under systemd with the actual
   signed binary. A fresh health check verifies active config digest, unit
   state and a loopback SOCKS5 handshake that explicitly **rejects** a
   CONNECT to protected 169.254.169.254:80.
4. Real \`systemctl kill --kill-who=main --signal=SIGKILL\` terminates the
   service. The root supervisor must report unhealthy.
5. A second restore must recover health after SIGKILL. A generation absent
   from the root allowlist must be rejected.

The lab uploads **sanitized evidence only** and never prints private config,
binary source/signing secrets, or arbitrary root command output.

## Limitations and known boundaries

A SOCKS5 denial of one protected destination is not evidence that every
RFC1918/link-local/metadata address is blocked. A matching active file SHA-256,
\`systemctl is-active\`, and one live application-layer probe do not
cryptographically bind every listener or observed packet to a specific
generation. This lab does not include an independent external reference
client, production certificate validation, a multi-host public VPS, actual
network namespace failover, or a full protected-egress policy audit.

The lab exercises root-side restoration and health; the unprivileged watchdog
retry loop and SQLite durable activation lease are tested in their own CI
packages. It does **not** certify end-to-end automatic commit-confirm rollback
in a deployed production node, nor does it advance the applied cursor or issue
a signed applied acknowledgment.

The real Linux/systemd smoke requires a disposable hosted runner with
passwordless sudo and a working systemd instance. It is intentionally disabled
outside that explicit CI environment.

**Release state remains BLOCKED:** a generation-authenticated network health
witness, independent reference-client Reality/Vision success, comprehensive
protected-route negative tests, policy-safe compiler, durable applied cursor
and ACK, root unit packaging/permissions, external VPS M0 and subsequent M1/M2
qualification remain tracked in
[issue #14](https://github.com/AmirrezaFarnamTaheri/Omnipanel/issues/14).

**Dependencies:** PR #13 → #16 → #17 → #18 → #19 → this PR; PR #15 remains
independent. None of these stacked PRs should be treated as merged into main
until individually reviewed and successfully integrated.
