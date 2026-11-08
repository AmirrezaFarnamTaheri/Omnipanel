# Protected SOCKS health matrix (host-local regression hardening)

This stacked change extends PR #21's verified systemd MainPID, Linux procfs and socket-owner witness. It closes two host-health false-positive cases:

1. A proxy can reject only the metadata address while allowing another protected destination; checking just one canary accepts the unsafe proxy.
2. A server can return a four-byte SOCKS5 error header, or a generic network-unreachable code, without a valid complete reply. Neither is evidence of a local routing policy denying a destination.

The fixed root-provisioned health address is checked sequentially using fresh bounded SOCKS5 no-auth connections. Each connection must negotiate version 5 and return a **complete reply with REP=0x02** (connection not allowed by ruleset) for its destination. IPv4, IPv6 and named-target response address formats are parsed to their full length; a truncated frame, wrong REP, timeout or unavailable listener fails closed.

The fixed canary matrix includes the existing 169.254.169.254 metadata address, IPv4 loopback, RFC1918 10/8, 172.16/12 and 192.168/16, CGNAT, unspecified IPv4, IPv6 loopback, ULA, IPv6 link-local, IPv4-mapped metadata and the `localhost` hostname. The canary bytes are not supplied by the unprivileged IPC caller.

## Verification scope

- Regression test: an explicit metadata denial with unconditional permit for all other destinations must fail.
- Regression tests: generic SOCKS5 errors and truncated IPv4/IPv6/domain responses must fail.
- Positive test: a correctly implemented bounded SOCKS5 peer returning policy denial for the complete matrix is accepted as **local** evidence.
- Existing root/systemd signed-Sing-box/SIGKILL smoke should continue to pass with the stricter health witness; exact-head CI results must be checked before review or merge.

**Do not treat this as production qualification.** It is a handful of probes through a trusted local process, not exhaustive CIDR/routing policy proof. A malicious proxy can manufacture SOCKS5 refusals, DNS policy may differ for unsampled names, and no independent authenticated external client binds a live generation to its observed service. The policy-safe full-config compiler, native candidate activation, durable applied ACK, public VPS M0, M1/M2 and disaster-recovery gates remain blocked. See issue #14.

Dependency order: #13 -> #16 -> #17 -> #18 -> #19 -> #20 -> #21 -> this change; #15 independently reviewable.
