# Personal runtime integration checkpoint — 2026-11-08

This **unmerged integration candidate** combines exact source heads (without changing `main`):

- PR #16–#22 stack: `9d176bc02be6e82218313fd2878018adbf05f783` (native staging, crash-safe guard, watchdog, root rollback and Linux process/egress witnesses).
- PR #15 mTLS node poller: `c37872a08f1d467a769fcf2e11b27799d18a0de3`.
- PR #26 protected full-config compiler: `0b9b34676fbea8989978bac5105c7934ff012dc7`.
- PR #25 firewall inventory safety regression: `27d8a27b759264fecf6788038b8732ab6f4bd682`.
- PR #23 personal-use architecture/research: `bcbe3dcab861d651e0f476467998f0edb32d2e8f`.

All other source code files from the donors are reused by immutable blob SHA. The two overlapping GitHub Actions workflows were integrated explicitly: Foundation verifies both Go executables and the node bootstrap; signed native runtime verifies both the compiled full config and actual root-host rollback smoke.

**Excluded intentionally:** PR #13's distinct-person authorization changes require a reviewed personal one-owner consent/step-up policy, and cannot be imported silently. No production login, approval bypass, network exposure or release gate is enabled by this candidate.

**Important:** Exact-head combined CI is mandatory, and local native + root SIGKILL success is **not** public VPS/reference-client M0. Release issue #14 remains blocked until independent external proof.
