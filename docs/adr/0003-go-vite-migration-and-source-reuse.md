# ADR 0003 — Go/Vite migration, unified foundation and source-derived operations

- Date: 2026-11-04
- Status: accepted architecture; implementation, production qualification and precise GPL SPDX variant remain pending

## Context

OmniPanel's current unified PR #2 contains a Next.js/Drizzle prototype, contract schemas, Go manifest verification, a runtime-neutral session registry and a local Sing-box laboratory. The accepted v2 target is Go control-plane and agent with separate trust-zone processes, PostgreSQL canonical state, SQLite-WAL node state and a static React/Vite UI. S-UI, 3X-UI, Hiddify Manager and 1Panel contain useful patterns but cannot replace that trust model.

## Decision

1. Preserve [unified PR #2](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/2) as the single unmerged foundation. Do not create another overlapping foundation PR. Subsequent independent work is reviewed in focused increments after this prerequisite is approved, or explicitly stacked on it when necessary.
2. Use a measured strangler cutover, not two simultaneously writable control planes. Move authorization and persistence to Go APIs before removing Next.js actions, then retire the server/Drizzle only after operator workflow parity passes.
3. Implement separately evidenced drivers and a durable agent before adopting operational conveniences. No protocol is guaranteed solely because an upstream panel supports it.
4. Selectively adopt the source-project features mapped in `docs/plans/2026-11-04-omnipanel-v2-rollout.md`, without wholesale vendoring, application-marketplace expansion or generic privileged shell access.
5. OmniPanel's intended code license is GPL version 3. Preserve third-party copyright/attribution and verify notices. The pinned Hiddify Panel submodule specifies CC BY-NC-SA 4.0 and must not be copied without separate rights; its architecture may be independently implemented.

## Consequences

- Historical `db/migrations/0001_initial.sql` and `0002_m2.sql` remain immutable; all Go migration/backfill work uses forward-only files and real PostgreSQL tests.
- Production gates stay blocked until signed artifacts, native validator/client conformance, mTLS/PKI, crash recovery, enforced accounting, independent paths and PITR+keys restore are demonstrated.
- The precise GPL-3.0-only vs GPL-3.0-or-later notice needs a packaging decision before a root `LICENSE`/SPDX header change.
- Detailed first executable tasks live in `docs/plans/2026-11-04-runtime-evidence-and-driver-contract.md`.
