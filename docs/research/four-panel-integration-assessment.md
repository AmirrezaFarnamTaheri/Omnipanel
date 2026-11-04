# Four-panel reference assessment for OmniPanel v2

**Reviewed:** 4 November 2026  
**Scope:** Source and README inspection of the four supplied GitHub forks, not an executable/runtime security audit.  
**Target:** OmniPanel v2 unified [PR #2](https://github.com/AmirrezaFarnamTaheri/Omnipanel/pull/2).  
**Decision:** Adopt *independently implemented, bounded contracts and test ideas*, not entire panels, installers, arbitrary plugin execution or their operational guarantees.

## Reviewed source revisions and licensing boundary

| Supplied fork | Reviewed ref / commit | Root license observed | Scope caution |
| --- | --- | --- | --- |
| [S-UI](https://github.com/AmirrezaFarnamTaheri/S-UI) | `main` / [`19302d1`](https://github.com/AmirrezaFarnamTaheri/S-UI/tree/19302d16f6c1fddf68595cf1ddd4b2e03077c2f6) | GPL-3.0 | README expressly discourages production use |
| [3X-UI](https://github.com/AmirrezaFarnamTaheri/3X-UI) | `main` / [`83ea59f`](https://github.com/AmirrezaFarnamTaheri/3X-UI/tree/83ea59fb693fee1815d867dff4d33028ddaf12a9) | GPL-3.0 | README expressly discourages production use |
| [Hiddify-Manager](https://github.com/AmirrezaFarnamTaheri/Hiddify-Manager) | `dev` / [`9974dc3`](https://github.com/AmirrezaFarnamTaheri/Hiddify-Manager/tree/9974dc390fb96528346a4c3cd4a4063b5bae6d97) | GPL-3.0 **for the manager repository** | Panel code is a distinct [Hiddify-Panel submodule](https://github.com/AmirrezaFarnamTaheri/Hiddify-Manager/blob/9974dc390fb96528346a4c3cd4a4063b5bae6d97/.gitmodules); do not infer its licensing from the manager LICENSE |
| [1Panel](https://github.com/AmirrezaFarnamTaheri/1Panel) | `dev-v2` / [`30381a3`](https://github.com/AmirrezaFarnamTaheri/1Panel/tree/30381a3c68d40b04a2f4117286d7d19cc5b18557) | GPL-3.0 **for the OSS repository** | Its [README](https://github.com/AmirrezaFarnamTaheri/1Panel/blob/30381a3c68d40b04a2f4117286d7d19cc5b18557/README.md) places multi-node management in Pro/Ent, not OSS |

These observations do not constitute a file-level audit of every dependency, asset, git submodule or commercial feature. The Hiddify-Manager development documentation explicitly describes `services/panel/src` as the *separate* Hiddify-Panel source tree. Treat that submodule, any commercial panel routes, and all separately licensed assets as **excluded pending license review**. Do not equate a GPL license in the orchestration repository with authorization to use all nested panel code.

No files from these projects are copied, vendored or linked into OmniPanel in this assessment. OmniPanel's original source retains its own GPL-3.0-only licensing, subject to a separate dependency and notice review if reuse is proposed.

## Selective design decisions

| Reference / evidence | What is worth learning | OmniPanel decision and boundary |
| --- | --- | --- |
| [S-UI user session registry](https://github.com/AmirrezaFarnamTaheri/S-UI/tree/19302d16f6c1fddf68595cf1ddd4b2e03077c2f6/core/usersession) and [stats service](https://github.com/AmirrezaFarnamTaheri/S-UI/blob/19302d16f6c1fddf68595cf1ddd4b2e03077c2f6/service/stats.go) | Session-owned authentication, closure versus blocking new routed flows, per-user runtime counters | Existing `internal/agent/sessions` handles a *contract* for closures/unclosable sessions. Require native runtime experiments for actual effects. Counters need durable process generations, baselines, gaps, and deduplicated delivery; a panel traffic graph is not a billable meter. |
| [3X-UI protocol predicates](https://github.com/AmirrezaFarnamTaheri/3X-UI/tree/83ea59fb693fee1815d867dff4d33028ddaf12a9/frontend/src/lib/xray) and [host ordering](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/83ea59fb693fee1815d867dff4d33028ddaf12a9/internal/sub/host_order.go) | Explicit protocol/transport compatibility, deterministic subscription variants and per-format exclusions | Existing `src/lib/protocol-compatibility.ts` rejects unqualified combinations. Keep deterministic order and exact client-release admission; do not treat quota UI, IP/HWID limits, client-side balancers or a protocol list as verified enforcement/HA. |
| [Hiddify-Manager development layout](https://github.com/AmirrezaFarnamTaheri/Hiddify-Manager/blob/9974dc390fb96528346a4c3cd4a4063b5bae6d97/DEVELOPMENT.md) and [panel run wrapper](https://github.com/AmirrezaFarnamTaheri/Hiddify-Manager/blob/9974dc390fb96528346a4c3cd4a4063b5bae6d97/services/panel/run.sh) | Service-specific runtime wrappers, generated configuration kept separate from installed sources, distinct admin/user frontends, secrets outside git | Reference for the **operational inventory** only. OmniPanel must use typed, allowlisted Go driver/helper operations, immutable generations, protected management access and an independently supervised runtime. Never execute or import Hiddify's root-install scripts, shell templates, runtime services, database or panel submodule. |
| [1Panel agent server](https://github.com/AmirrezaFarnamTaheri/1Panel/blob/30381a3c68d40b04a2f4117286d7d19cc5b18557/agent/server/server.go) and [core server](https://github.com/AmirrezaFarnamTaheri/1Panel/blob/30381a3c68d40b04a2f4117286d7d19cc5b18557/core/server/server.go) | Distinct Go core/agent modules; agent's local socket has strict `0700` parent and `0600` socket permissions, including ownership checks | Use as a **security review checklist** for OmniPanel's node-local state/socket boundary. Do not assume 1Panel's core/agent network design meets OmniPanel's outbound-only, node-scoped signed-manifest and end-to-end mTLS requirements. 1Panel OSS is not a free multi-node control plane. |
| [1Panel backup records](https://github.com/AmirrezaFarnamTaheri/1Panel/blob/30381a3c68d40b04a2f4117286d7d19cc5b18557/agent/app/service/backup_record.go) and [PostgreSQL backup path](https://github.com/AmirrezaFarnamTaheri/1Panel/blob/30381a3c68d40b04a2f4117286d7d19cc5b18557/agent/app/service/backup_postgresql.go) | Explicit operator-visible backup records, stateful tasks, failure and restore outcomes | Inform a typed backup/restore **task model**, but do not substitute SQL dumps or local backup files for independently verified PostgreSQL PITR, envelope-key restoration, signing-epoch recovery and disaster-recovery drills. |

## Phased adoption, with measurable acceptance

### Immediate: agent foundation / local evidence

1. Complete a **verification-only outbound polling** path: the agent initiates a scoped fetch over a separately authenticated transport, runs `manifest.Verifier.Verify`, records the result in the node-local SQLite WAL journal, and **does not commit any applied cursor**. Repeat/replay/conflict/restart tests must pass. Until authenticated transport exists, a mock gateway may prove orchestration only.
2. Expand journal scope-hardening tests using the 1Panel socket review as inspiration: owner-only real parent directory and file, rejection of symlinks/unsafe ownership, WAL mode and `synchronous=FULL`, no unsafe path from manifest. These tests are not proof of hardened helper IPC.
3. Reproduce hot user revocation, new-stream behavior and accounting from the actual source-pinned sing-box build and client. The existing green local Reality/Vision test covers **whole-core restart credential rotation**, not hot revocation or a public client.
4. Keep protocol/client compatibility fail-closed; no dynamic capability based on a source panel's README.

### Later: actual node application and recovery

5. Add a typed privileged helper with a *fixed, narrowly audited* operation set. The agent may only stage configs under bounded generation directories, use native validation and preflight, apply through an independent runtime service, and commit an observed result to SQLite.
6. Network-affecting plans require an **independent** commit-confirm watchdog that can roll back if the agent dies. Inject failures and verify the protected management route stays usable; no actor receives arbitrary host command or path authority.
7. Use Hiddify's split service inventory and 1Panel's task lifecycle as test design inputs for explicit component state and diagnostic visibility. Never copy or shell out to their installers.

### Deferred capabilities

- Hiddify-specific proxy templates, CDN, multi-domain and external infrastructure automation: candidates only after native config, ownership, privacy, abuse, security and network-failure reviews.
- 3X-UI bots, client-side balancing, bulk renewal, XHTTP and broad transports: separately gated M2/M3 product work.
- 1Panel's AI, container, website, terminal, marketplace, Pro/Ent multi-node and general-purpose server administration: **out of scope** for OmniPanel's least-privileged proxy node agent.
- Legacy importers: dry-run-first, explicit source/version, canonical principal mapping, collision and unsupported-feature reports, credentials re-encrypted under OmniPanel keys, operator approval, resumable idempotency journal. Do not treat imported counters as authoritative billing.

## Non-negotiable guardrails

- Original runtime binaries are accepted only with exact pinned sources/build provenance and lab qualification; passing a UI or syntax checker does not prove network health.
- An existing authentication session may outlive credential deletion. Test new authentication, new streams on existing sessions, and established streams separately.
- No direct code copy, database restore, submodule vendoring, root installer execution or general-purpose arbitrary command helper.
- Isolate control-plane identity, agent identity, subscription delivery and runtime data plane. No frontend may authorize host changes.
- Production gates (`gate-lab`, `gate-agent`, `gate-control`, `gate-security`, `gate-dr`) remain **BLOCKED** until their own evidence succeeds.

## Evidence limits

This is a **static source review**. It does not establish that any reference project, code path or edition is production-safe, that Pro/Ent features are available to OmniPanel, or that any existing local smoke result qualifies external VPSs, third-party clients or hard quotas. A source-specific licensing inventory and an independent integration test are prerequisites before changing that claim.
