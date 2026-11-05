# S-UI and 3X-UI source review: selective reuse plan

**Reviewed:** 3 November 2026  
**Repositories:** [S-UI](https://github.com/AmirrezaFarnamTaheri/S-UI) and [3X-UI](https://github.com/AmirrezaFarnamTaheri/3X-UI)  
**Target:** OmniPanel v2 unified architecture

For Hiddify-Manager and 1Panel, including license/submodule and OSS-edition boundaries, see the [four-panel integration assessment](four-panel-integration-assessment.md).

This review inspected the supplied forks' default-branch documentation and selected implementation modules. It is a source review, not a production qualification or a claim that every feature in either panel is safe to deploy.

## Important source constraints

Both supplied repositories identify GPL-3.0 licensing. S-UI's README says it is for personal learning/communication and explicitly says not to use it in production. 3X-UI's README likewise describes the project as intended for personal use and says not to use it in a production environment. OmniPanel's original code is licensed as GPL-3.0-only by its root LICENSE; existing third-party ownership and notices are unaffected.

Accordingly, this increment does **not** copy source files, vendor either panel, or add their dependencies. It independently implements selected behaviors and links to the source references. Any future direct code reuse requires file-level license, authorship and dependency review.

## What each project contributes

### S-UI: Sing-box and live-session behavior

| Source | Useful behavior | OmniPanel decision |
| --- | --- | --- |
| [README](https://github.com/AmirrezaFarnamTaheri/S-UI/blob/main/README.md) | Sing-box-native panel, multiple protocols/inbounds, traffic and system status, link/JSON/Clash subscriptions and REST API | Use as a Sing-box integration reference, not as a production-readiness claim |
| [core/usersession/registry.go](https://github.com/AmirrezaFarnamTaheri/S-UI/blob/main/core/usersession/registry.go) | Associates an authenticated principal with the runtime session; closes sessions where a protocol exposes a closer; mutes sessions that cannot be closed so they cannot open new routed streams | Adopt the session-lifecycle contract as a runtime-neutral agent primitive |
| [service/stats.go](https://github.com/AmirrezaFarnamTaheri/S-UI/blob/main/service/stats.go) | Aggregates per-user/inbound/outbound counters, preserves failed database batches in a pending buffer, buckets history and downsamples graph output | Adopt aggregation and explicit retry semantics; do **not** treat its in-memory pending buffer as durable agent accounting |
| [database/backup.go](https://github.com/AmirrezaFarnamTaheri/S-UI/blob/main/database/backup.go) | Checkpoints SQLite WAL, validates the candidate database, retains a fallback and restores it after migration failure | Reuse the safety principles only. OmniPanel's PostgreSQL PITR plus separately restored keys and epoch recovery is a different process; do not replace the live PostgreSQL database by renaming SQLite files |

The session registry is the strongest immediately reusable idea. Protocols that authenticate once per QUIC/AnyTLS session can keep opening streams after the user is removed from the current authentication map. Closing only the routed connections is insufficient. A runtime adapter must either close the owning session or block subsequent routed flows and report that an existing session may remain.

### 3X-UI: Xray compatibility, subscriptions and operations

| Source | Useful behavior | OmniPanel decision |
| --- | --- | --- |
| [README](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/README.md) | Broad protocol/transport support, per-client quota and expiry, multi-node administration, routing/balancers, subscription formats, REST API, bots and operational tooling | Use as a capability inventory; enable only independently verified drivers and services |
| [protocol-capabilities.ts](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/frontend/src/lib/xray/protocol-capabilities.ts) | Explicit protocol/transport predicates for TLS, Reality, VLESS flow, Vision seed and special protocol behavior | Adopt a narrow, typed compatibility preflight before configuration or subscription emission |
| [inbound-link.ts](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/frontend/src/lib/xray/inbound-link.ts) | Extensive URI generation and parsing coverage for Xray client formats | Use as a future conformance-test inventory; do not copy its large legacy parser into the canonical IR |
| [host_order.go](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/internal/sub/host_order.go) | Stable ordering across host groups and inbounds, with deterministic tie-breakers | Preserve deterministic ordering in OmniPanel's compiler; add explicit operator order only when the canonical model supports it |
| [subscription docs](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/docs/content/docs/en/config/subscription.mdx) | Separate raw links, Xray JSON and Mihomo profiles; per-format exclusions; explicit errors when no compatible legacy nodes remain | Extend OmniPanel's client registry and compiler tests by exact client release; never silently weaken security fields |
| [subscription balancer API](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/docs/content/docs/en/reference/api/subscription-balancers.mdx) and [settings UI](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/frontend/src/pages/settings/SubscriptionBalancersTab.tsx) | Client-side JSON subscription balancers, selected inbound members, weights and observatory/ping settings | Candidate M2 enhancement. These are emitted client-side configuration documents, not proof of server-side network failover |
| [clients docs](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/docs/content/docs/en/config/clients.mdx) | One client identity can attach to multiple inbounds; lifecycle, quota, expiry, renewal, bulk actions, groups and external links | Keep one logical OmniPanel user with distinct endpoint principals and credentials; consider renewal/groups/bulk operations as product decisions |
| [WebSocket API docs](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/docs/content/docs/en/reference/api/websocket.mdx) | Authenticated event stream for real-time status without constant polling | Candidate after event envelopes, authorization scopes, backpressure and reconnect semantics are defined |
| [backup/restore docs](https://github.com/AmirrezaFarnamTaheri/3X-UI/blob/main/docs/content/docs/en/operations/backup-restore.mdx) | Backs up database and certificates, encourages off-host copies and tested restore | Align with OmniPanel's PostgreSQL PITR, key recovery and restore drills; SQLite file copy is not an OmniPanel recovery method |

## Implemented in this increment

### 1. Runtime compatibility preflight

Added `src/lib/protocol-compatibility.ts` and integrated it into subscription IR construction. It rejects unsupported runtime/protocol/transport combinations and malformed Reality identity fields before an endpoint can reach an emitter.

The initial matrix is deliberately narrow:

| Runtime | Protocol | Transport | Result of preflight |
| --- | --- | --- | --- |
| sing-box | VLESS / Reality / Vision | TCP | Structurally supported |
| Xray | VLESS / Reality / Vision | TCP | Structurally supported |
| sing-box | Hysteria2 | UDP | Structurally supported |
| standalone Hysteria2 | Hysteria2 | UDP | Structurally supported |
| Xray | Hysteria2 | Any | Rejected |
| Any other combination | — | — | Rejected |

Reality requires a valid unpadded base64url public key, 1–8-byte lowercase hexadecimal short ID, DNS server name, Vision flow and a valid fingerprint identifier. Omitted optional flow/fingerprint values use the existing supported defaults.

**This is structural preflight, not a claim that any runtime build, client release, native config or network path has passed the lab gate.** Exact-build qualification remains mandatory.

The subscription compiler also rejects a path when the requested client format does not declare support for its canonical protocol ID, and excludes all client formats until exact-release compatibility evidence is marked verified. Runtime names do not create a second protocol identity: VLESS/Reality/Vision remains the same canonical protocol for Sing-box and Xray.

### 2. Runtime-neutral session revocation primitive

Added `internal/agent/sessions`, an independently implemented Go registry that associates an opaque runtime session ID with an endpoint-principal ID and credential generation.

It supports:
- Registration only against the current authorized principal/generation snapshot.
- Atomic membership reconciliation and permanent blocking of removed or stale-generation sessions.
- Runtime session closure outside the registry lock, avoiding re-entrant close-handler deadlocks.
- Blocking further routed flows when no session closer exists or closure fails.
- Manual disconnect without revoking future authentication.
- Bounded diagnostic snapshots without credentials or remote IP addresses.

A blocked session is not automatically revived if the principal is later re-enabled. A new runtime session must authenticate. The result distinguishes `Closed` from `Unclosable`; it never claims that an existing stream was terminated when the runtime cannot prove that.

**This package is not yet wired into a Sing-box/Xray/Hysteria2 driver, and it does not prove protocol-specific revocation behavior.** Each driver must call the authorization check at the correct session/stream boundary and supply a real runtime-owned closer where available.

## What should be adopted later

### M0 / Task 1
- Prove the session registry against actual Sing-box Reality/Vision and both Hysteria2 implementations.
- Record authentication, new-stream rejection, existing-stream termination and close-failure behavior separately.
- Test cumulative counter sampling, reset generations, batch overflow and durable recovery.
- Build golden configurations and client conformance fixtures from exact release pairs.

### M1 / Tasks 2–4
- Preserve the single logical user / per-endpoint principal model.
- Add deterministic endpoint ordering and format-specific inclusion/exclusion explanations.
- Build authenticated subscription delivery independently from the admin surface.
- Add typed node events only after the agent gateway and authorization contracts exist.
- Keep quota enforcement tied to measured runtime/session capabilities, not UI counters or IP limits.

### M2
- Evaluate XHTTP, additional transports, client-side balancer documents, observatory/ping and external link import as separately gated integrations.
- Add only exact client formats and features that pass native validators and real-client import/connectivity tests.
- Keep client-side selection distinct from control-plane endpoint placement and network-level failover.

### M3
Implement S-UI and 3X-UI migration as one-shot, dry-run-first importers—not by restoring their SQLite databases into OmniPanel. Each importer should identify source/version, parse supported records into the canonical IR, map source clients to logical users and endpoint principals, re-encrypt credentials under OmniPanel keys, report unsupported features and collisions, and write an idempotent migration journal. Imported counters are historical source data, not automatically authoritative billable observations. The operator must approve destructive or ambiguous changes.

## Explicitly rejected shortcuts

- Copying either panel's database schema or service layer into the canonical PostgreSQL model.
- Treating a panel's displayed protocol list as a qualified runtime capability.
- Treating source-IP/Fail2ban limits as device identity or strict quota enforcement; NAT, shared networks and privacy make that unsuitable as a universal entitlement contract.
- Using random or round-robin endpoint ordering as the default for deterministic subscription output.
- Using User-Agent detection as the only compatibility decision.
- Treating a client-side subscription balancer as server-side HA or existing-session migration.
- Treating in-memory pending statistics as durable accounting.
- Treating a SQLite backup or successful panel migration as a PostgreSQL PITR/key/epoch recovery test.
- Treating either source project's personal-use disclaimer as production approval.

## References and review limits

The review used the supplied forks' `main` branches and selected README, Go, TypeScript and English documentation files on 3 November 2026. It did not run either panel, execute their installers, import their databases, or validate their current releases against real clients. Source behavior must be reproduced in OmniPanel's own lab before it becomes a support or security guarantee.
