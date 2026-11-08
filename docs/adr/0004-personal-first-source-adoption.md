# ADR 0004 — Personal-first OMNIPANEL with selectively adopted upstream mechanisms

**Date:** 2026-11-08
**Status:** Proposed for review
**Context:** [34-repository source audit](../research/2026-11-08-personal-source-extraction.md), existing v2 trust baseline and [external acceptance issue #14](https://github.com/AmirrezaFarnamTaheri/Omnipanel/issues/14).

## Decision

OMNIPANEL is a **self-hosted, personal operator panel**, not a commercial VPN sales or multi-tenant SaaS product. Default workflows target a single owner and one node; an owner can optionally add personally operated nodes and trusted friends/family devices. Do not add reseller balances, checkout/payment, affiliate systems, customer acquisition, tenant billing, mandatory enterprise identity or production multi-region complexity merely to match upstream feature counts.

We **retain** the existing Go signed desired-state and root-supervisor architecture. Compatibility and UX ideas from Marzneshin, 3x-ui, S-UI, Marzban, Hiddify, 1Panel, S-UI-X Extended, LucX, vpn-ui and specialized tools enter only through reviewed, bounded, testable modules. A source project's attractive feature does not automatically qualify its security, binaries, network routes, licensing or deployment assumptions.

## Principles and consequences

1. **Safe and usable by one operator:** understandable setup, preview-before-apply, private management endpoint, backup/restore, owner-controlled keys, readable diagnostics, optional advanced settings.
2. **No second easy-but-unsafe apply path:** UI, CLI and automation all consume the same verified manifest/staging/supervisor/health/ack sequence. Never run user-supplied shell commands as root.
3. **Default fail closed:** no implicit direct traffic fallback when all proxy outbounds fail, no SSL verification bypass, no unverified CDN address selection, no unsigned or edited-on-disk runtime binary.
4. **Protocol breadth is optional and separately tested:** recognized, compilable, native-tested and externally qualified remain distinct states. Optional engines and sidecars cannot alter privileged root RPC verbs.
5. **Device != source IP:** track per-device credentials when supported; otherwise expose sessions/connections without a false device count.
6. **Privacy minimum:** avoid default subscriber user-agent histories, source-IP/device fingerprint tracking, browsing-history collection and public service telemetry. Expose only health/usage detail necessary for personal operation.
7. **Low operational burden:** avoid Redis/MySQL/job queues solely to enable optional personal features. Postgres-backed authoritative Go/TypeScript components already exist and cannot be swapped for SQLite without a separately reviewed consistency migration.
8. **One clear security boundary:** management UI -> authenticated control API -> signed, node-scoped publication -> local unprivileged agent -> root-owned fixed-verb supervisor -> qualified runtime. Public subscriptions are a separate minimal-permission surface.
9. **Independent proof:** local unit tests and real hosted-CI recovery tests do not satisfy public VPS/external reference-client M0. Only reviewed evidence authorizes new release labels.
10. **Licensing:** direct copying requires per-file source, license, provenance and obligations review. AGPL and PolyForm-restricted code cannot be assumed reusable simply because OMNIPANEL will be GPL-3.0 or personally operated.

## Personal profile model

Recommend one lightweight 'personal profile' concept (proposed, not yet implemented): a named collection of eligible endpoints/protocols, client export formats, access credentials and optional verified device bindings. It is **not** a subscription sales plan. Its public export must derive only from healthy, committed deployments, and connection credentials must remain separate from panel administrator and node mTLS credentials.

## Explicitly excluded from personal default

Reseller/admin credit quotas, sales bots, ads, payment provider hooks, marketing bundles, IP-based device enforcement, bulk anonymous CDN endpoint generators, trust-all TLS, root-install scripts downloaded at runtime, arbitrary third-party plugin execution, traffic surveillance dashboards and unqualified experimental cores.

## Rollout

- First complete existing stacked PR reviews and external acceptance for the real control-to-node path.
- Add read-only diagnostics and personal setup/backup flows behind verified runtime state.
- Add optional node/profile convenience only after applied ACK is trustworthy.
- Add specialized independent protocol drivers only on an opt-in, pinned, tested basis.

## Unresolved operator-visible choices

The project has not yet selected (a) which supported OS/distribution pair is first for the host packaging acceptance harness, (b) whether an owner wants a private-network-only dashboard or separately reachable public HTTPS admin endpoint, (c) which reference clients/platforms must be qualified before enabling each format, or (d) whether a lightweight control-plane persistence alternative to PostgreSQL is valuable enough to fund a consistency/migration project. These choices must be recorded in a separate reviewed ADR before they change privileged deployment or published defaults.
