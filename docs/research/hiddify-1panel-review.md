# Hiddify Manager and 1Panel source review: reusable capabilities

**Reviewed:** 2026-11-04. **Scope:** selected repositories, pinned branches/commits and implementation files; no live deployment, import or runtime conformance executed. This document complements [S-UI / 3X-UI findings](source-project-review.md).

## Source identities and licensing boundary

- [Hiddify-Manager](https://github.com/AmirrezaFarnamTaheri/Hiddify-Manager/tree/dev) is a GPL-3.0 deployment/service repository. Its panel source is a separate Git submodule, pinned to [hiddify/hiddifypanel at 6f3e4457](https://github.com/hiddify/hiddifypanel/tree/6f3e4457aef38e033c731a12a9d8a3e8da6d8f4c).
- That pinned Hiddify Panel [license file](https://github.com/hiddify/hiddifypanel/blob/6f3e4457aef38e033c731a12a9d8a3e8da6d8f4c/LICENSE.md) specifies **CC BY-NC-SA 4.0**. OmniPanel's intended GPL version 3 does **not** authorize wholesale copying of this differently licensed panel code. Study behavior and write independently, or obtain separate rights.
- [1Panel dev-v2](https://github.com/AmirrezaFarnamTaheri/1Panel/tree/dev-v2) declares GPL-3.0; reusable snippets still require original notices, attribution and dependency review. No code was copied in this review.
- The project owner approved GPL version 3 for OmniPanel. The exact \`-only\` vs \`-or-later\` distribution grant remains an explicit packaging choice.

## Hiddify Manager / Hiddify Panel

| Inspected source | Valuable behavior | OmniPanel boundary and safety rule |
| --- | --- | --- |
| [config builder](https://github.com/hiddify/hiddifypanel/tree/6f3e4457aef38e033c731a12a9d8a3e8da6d8f4c/hiddifypanel/proxy_v3/config_builder) | Protocol/client rendering registry, JSON diagnostics and error localization | Typed \`internal/subscription\` and \`internal/drivers\` renderers, native validators, no arbitrary trusted templates |
| [node sync](https://github.com/hiddify/hiddifypanel/tree/6f3e4457aef38e033c731a12a9d8a3e8da6d8f4c/hiddifypanel/hutils/node) | Bounded feeds, record cursors/tombstones, inventory digests, missed-record resynchronization | Separate signed structural/membership streams, authenticated node scope, explicit epoch recovery |
| [ACME](https://github.com/hiddify/hiddifypanel/tree/6f3e4457aef38e033c731a12a9d8a3e8da6d8f4c/hiddifypanel/acme) | Domain-scoped certificate renewal, retry/backoff, rate-limit awareness, atomic updates | \`internal/certificates\` with TLS boundary inventory, audited renewal and no silent insecure fallback |
| [config testing](https://github.com/hiddify/hiddifypanel/tree/6f3e4457aef38e033c731a12a9d8a3e8da6d8f4c/hiddifypanel/admin_v2/src/features/config-tester) | Import and connectivity checks for client/output combinations | Exact-release client compatibility lab; native schema pass alone is not sufficient |
| [L4 multiplexer](https://github.com/AmirrezaFarnamTaheri/Hiddify-Manager/tree/dev/services/rust-rpxy-l4) | Optional SNI-based ingress multiplexing | M2+ optional driver; test absent/unexpected SNI, malformed TLS, QUIC and socket ownership before use |

**Recommendation:** Hiddify's *behaviors* improve endpoints, certificate automation, support explanations and recovery; the separately licensed panel source is a reference, not a copy target. CDN termination, relay identity and fallback remain distinct trust models.

## 1Panel

| Inspected source | Valuable behavior | OmniPanel boundary and safety rule |
| --- | --- | --- |
| [host monitoring](https://github.com/AmirrezaFarnamTaheri/1Panel/blob/dev-v2/agent/app/service/monitor.go) | CPU, memory, disk, processes, network and historical monitoring | \`internal/observability\`; separate node resources from L1/L2/L3 proxy health and metering freshness |
| [firewall adapters/safety](https://github.com/AmirrezaFarnamTaheri/1Panel/tree/dev-v2/agent/utils/firewall) | nftables/iptables/UFW/firewalld inventory, normalized rule identity and protected-rule handling | \`internal/networking\`; start read-only, apply only owned rules with external commit-confirm watchdog, protect SSH and management |
| [cloud storage](https://github.com/AmirrezaFarnamTaheri/1Panel/tree/dev-v2/agent/utils/cloud_storage) | Local, S3/MinIO, SFTP, WebDAV and provider adapters for backups | \`internal/backup\`; initial local + S3-compatible storage, independent KEK backup, TLS certificate validation. Inspected S3 implementation disables TLS verification; do not reproduce it |
| [cron scheduler](https://github.com/AmirrezaFarnamTaheri/1Panel/tree/dev-v2/agent/cron) | Scheduled recurring work, restart recovery and history | \`internal/jobs\`; PostgreSQL outbox, idempotent leases, bounded retries and audited outcomes instead of volatile-only cron |
| [alert service](https://github.com/AmirrezaFarnamTaheri/1Panel/tree/dev-v2/agent/app/service) | Multiple notification transports | \`internal/alerts\`; deduplication, per-organization authorization, redacted messages and rate limits |
| [terminal/auth lease](https://github.com/AmirrezaFarnamTaheri/1Panel/tree/dev-v2/agent/utils/terminal) | Revocable session leases and bounded streams | M3 consideration only; no unrestricted shell or SSH surrogate in node agent |

**Recommendation:** Borrow narrowly specified operational interfaces, not 1Panel's general app store, site/WordPress manager, Docker control plane or file manager. Backups are incomplete without PostgreSQL PITR **and separately restored key material**, verified as one disaster-recovery exercise.

## Adoption order

1. **M0/M1:** typed drivers, real runtime/client diagnostics, session + metering evidence, exact capabilities.
2. **M1:** node resource monitoring, source-aware alerts, durable jobs, local + S3 encrypted backups, ACME certificate inventory and recovery.
3. **M2:** managed domain/CDN paths, guardrailed nftables rules, selected relays and external reachability vantages after explicit policy gates.
4. **M3:** optional multiplexer/advanced management and one-shot migration tools with independent security reviews.

## Anti-goals

No replacement of canonical PostgreSQL with upstream SQLite schemas; no dynamic root shell through agent APIs; no unverified TLS skip for storage; no user-agent-only client compatibility promises; no double billing relay counters; no silent direct egress fallback from strict WARP policy; no copy of CC BY-NC-SA panel code into GPL-distributed OmniPanel.
