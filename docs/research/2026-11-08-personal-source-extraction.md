# OMNIPANEL Personal-Use Source Extraction (34 repositories)

**Evidence date:** 2026-11-08. **Scope:** GitHub repository metadata, default-branch trees, READMEs, selected implementation files and tests. This is a targeted source audit, not a complete line-by-line verification or security endorsement. **Goal:** private self-hosted administration by one owner, optionally a few personal nodes and friends/family devices. No reseller, payment, tenant hierarchy, advertising or commercial product roadmap.

**Evidence vocabulary:** S = representative source or tests inspected; D = docs/tree only; I = design inspiration without local verification; R = mechanism to reject. Source URLs identify files available on the review date; upstream branches can move. Do not confuse test names with proven production behavior.

## Complete source register

| Source | Most valuable mechanisms | Personal-use disposition and evidence |
| --- | --- | --- |
| [Hiddify-Manager](https://github.com/hiddify/Hiddify-Manager) | Guided parallel install status, per-domain ACME renew/retry, service graph, DNS-tunnel units, runtime-deleted-inode detection | **Study:** installer/diagnostics/optional transports. Do not copy privileged installer. [installer](https://github.com/hiddify/Hiddify-Manager/blob/dev/scripts/install.sh), [DNS](https://github.com/hiddify/Hiddify-Manager/blob/dev/services/dns_proxy/run.sh) (S) |
| [ShahanPanel](https://github.com/HamedAp/ShahanPanel) | Compact users/online view | **UX only:** its [repeated killusers script](https://github.com/HamedAp/ShahanPanel/blob/main/New-Server/killusers.sh) is not a reliable session controller (S) |
| [x-ui-pro](https://github.com/GFW4Fun/x-ui-pro) | Nginx/transport installation recipes | **Study** topology; verify every advertised combination against pinned native runtime (D) |
| [SulgX-Panel](https://github.com/SulgX/SulgX-Panel) | Lightweight one-file UI, share links, traffic charts, simple hosting | **UX only:** avoid monolith and default administrator password fallback observed in [main.py](https://github.com/SulgX/SulgX-Panel/blob/main/main.py) (S) |
| [Astro](https://github.com/Soroushnk/Astro) | Interactive first-run menus, diagnostics and backup checklist | **UX only:** reject password-based sshpass copy and remote tar-to-root in [backup script](https://github.com/Soroushnk/Astro/blob/main/managed/server-backup.sh) (S) |
| [Marzneshin](https://github.com/marzneshin/marzneshin) | Services grouping inbounds, user fixed/first-use expiry and periodic resets, node backends and host chains | **High-value model:** [service](https://github.com/marzneshin/marzneshin/blob/master/app/models/service.py), [user](https://github.com/marzneshin/marzneshin/blob/master/app/models/user.py); reject fire-and-forget as durable apply in [node ops](https://github.com/marzneshin/marzneshin/blob/master/app/marznode/operations.py) (S) |
| [Marzban](https://github.com/Gozargah/Marzban) | On-hold user state, quota/expiry, explicit subscription client types, UA negotiation, rich Sing-box/Clash/share exporters | **High-value compatibility:** [user](https://github.com/Gozargah/Marzban/blob/master/app/models/user.py), [subscription router](https://github.com/Gozargah/Marzban/blob/master/app/routers/subscription.py), [Sing-box](https://github.com/Gozargah/Marzban/blob/master/app/subscription/singbox.py) (S) |
| [xray-torrent-blocker](https://github.com/kutovoys/xray-torrent-blocker) | Expiring abuse-response state, conntrack, nftables sets | **Selective:** design identity-aware temporary enforcement; reject indiscriminate IP bans under shared NAT. [nft](https://github.com/kutovoys/xray-torrent-blocker/blob/main/firewall/nft.go) (S) |
| [china-dictatorship](https://github.com/cirosantilli/china-dictatorship) | No panel architecture | **Exclude** unrelated content (D) |
| [OpenPacketFix_](https://github.com/panbinibn/OpenPacketFix_) | No substantiated relevant mechanism in inspected metadata | **Exclude** until source proves applicability (D) |
| [sog_v2ryng](https://github.com/shanduzgil/sog_v2ryng) | Containerized frontend + dedicated subscription landing page | **Study:** separate public self-service page from private management plane (D) |
| [AntiDPI-UA-Random-Patcher](https://github.com/GFW4Fun/GFW-AntiDPI-UA-Random-Patcher) | Motivation to audit HTTP client fingerprints | **Reject binary patching:** breaks exact digest and runtime provenance. [readme](https://github.com/GFW4Fun/GFW-AntiDPI-UA-Random-Patcher/blob/master/README.md) (D) |
| [random-CDN-config generator](https://github.com/GFW4Fun/xray_bulk_config_with_random_cdn_ip_range) | Bulk profile templating | **Reject** unverified random endpoint selection; require owned or qualified addresses (D) |
| [S-UI](https://github.com/alireza0/s-ui) | Full Sing-box option assembly, serialized lifecycle and maintenance, cooldown, subscriptions, migration fixtures | **Critical Sing-box reference:** [config lifecycle](https://github.com/alireza0/s-ui/blob/main/service/config.go), [lifecycle tests](https://github.com/alireza0/s-ui/blob/main/core/lifecycle_test.go) (S) |
| [S-UI-PRO](https://github.com/GFW4Fun/S-UI-PRO) | Sing-box + reverse proxy setup recipes | **Study** only, do not run third-party shell installer by default (D) |
| [s-ui-x-extended](https://github.com/deposist/s-ui-x-extended) | Structured config/client doctor, failover hysteresis/all-down policy, XUI migration pre-backup, audit overflow markers, AWG device reconciliation | **Underappreciated high-value reference:** [doctor](https://github.com/deposist/s-ui-x-extended/blob/s-ui-x-extended/service/doctor.go), [failover](https://github.com/deposist/s-ui-x-extended/blob/s-ui-x-extended/service/failover_assembly.go), [migration](https://github.com/deposist/s-ui-x-extended/blob/s-ui-x-extended/api/import_xui.go) (S) |
| [LucX-UI](https://github.com/AlexeyLCP/lucx-ui) | Kernel/host blocker codes, isolated sidecar manifests, AWG diagnostics, geodata and specialized tunnels | **Study** preflight + sandbox. **No direct noncommercial code import without clearance.** [preflight](https://github.com/AlexeyLCP/lucx-ui/blob/main/internal/amneziawgkern/preflight.go), [sidecar design](https://github.com/AlexeyLCP/lucx-ui/blob/main/docs/plugin-sidecars.md) (S/D) |
| [vpn-ui](https://github.com/Sir-MmD/vpn-ui) | Legacy tunneling families, account freeze, direct use of Xray identity, deep device and speed-limit analyses | **Study** NAT-proof per-device registered key identity; speed-limit and device-limit documents are analyses, not proof of shipped enforcement. [device study](https://github.com/Sir-MmD/vpn-ui/blob/main/device-limit-plan.md), [rate study](https://github.com/Sir-MmD/vpn-ui/blob/main/speed-limit-plan.md) (S/D) |
| [railway-x3ui](https://github.com/arvin341az-glitch/railway-x3ui) | Control UI in PaaS-like container | **Low priority:** keep privileged node/supervisor outside restricted containers (D) |
| [whale-panel](https://github.com/primeZdev/whale-panel) | Adapter facade for external panels, aggregate traffic | **Study** read-only legacy panel import/monitoring; reject reseller credit/billing. [services](https://github.com/primeZdev/whale-panel/tree/main/backend/services) (S) |
| [3X-UI-Manager](https://github.com/yukh975/3X-UI-Manager) | Android Keystore-encrypted connection profiles and multi-panel UX | **Adopt design** credential storage; reject [trust-all TLS](https://github.com/yukh975/3X-UI-Manager/blob/main/app/src/main/java/net/yukh/xui/data/auth/InsecureTls.kt). [encrypted profile store](https://github.com/yukh975/3X-UI-Manager/blob/main/app/src/main/java/net/yukh/xui/data/prefs/ConnectionStore.kt) (S) |
| [3x-ui-skill](https://github.com/AndyShaman/3x-ui-skill) | VPS-to-reference-client runbook and guided setup | **Study:** turn steps into a supervised, idempotent install and external acceptance script (D) |
| [3x-ui](https://github.com/MHSanaei/3x-ui) | Bounded node heartbeat concurrency and outage coalescing; usage normalization; protected node tokens; DST-safe renewal; subscription test coverage | **Critical operational reference:** [heartbeat](https://github.com/MHSanaei/3x-ui/blob/main/internal/web/job/node_heartbeat_job.go), [traffic sync](https://github.com/MHSanaei/3x-ui/blob/main/internal/web/job/node_traffic_sync_job.go), [calendar](https://github.com/MHSanaei/3x-ui/blob/main/internal/web/service/calendar_renew.go) (S) |
| [3X-ui.3.7.0](https://github.com/x4gpanell/3X-ui.3.7.0) | Version-specific fork | **Diff-only:** no duplicative upstream adoption without tested divergence (D) |
| [hydraponique/3x-ui](https://github.com/hydraponique/3x-ui) | Specialized regional routing | **Selective** geodata/profile preset inspiration; independent geodata provenance (D) |
| [Fourgetu/3x-ui](https://github.com/Fourgetu/3x-ui) | 3x-ui derivative | **Diff-only** after upstream comparison (D) |
| [sharx-code](https://github.com/konstpic/sharx-code) | Customized 3x-ui-derived frontend | **Diff-only** UI patterns; no general code merge (D) |
| [WINGS-N/3x-ui](https://github.com/WINGS-N/3x-ui) | 3x-ui derivative | **Diff-only** after source-specific finding (D) |
| [Ex3-ui](https://github.com/Bebrik2283555/Ex3-ui) | 3x-ui derivative | **Diff-only** after source-specific finding (D) |
| [MHSanaei/mtg-multi](https://github.com/MHSanaei/mtg-multi) | Per-secret MTProto accounts, quota/expiry and API, fair-share connection throttling | **Optional** pinned sidecar; no sponsor/ads functionality in personal mode. [README](https://github.com/MHSanaei/mtg-multi/blob/main/README.md) (D) |
| [dolonet/mtg-multi](https://github.com/dolonet/mtg-multi) | SIGHUP atomic hot reload, per-secret stats, WEB-mode TLS decoy | **Optional:** compare fork differences and choose one version. Do not retain clients' IP histories by default. [README](https://github.com/dolonet/mtg-multi/blob/master/README.md) (D) |
| [1Panel](https://github.com/1panel-dev/1panel/) | Firewall locator/mutation guards, owner inventory, rollback backup before destructive PostgreSQL restore, host task lifecycle | **High-value host safety:** [firewall](https://github.com/1Panel-dev/1Panel/blob/dev-v2/agent/utils/firewall/filter/safety.go), [restore](https://github.com/1Panel-dev/1Panel/blob/dev-v2/agent/app/service/backup_postgresql.go). Community README does not promise free multi-node (S) |
| [cpanel-csf](https://github.com/cpanel/cpanel-csf) | cPanel-specific firewall scripts | **Exclude** from default personal host path (D) |
| [cpanel-node-api](https://github.com/cpanel/cpanel-node-api) | Hosting-vendor API wrapper | **Exclude** unless explicitly using cPanel (D) |

## Extracted mechanisms and engineering requirements

### Deployment, runtime, trust
1. Maintain exact signed sequence: desired intent -> trusted versioned full-config compiler -> native check -> root-owned atomic stage -> fixed-unit candidate activation -> kernel/PID/socket witness -> independent nonce-bound client probe -> durable applied cursor/ACK. A validated fragment, active PID or green local SOCKS probe is not an applied ACK.
2. Serialize all core lifecycle operations (S-UI) under a single privileged operation lease; prevent concurrent restart/restore/mutation and stale generation replacement.
3. Detect executable-on-disk vs running deleted inode (Hiddify) and only transition to a new binary after digest/provenance validation.
4. Preserve supported Sing-box top-level fields explicitly (S-UI: DNS, NTP, certificate providers, HTTP clients, routing, service endpoints, experimental). Reject unknown/unsafe keys; never silently drop operator-provided configuration.
5. Expose stable structured diagnostic statuses with evidence tier and remedial instruction (S-UI-X doctor). Do not expose secrets or raw native logs to a lower-trust web UI.
6. Apply host-specific preflight blocker codes (LucX) and independently confirm the available IPv4/IPv6, kernel, port, disk, firewall, systemd, certificate and listening socket requirements.
7. Native/runtime feature tables must distinguish recognized, implemented, locally tested and externally qualified; make unsupported protocols unavailable rather than rendering dead UI toggles.

### Connectivity, subscriptions, anti-filtering
8. Provide a named personal profile: transport, credential, expected runtime, public endpoint and client export; stable identity independent of UI widget or inbound row.
9. For client formats, support explicit Sing-box, Mihomo/Clash and share-link selection; use bounded UA negotiation as compatibility fallback, not as identity. Derive exported endpoints only from committed active generations.
10. Separate client-side URL-test/selector/fallback config from server/node failover. Existing OMNIPANEL client balancer already says it cannot migrate live sessions.
11. Failover uses priority + consecutive-healthy hysteresis + bounded probes + explicit all-down policy. **Default to BLOCK, never silent DIRECT.** S-UI-X uses configurable hold/block/direct; do not inherit permissive direct fallback for personal security.
12. Use exact SNI, TLS, ALPN, transport, public host and route ownership; never random CDN IPs or post-signature binary modifications.
13. Defend protected metadata/private IPv4 and IPv6 destinations plus DNS/rebinding/leak paths, with explicit bounded exceptions for intentionally reachable private services.
14. Separate loopback/private management from public proxy/subscription path by default; reverse-proxy/tunnel port sharing requires atomic port ownership and rollback.
15. Per-domain certificate issue/renew/retry with clear stale/self-signed states; reload only affected listeners when supported; ACME failure cannot become a false healthy flag.
16. Optional special transports (DNS tunnels, MTProto, AWG, legacy Xray, sidecars) each require their own capability, binary signature, interface contract, network isolation and real reference-client acceptance.

### Personal identities, device, sessions, traffic
17. **Do not count devices by public IP.** NAT, CGNAT, roaming and shared relays make IP heuristics unsuitable. Use per-device registered keys where possible; otherwise call observed objects sessions/connections, not devices (vpn-ui study).
18. Access state may be active, disabled, paused or expired, with expiration never/fixed/first-use and optional period reset. No reseller credits or monetary plans (Marzneshin/Marzban).
19. Preserve usage WAL, boot-generation, counter reset and gap semantics; normalize dashboard throughput by real poll elapsed time after outages (3x-ui).
20. A traffic quota must be enforced by the driver and tested under load; rendered quotas or TypeScript contracts cannot prove live enforcement. Account for QUIC unclosable sessions explicitly.
21. Renewal and quota reset must be calendar- and timezone-aware, idempotent across repeated/nonexistent local midnight, end-of-month and DST (3x-ui).
22. MTProto per-secret connections, hot reload and throttling are useful as isolated optional runtime only; do not expose active client IPs to default long-term storage.
23. Abuse response must use validated principal/session identity and short-lived owner-tagged firewall rules; public IP banning risks collateral impact on shared NAT (torrent blocker).

### Installation, operations, recovery, privacy
24. Implement guided install with resumable steps and honest intermediate states (Hiddify/Astro). No curl-pipe-root, eval of user inputs, password-containing shell args or privilege escalation via admin API.
25. Read-only personal diagnostics: config parse, preflight, cert, native process, socket, protected route denial, remote client test, subscription/credential validity, storage, last recovery. UI must distinguish untested from failed.
26. Maintenance mode must be durable, bounded and not erase an unconfirmed activation/rollback guard (S-UI).
27. Backups should be encrypted, versioned, manifest-digested, optionally off-host and periodically restored to disposable host. Before any destructive restore create a separate recovery point (1Panel). A successful backup job is not restore proof.
28. Imports from 3x-ui/S-UI (later Marzban/Hiddify) require bounded validated raw source, dry-run, diff, credential rotation, conflict report, pre-import backup, crash-safe journal and reversible commit (S-UI-X).
29. Firewall mutations are subject to current snapshot/version, exact owned rule locator and protected management path; preserve unrelated Docker/host chains and support rollback (1Panel).
30. Event/alert controls should use consecutive-failure threshold, bounded polling, transition coalescing and explicit recovery event rather than per-node event storms (3x-ui).
31. Low-priority audit events may have bounded queues and loss markers (S-UI-X), but **high-severity operator/root decisions must be synchronously durable or reject the operation**; never silently drop security evidence.
32. Optional Android admin app should use Keystore-encrypted credentials and strict TLS or cert pinning; the demonstrated trust-all TLS implementation is not acceptable for OMNIPANEL.
33. Prefer one-owner low-resource default and on-demand optional components. Existing Postgres-backed control semantics cannot be silently replaced by SQLite; a low-resource backend is a separate migration with tests.

## Existing OMNIPANEL overlap — extend, do not recreate

| Observed path/PR | Already available | Missing qualification or next seam |
| --- | --- | --- |
| internal/manifest | Signed desired-state verification | Actual applied-state and runtime binding |
| internal/drivers/singbox/config.go | Bounded Reality/Vision inbound fragment | Full, protected, versioned config compiler |
| PR #16 native Sing-box staging | Pinned native validation | Production activation and safe policy application |
| internal/agent/reconcile/reconciler.go | Authenticated poll -> VERIFIED journal | Applied ACK, committed cursor, rollback on timeout |
| PR #17 activation guard | Durable recovery lease | Actual candidate and confirmation |
| PRs #18–#21 watchdog, root IPC, root host and kernel witness | Local rollback and process/listener trust | Independent client witness, runtime-loaded config and broader route proof |
| internal/agent/metering | Durable checkpoints | Live collectors and enforced quotas |
| internal/agent/sessions/registry.go | Session/principal distinction | Real protocol-specific enforcement, no IP-device inference |
| internal/networking/firewall.go | Read-only safety inventory | Owned atomic mutation and restore |
| internal/backup/task.go | Backup state contract | Real encrypted backup/restore verification |
| src/lib/subscription-profile.ts | Validated profile response headers | Committed-state export and client fixtures |
| src/lib/subscription-balancer.ts | Deterministic client-side group | Health eligibility and no-direct failover policy |
| src/lib/panel-importer.ts | S-UI/3x-ui dry-run contract | Real source decoders and reversible import |
| src/lib/certificate-inventory.ts | ACME/cert state model | Real issuer, renewal and verified reload |

## Priority by personal-use value

**P0, hard release prerequisite:** full config compiler; privilege-limited candidate apply; applied-state ACK; independent client witness; protected egress; real external VPS/reference client acceptance; merge/review existing open PR stack.

**P1, daily personal value:** read-only doctor; install and recovery wizard; secure client profile exports; QR; minimal health dashboard; ACME; encrypted backup+restore; maintenance mode; transparent firewall/proxy controls.

**P2, a few nodes/devices:** optional node failover with block-all-down; per-device key registration; family identities; quota/renewal; backend-independent usage; source migration.

**P3, optional advanced:** Xray backend, Hysteria2, AWG, MTProto, DNS tunnels, geodata presets, custom isolated sidecars, read-only mobile management.

**Rejected defaults:** resellers, affiliate/billing, traffic-for-sale credits, enterprise multi-region orchestration, source-IP surveillance, unsafe TLS, random CDN, binary patching, executing external scripts as root, unaudited forks and broad plugin execution.

## License and security admission

- GPL-3.0 compatibility is not a blanket code-copy authorization. Check exact file/license/third-party dependencies and keep SPDX attribution. Marzban and Marzneshin are AGPL-3.0; LucX contains separately restricted/noncommercial material; personal-use intent does not waive terms.
- For copied code, record source repository + immutable commit + path + license + changes + test provenance in a dependency ledger. Prefer independent behavior implementations and verified client formats.
- Do not import child daemons, kernel drivers or patched core without signed artifact provenance, resource/permission isolation, platform tests and explicit opt-in.

## Evidence and release status

Existing stacked PRs #13 and #15–#21 were open at the previous review; PR #21 local signed root/SIGKILL lab success does not constitute public external M0. [Issue #14](https://github.com/AmirrezaFarnamTaheri/Omnipanel/issues/14) remains the independent acceptance ledger. The separate nonce-bound health attestation development branch is not yet verified as a completed, accepted external test.

**Future acceptance for each extracted mechanism:** exact upstream source; one personal-use user story; typed scope/privilege boundaries; focused regression tests for malformed/replayed/concurrent/expired/restart cases; real host/client tests where claimed; rollback, privacy retention and operator-visible states.