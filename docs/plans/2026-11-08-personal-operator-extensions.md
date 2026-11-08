# Personal Operator Experience and Optional Drivers Implementation Plan

> **For agentic workers:** Use the host's available task-by-task implementation workflow. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Absorb proven self-hosted UX, diagnostics, profile, recovery, portability and protocol-extension ideas from reviewed panels without turning OMNIPANEL into a reseller service or sacrificing its fixed-root security boundary.

**Architecture:** Add low-resource, feature-gated modules around existing OMNIPANEL Go agent/runtime interfaces and TypeScript presentation contracts. Every UI action must be a typed, authenticated operation whose observed result comes from real host, stored state or an explicit unknown tier. Externally qualified applied-state pipeline remains the only path for published proxy endpoints. Optional protocols and sidecars are isolated from control-plane secrets.

**Tech Stack:** Existing Go drivers, state, networking, backup and auth packages; TypeScript/Next.js contracts during migration toward Go API + React/Vite; SQLite agent journal; existing PostgreSQL control storage; pinned native Sing-box/Xray/sidecars; Linux services and ACME.

## Global Constraints

- Default: one private owner, one node, optional additional personally controlled nodes and trusted friends/family devices; no sales, prepaid credits, payment gateways, sponsored Telegram placement, resellers or mandatory multi-tenant roles.
- Privileged root operations remain fixed-verb and generation-approved. Personal simplicity must never create a second unsigned shell/JSON apply path.
- Default panel access is private/network-restricted. Public subscriptions and the data-plane are separate least-privilege endpoints.
- No source-IP-based "device" enforcement; use explicitly registered device credentials/keys only where protocol supports the property.
- No automatic direct fallback on failure; no binary patching, trust-all TLS, unknown third-party executables or remote root scripts.
- Existing modules listed as observed are *not* necessarily production executors: backup/task and certificate inventory are contracts; subscription balancer is client-side only; panel importer is dry-run only.
- Work packages are independent PRs; maintain a feature registry with supported/runtime-verified/external-qualified labels. Availability is not a license to turn on a feature.

---

### Task 1: Read-only operator and client configuration doctor

**Files:**
- Create (proposed): internal/agent/doctor/doctor.go
- Test (proposed): internal/agent/doctor/doctor_test.go
- Create (proposed): cmd/omnipanel-doctor/main.go, main_test.go
- Modify (observed): internal/drivers/types.go (only if a typed diagnostic classification is required)
- Modify (observed): src/app/(admin)/nodes/[id]/page.tsx (visual state after Go API exists)

**Interfaces:**
- Consumes (proposed): DoctorProbe interface with Name() string and Check(context.Context) Finding, each probe supplied by existing protected journal, native observer, firewall snapshot and cert inventory. Probe output contains no config bytes.
- Produces (proposed): Report{ObservedAt, NodeID, Overall, Findings[]} where a Finding has stable CheckID, Tier(config/host/client), Status(pass/warn/fail/unknown), ErrCode, ActionID. CLI exits 0 only if required checks pass; 2 if any required fail; 3 if required evidence unavailable.

- [ ] **Step 1: Add failing tests.** Wrong node ID, missing supervisor, config check failure, expired cert, untrusted listener, stale evidence, redacted secret content, permission denial, context timeout, optional probe unavailable and no false "healthy" without client proof.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/agent/doctor ./cmd/omnipanel-doctor. Expected missing doctor types and CLI until implemented.
- [ ] **Step 3: Implement minimum.** Bounded read-only checks with stable codes and clean evidence tiers; never execute root command from CLI or return raw native stderr. Reference S-UI-X doctor and LucX host readiness, not their privileges or direct configuration.
- [ ] **Step 4: Focused pass.** Test same package and inspect sanitized output.
- [ ] **Step 5: Integration.** Run make test-go and a real signed host smoke in CI with known-good, missing service, wrong binary, expired cert and intentionally blocked client-port cases. Report unknown rather than assuming pass.
- [ ] **Step 6: Commit.** A standalone diagnostic contract is useful even before interactive UI.

### Task 2: Personal-first guided bootstrap and maintenance

**Files:**
- Create (proposed): cmd/omnipanel-setup/main.go, main_test.go
- Create (proposed): internal/agent/bootstrap/steps.go, steps_test.go
- Modify (observed): src/app/(auth)/setup/page.tsx
- Modify (branch-only observed): cmd/omnipanel-supervisor/main.go only for fixed provisioning acceptance, never generic install shell.

**Interfaces:**
- Consumes: locally verified OS/architecture/platform, explicitly installed root supervisor, protected node enrollment identity and pinned binary inventory.
- Produces (proposed): BootstrapPlan with deterministic steps + prerequisite findings + immutable run ID; ApplyBootstrap(context, planID) only invokes allowlisted idempotent package/service steps under a separate narrow privileged installer, not the public API. MaintenanceLease carries reason, owner, deadline and rollback guard binding.

- [ ] **Step 1: Add failing tests.** Idempotent rerun, interrupted step resume, unsupported distribution, absent systemd, non-root default user, unsafe path, occupied management port, expired maintenance lease, crash while maintenance is active, concurrent setup, and no cancel of an unconfirmed rollback guard.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/agent/bootstrap ./cmd/omnipanel-setup. Expected unknown bootstrap interfaces.
- [ ] **Step 3: Implement minimum.** Separate inspect/plan/apply; private directory permissions; signed runtime lockfile and explicit host prerequisites; recoverable journal. Show Hiddify-style honest progress and Astro-style simple workflow without executing third-party root installers.
- [ ] **Step 4: Focused pass.** Verify all failure states retain original host state and stable retry identifiers.
- [ ] **Step 5: Integration.** Disposable host exercise from clean VPS/VM through service install, local admin login, node enrollment, first approved known-good baseline, restore and uninstall; public service remains off until qualified.
- [ ] **Step 6: Commit.** Restrict initial OS matrix to an explicitly reviewed host target; others remain unsupported rather than claimed.

### Task 3: Personal profiles, key-based devices and client exports

**Files:**
- Create (proposed): internal/control/personalprofile/model.go, model_test.go
- Create (proposed): internal/control/personalprofile/export.go, export_test.go
- Modify (observed): src/lib/subscription.ts, src/lib/subscription-profile.ts
- Modify (observed): src/lib/subscription-balancer.ts
- Modify (observed): internal/agent/sessions/registry.go only to expose existing session semantics without inventing device IDs

**Interfaces:**
- Produces (proposed): PersonalProfile{ProfileID, DisplayName, PrincipalIDs, EndpointIDs, Formats, AccessState, ExpiryMode, ExpiresAt, FirstUseDuration}. CredentialBinding{DeviceID, PrincipalID, PublicKeyFingerprint, Status}, with protocol capability checking. ExportProfile(ctx, profileID, format, committedSnapshot) returns client bytes + content type + metadata; no uncommitted candidate endpoints.
- Consumes: immutable applied/healthy endpoint snapshot, not desired manifest only; protocol exporter supports explicit Sing-box, Mihomo/Clash and validated share-links.

- [ ] **Step 1: Add failing tests.** Duplicate device key, revoked key, first-use activation exactly once, fixed expiry, unlimited, UTC/DST/local calendar resets, shared NAT between two real registered devices, one roaming device on multiple IPs, malformed URI/header injection, noncommitted endpoint omission, deterministic sort/format and token rotation.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/control/personalprofile; npm run test:contracts. Expected new Go profile tests fail before implementation; existing TS subscription contracts remain green.
- [ ] **Step 3: Implement minimum.** Separate principal/account, registered credential, runtime session and subscription resource. Marzneshin services and Marzban subscription types are models; **never identify devices through public IP**. Export format explicit first, UA negotiation optional with correct cache controls.
- [ ] **Step 4: Focused pass.** Golden fixtures match each verified client format; revoked profiles no longer expose working credentials.
- [ ] **Step 5: Integration.** Reference clients import QR/links and connect to a genuinely applied node; confirm a subscriber cannot see a failed generation. Run make test-go and contract tests.
- [ ] **Step 6: Commit.** Friend/family sharing remains optional, not a sales/product hierarchy.

### Task 4: Owned firewall and certificate lifecycle

**Files:**
- Create (proposed): internal/networking/managedrules.go, managedrules_test.go
- Modify (observed): internal/networking/firewall.go
- Create (proposed): internal/certificates/acme.go, acme_test.go
- Modify (observed): src/lib/certificate-inventory.ts

**Interfaces:**
- Produces (proposed): FirewallPlan{ObservedSnapshotDigest, ExactOwnedRules, ProtectedManagementPorts}; ApplyOwnedRules(ctx, plan) returns new observation and rollback identifier, never generic iptables/nft command input. CertificateRenewal{SANs, BoundService, ExpectedFingerprint, Deadline} staged under separate ACME trust boundary.
- Consumes: verified existing host snapshot, management connectivity preservation, signed host service identities; no public controller certificate can replace node mTLS trust.

- [ ] **Step 1: Add failing tests.** Docker chain coexistence, stale snapshot, exact rule locator conflict, IPv6 management lockout, reverse NAT/port collision, port 443 reuse, ACME rate limit, SAN mismatch, failed reload and attempted cross-boundary certificate use.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/networking ./internal/certificates. Expected new mutation/ACME tests fail before implementation.
- [ ] **Step 3: Implement minimum.** Inventory -> semantic diff -> protected ownership guard -> narrow atomic rule mutation -> observe -> rollback. Reuse 1Panel rule-safety concept; add retry/backoff and isolated ACME credential store. Nothing executes arbitrary root scripts.
- [ ] **Step 4: Focused pass.** Host management path stays reachable across deliberately failed mutations; cert mismatch remains unhealthy.
- [ ] **Step 5: Integration.** Disposable root/nft/systemd lab plus ACME staging CA; verify certificate rollover and failed-host rollback, then make test-go.
- [ ] **Step 6: Commit.** Keep firewall and cert tests as separately reviewable changes if their privilege boundaries differ.

### Task 5: Executable encrypted backups, pre-restore checkpoint and recovery drill

**Files:**
- Modify (observed): internal/backup/task.go, repository.go
- Create (proposed): internal/backup/engine.go, engine_test.go
- Create (proposed): cmd/omnipanel-backup/main.go, main_test.go
- Modify (observed): src/lib/backup-tasks.ts only for status presentation
- Test (proposed): lab/runtime/run-backup-restore-smoke.sh

**Interfaces:**
- Produces (proposed): BackupManifest{SchemaVersion, CreatedAt, ArtifactDigest, Node/ControlScope, Encrypted, KeyID, RestoreTested}; Backup(ctx, destination) returns immutable artifact and ledger update; RestoreDryRun(ctx, artifact) returns compatibility/conflict report; Restore(ctx, verifiedArtifact) requires a distinct pre-restore checkpoint and operator approval.
- Consumes: protected node journal, control DB and runtime configuration through separately authorized read-only export. No secret bytes ever enter console or logs.

- [ ] **Step 1: Add failing tests.** Interrupted backup, wrong key, corrupted ciphertext, restored wrong node/epoch, symlinked directory, malicious archive path, incomplete WAL checkpoint, expired retention, unavailable off-host destination and pre-restore backup failure. A green backup task without verified restore must remain unqualified.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/backup ./cmd/omnipanel-backup. Expected executor/manifest tests fail before implementation; task-ledger tests remain green.
- [ ] **Step 3: Implement minimum.** Atomic encrypted artifacts with hash+manifest, owner-only temporary directories, bounded file entries, fsync/rename, checksum on import, optional off-host copy and restore to a disposable location. 1Panel's backup-before-restore informs the irreversible action boundary.
- [ ] **Step 4: Focused pass.** Wrong artifact/key/epoch does not change production state; completed dry-run shows precise actions.
- [ ] **Step 5: Integration.** VM A backup -> VM B restore and independent client connection with restored/rotated trust; include recovery of credentials and epoch cutover. Run make test-go and genuine PostgreSQL restore/PITR lab where used.
- [ ] **Step 6: Commit.** Retention schedule can be operator configurable, never require a paid storage backend.

### Task 6: Low-noise node alerts and privacy-safe failover

**Files:**
- Create (proposed): internal/agent/healthpolicy/failover.go, failover_test.go
- Create (proposed): internal/agent/healthpolicy/alerts.go, alerts_test.go
- Modify (observed): src/lib/subscription-balancer.ts
- Modify (observed): src/lib/alerts.ts

**Interfaces:**
- Produces (proposed): SelectEligibleEndpoint(now, committedNodeEvidence, Preference, FailurePolicy) -> NodeSelection{EndpointID or Block, Reason, EvidenceAge}. AlertTransition{ID, NodeID, From, To, EvidenceTime, SuppressedCount}. FailurePolicy includes BlockAllDown; direct bypass is not the default/automatic outcome.
- Consumes: only committed node health and bounded independent witness age, not raw heartbeats alone.

- [ ] **Step 1: Add failing tests.** All nodes down => no endpoint; transient heartbeat blip does not oscillate; stale evidence ineligible; wrong epoch invalidates choice; two-flap alert burst coalesces; manual pin not silently bypassed; no claim of migrated existing sessions.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/agent/healthpolicy; npm run test:contracts. Expected selection tests fail on absent module.
- [ ] **Step 3: Implement minimum.** Priority+health hysteresis+maximum evidence age and stable de-duplication keys; default personal mode prefers one known primary and optional backup; API exposes cause and monitoring age.
- [ ] **Step 4: Focused pass.** Exactly one meaningful transition alert per outage/recovery window and no direct bypass under all-down.
- [ ] **Step 5: Integration.** Two disposable nodes, stop primary/secondary, verify fallback and restoration; previously active TCP/QUIC connections are reported as disconnected/reestablishing rather than automatically migrated.
- [ ] **Step 6: Commit.** Integration may remain opt-in without second personally operated node.

### Task 7: Read-only import and reversible source panel migration

**Files:**
- Modify (observed): src/lib/panel-importer.ts
- Create (proposed): internal/importers/sui.go, sui_test.go
- Create (proposed): internal/importers/xui.go, xui_test.go
- Create (proposed): internal/importers/backup.go, backup_test.go
- Create (proposed): internal/importers/marzban.go, marzban_test.go
- Test (observed): tests/contracts/recomposition-contracts.test.ts

**Interfaces:**
- Produces (proposed): AnalyzeImport(ctx, immutableBackup, sourceVersion) -> ImportPreview{ContentDigest, Conflicts, Unsupported, CredentialRotation, HistoricalUsage, SafeToCommit}; CommitImport(ctx, previewDigest, approvedBackup) records one journal transition and secure pre-import rollback artifact.
- Consumes: exported backups only, never direct execution of source panel SQL or imported scripts. Historical counters retain non-billable labels.

- [ ] **Step 1: Add failing tests.** Malformed SQLite, decompression bomb, symlink archive, duplicate users/inbounds/ports, invalid TLS key, stale template, legacy credentials, wrong source type, unknown protocol and concurrent retries.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/importers; npm run test:contracts. Expected missing decoders/preview tests fail; existing dry-run contracts stay green.
- [ ] **Step 3: Implement minimum.** Typed version-specific extraction; preserve source metadata/hash, redact credentials, map only qualified protocols, produce human-readable diff, require pre-import backup and explicit per-conflict choices; no auto-commit on upload.
- [ ] **Step 4: Focused pass.** Golden fixtures produce deterministic conflicts and explicit unsupported records.
- [ ] **Step 5: Integration.** Authorized fixture exports from S-UI/3x-ui first, later Marzban/Hiddify; import, activate only qualified endpoint, revert source after simulated failure. Repeat after interruption.
- [ ] **Step 6: Commit.** Each source family is independent and can be reviewed separately.

### Task 8: Optional isolated protocol engines, transports and sidecars

**Files:**
- Create (proposed): internal/drivers/registry.go, registry_test.go
- Create (proposed): internal/agent/sidecars/manifest.go, manifest_test.go
- Create (proposed): internal/agent/sidecars/sandbox.go, sandbox_test.go
- Modify (observed): capabilities/runtime.json, capabilities/clients.json
- Create (proposed): docs/implementation/personal-optional-protocols.md

**Interfaces:**
- Produces (proposed): RuntimeCapability{DriverID, Version, BinaryDigest, SupportedTransport, Validated, NativeTested, ClientQualified, RequiredHostFeatures}; SidecarSpec{Digest, Arch, NonrootUID, NetworkProfile, CPU/MemoryBound, HealthProbe}. Installable only through allowlisted pinned artifacts with provenance and explicit opt-in.
- Consumes: existing drivers.Driver interface. No sidecar can edit node mTLS, access panel admin API, write root-owned generations or obtain supervisor socket.

- [ ] **Step 1: Add failing tests.** Unknown runtime, unsigned/modified binary, unsupported OS, missing kernel module, colliding port, unsafe path, required CPU cap unenforceable, archive traversal, sidecar network/admin capability request and failure to terminate child after restart.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/drivers ./internal/agent/sidecars. Expected absent registry/sandbox types or fail-closed rejection.
- [ ] **Step 3: Implement minimum.** Start with native Sing-box only; optional Xray, Hysteria2, AWG, MTProto, DNS-tunnel and experimental transport drivers each ship a separate permission, config and qualification manifest. Do not copy patched Xray cores or kernel module installers into default build.
- [ ] **Step 4: Focused pass.** Unknown artifact cannot start, unsupported module remains unavailable, secrets never transit sidecar logs.
- [ ] **Step 5: Integration.** Isolated runtime and reference-client compatibility for each activated capability (including protected route denial and rollback); multi-protocol tests must not claim universality from one smoke fixture.
- [ ] **Step 6: Commit.** Deliver one qualified optional driver per PR; unqualified drivers stay disabled.

### Task 9: Private minimal dashboard and optional secure mobile API

**Files:**
- Modify (observed): src/app/(admin)/page.tsx, src/app/(admin)/nodes/page.tsx
- Create (proposed): internal/control/personalapi/health.go, health_test.go
- Create (proposed): docs/implementation/mobile-personal-administration.md

**Interfaces:**
- Produces (proposed): authenticated read-only node/profile/certificate/backup summaries with explicit evidence tier; separate destructive API capability requires fresh session/step-up and refuses bearer tokens from a subscription URL.
- Consumes: operator profile, applied-state ledger, doctor and health policies. Mobile clients store only scoped tokens in platform keystore and use strict TLS/CA pinning.

- [ ] **Step 1: Add failing tests.** Anonymous read, reused subscriber URL, cross-origin request, stale admin session, CSRF, untrusted TLS, unauthorized destructive request, absent M0 evidence shown as success, sensitive IP/secret in logs.
- [ ] **Step 2: Verify failure.** Run: go test -count=1 ./internal/control/personalapi; npm run test:contracts. Expected missing API or unauthorized behaviors fail.
- [ ] **Step 3: Implement minimum.** One-screen overview: current applied generation, node/proxy health tiers, last external witness, active profiles, connection failures, backup age, certificate status and diagnostics. Keep resource charting optional and privacy-minimal. No sales/tenancy UI.
- [ ] **Step 4: Focused pass.** Tests demonstrate role and evidence boundaries, no secrets in JSON, no trust-all TLS.
- [ ] **Step 5: Integration.** Browser and optional phone on a private management network, with token rotation/revocation and disabled public admin endpoint by default.
- [ ] **Step 6: Commit.** Mobile application packaging is independent and follows a stable reviewed API.

## Incremental adoption and compatibility policy

| Domain | Source inspirations | Personal default | Optional extensions |
| --- | --- | --- | --- |
| Runtime | S-UI, Hiddify, 3x-ui | Sing-box pinned + verified | Xray, alternative signed cores |
| Access | Marzneshin, Marzban, vpn-ui | Named personal profiles and key binding | Friends/family device groups |
| Subscription | Marzban, 3x-ui, S-UI, sog_v2ryng | Export only committed endpoints | Client-specific templates, private portal |
| Failover | S-UI-X, 3x-ui | Block when all down | Preferred backup nodes, client URL-test |
| Host | 1Panel, Hiddify, LucX | Read-only doctor, safe cert and firewall | Controlled kernel/sidecar tools |
| Migration | S-UI-X, Whale Panel | Local backup import/dry-run | Other source panel adapters |
| Abuse/quotas | torrent blocker, mtg-multi | Usage view and protected route denial | Per-principal enforcement and connection throttling |
| Mobile | 3X-UI-Manager | Private responsive dashboard | Scoped native app |

## Execution sequence and release criteria

- Personal core integrity plan is a prerequisite for any user-facing claim that a profile is applied/healthy. The doctor module can ship independently as read-only code.
- Work packages 1, 2, 5 and 7 have immediate personal-use value and can be reviewed separately. Packages 3 and 6 require trustworthy committed applied state. Package 8 is **strict opt-in**; package 9 may ship a read-only status view with unqualified labels.
- Each task follows RED -> GREEN -> integration -> exact-head CI, with a reviewer permitted to reject one module without blocking other independent modules.
- A UI feature may be displayed as unsupported or unqualified but never as deployable without matching runtime and reference-client evidence.
- External release gates remain open in [issue #14](https://github.com/AmirrezaFarnamTaheri/Omnipanel/issues/14).

## Operator-visible decisions not yet settled

1. Whether private-only administration is via loopback SSH forwarding or private VPN interface; public HTTPS administration is not the automatic fallback.
2. Initial qualified OS/runtime and reference-client matrix, to be recorded before packaging external install scripts.
3. Whether the operator wants optional friends/family identity groups and a shared portal; neither is required for a single-owner system.
4. Default retention windows for usage, logs, audit and device/session metadata; do not silently collect source IPs or browsing history pending this choice.
5. Optional protocol preference: Hysteria2, Xray, AWG, MTProto, DNS-tunnel or reverse proxy can be developed separately without blocking personal M0.

**No feature described in this plan is claimed implemented by the creation of this document.**