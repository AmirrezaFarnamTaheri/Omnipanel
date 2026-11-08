# Personal Core Integrity Implementation Plan

> **For agentic workers:** Use the host's available task-by-task implementation workflow. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Make a personal OMNIPANEL node reliably apply a signed, protected full Sing-box configuration, independently prove connection and safe egress, and publish a durable applied acknowledgment without bypassing crash-safe rollback.

**Architecture:** Keep current signed manifest, unprivileged node agent, SQLite WAL journal, root-owned fixed-verb supervisor, separate watchdog and native binary pinning. Add a narrowly typed full-config compiler, generation-specific candidate authorization, root-mediated apply, remote witness, transactional journal commit and mTLS applied-state receipt. Any failure leaves the previous qualified generation eligible for restoration. No commercial user/customer layer.

**Tech Stack:** Go 1.23 module / CI Go 1.27, Linux systemd/procfs, Sing-box pinned artifacts, SQLite WAL, PostgreSQL 17 on control side, Go net/http mTLS, existing TypeScript contracts and GitHub Actions.

## Global Constraints

- Existing stacked security/host PRs #13, #15–#21 are open at the baseline review. Do not silently merge them or imply they are already on main. Code paths introduced only by those PRs are **branch-only observed**, not yet main.
- No arbitrary root command, path, host endpoint, service unit, shell script, JSON config bytes or runtime version from a watchdog/user-facing IPC request. Privileged candidate allowlisting must be independently rooted in approved trusted local state and policy preflight.
- Signed desired intent is not proof of applied state; host health is not independent client proof; a signed report whose test was not actually executed is not production qualification.
- Preserve exact node ID, epoch, structural/membership sequence, signed manifest digest, candidate SHA-256, former LKG SHA-256 and witness challenge nonce across the apply/ACK chain. Do not advance cursor on timeout, crash, revocation or stale evidence.
- Protected IPv4/IPv6/metadata/DNS egress must be enforced in full-config compilation and tested with independent clients; no implicit direct fallback.
- Runtime bytes/config/credentials must never enter logs, audit/error messages, UI, PR comments or CI artifact uploads. Security evidence persists with redacted stable error codes.
- All code tasks follow RED -> GREEN -> focused integration -> exact-head CI, independently reviewable. No product feature gets a production-ready status until external acceptance in issue #14.

---

### Task 1: Integration and exact-head foundation gate

**Files:**
- Modify (observed): .github/workflows/contracts.yml
- Modify (observed): .github/workflows/runtime-smoke.yml
- Modify (observed): docs/implementation/status.md
- Test (observed): internal/agent/supervisoripc/real_host_test.go

**Interfaces:**
- Consumes: verified code from sequential PRs #13, #16, #17, #18, #19, #20, #21 and independently reviewable #15.
- Produces: reviewed merged commit SHA, exact-head Foundation + signed-root-host + PostgreSQL migration checks, and a redacted machine-readable baseline status.

- [ ] **Step 1: Add focused failing test.** Assert that CI names and rendered gate report distinguish signed local host test from public external M0, and that fixed root IPC refuses unknown verbs; reproduce one intentional missing-gate error before updating workflows.
- [ ] **Step 2: Verify relevant failure.** Run: make check-contracts test-contracts test-go test-provenance. Expected targeted policy test to fail before introducing the missing gate; existing unrelated tests must not be edited to greenwash.
- [ ] **Step 3: Implement minimum.** Review stack in dependency order, record exact review + merge SHA, resolve branch conflicts, and add read-only gate evidence summary without altering permissive release status. Require signed runtime workflow and PostgreSQL 17 tests as explicit checks where they exist.
- [ ] **Step 4: Focused pass.** Run the same command on a checked-out consolidated head; the previously failing policy test succeeds.
- [ ] **Step 5: Integration.** Review GitHub Actions exact merged commit SHA: Foundation, signed runtime, Postgres 17 grant migrations and production frontend build if required by branch policy. All reported run conclusions must be success or explicitly blocked; missing = blocked.
- [ ] **Step 6: Commit passing deliverable.** Commit only workflow and gate documents for this task, with no release qualification claims.

### Task 2: Full Sing-box compiler and protected egress (separate reviewable PR)

**Files:**
- Create (proposed): internal/drivers/singbox/fullconfig.go
- Test (proposed): internal/drivers/singbox/fullconfig_test.go
- Modify (observed): internal/drivers/singbox/config.go
- Modify (observed): internal/networking/firewall.go
- Test (observed): internal/networking/firewall_test.go

**Interfaces:**
- Consumes: drivers.ComponentPlan, drivers.ConfigArtifact, drivers.BuildIdentity, manifest.Verified, and a new **locally trusted** typed Policy, never a caller's unconstrained Sing-box JSON.
- Produces (proposed): CompileFull(ctx context.Context, plans []drivers.ComponentPlan, policy ProtectedPolicy, build drivers.BuildIdentity) (drivers.ConfigArtifact, error). ProtectedPolicy belongs in internal/drivers/singbox; default denies private/metadata egress on both address families.

- [ ] **Step 1: Add focused failing tests.** Golden full-config JSON; deterministic digest across input order; protected IPv4/IPv6, metadata and DNS route denial; two listeners conflicting on port; missing outbound; unsupported version/key; hostile unknown top-level option; secrets absent from errors; manifest/build mismatches.
- [ ] **Step 2: Verify relevant failure.** Run: go test -count=1 ./internal/drivers/singbox ./internal/networking. Expected compile tests fail with an undefined CompileFull before implementation; existing Render fragment tests remain green.
- [ ] **Step 3: Implement minimum.** Convert bounded fragment artifacts into full native config using typed version-specific options (DNS, route, inbound, outbound, TLS, logging); enforce a protected egress guard before adding operator routes; stable deterministic serialization and SHA-256. Route exceptions are separately approved, explicit CIDR+reason and never wildcarded.
- [ ] **Step 4: Focused pass.** Re-run the focused tests; all malformed/secret/IPv6 cases pass without relaxing existing checks.
- [ ] **Step 5: Integration.** Run: make test-go; then signed native workflow must perform actual sing-box check on the generated full config, not only a fragment. A negative config must be rejected before a listener is restarted.
- [ ] **Step 6: Commit.** Commit only full config, protected policy and tests. Do not broaden protocol support until qualified.

### Task 3: Root-owned candidate activation with crash rollback

**Files:**
- Modify (PR #19/#21 branch-only observed): internal/agent/supervisorserver/server.go
- Modify (branch-only observed): internal/agent/supervisorserver/native.go
- Test (branch-only observed): internal/agent/supervisorserver/native_test.go, server_test.go
- Modify (branch-only observed): internal/agent/supervisoripc/client.go
- Modify (branch-only observed): internal/agent/state/activation.go
- Test (branch-only observed): internal/agent/state/activation_test.go

**Interfaces:**
- Consumes: immutable candidate generation (SHA-256 of protected root-approved bytes), exact LKG SHA-256, active fail-closed ActivationGuard, native build digest and fixed unit name.
- Produces (proposed): privileged apply-approved-candidate verb with only {version, operation, reference}; root independently authenticates peer and local allowlist. New ConfirmedActivation record must bind operation transaction to the guard and independent subsequent receipt.

- [ ] **Step 1: Add failing tests.** Reject wrong caller UID/GID, mismatched candidate hash, unallowlisted generation, forged local provisioning, wrong node, stale guard, duplicate concurrent apply, native check error, restart error, active file change and power loss after atomic rename. Crash must keep or recover the guard, never advance applied cursor.
- [ ] **Step 2: Verify relevant failure.** Run: go test -count=1 ./internal/agent/supervisorserver ./internal/agent/supervisoripc ./internal/agent/state. Expected new verb/guard tests fail on pre-feature supervisor.
- [ ] **Step 3: Implement minimum.** Add protocol versioned verb and server-enforced local generation allowlist; derive approved candidate from root-protected staged file + trusted manifest digest; validate signer/version, native binary and config; atomically activate; sync parent directory; restart fixed unit; preserve immutable former LKG until remote confirmation. A false check cannot clear the durable guard.
- [ ] **Step 4: Focused pass.** Tests pass including adversarial peer/provisioning cases.
- [ ] **Step 5: Integration.** Extend disposable CI host smoke to apply a candidate, SIGKILL mid-activation, prove independent watchdog restores the former LKG and refuses a stale commit.
- [ ] **Step 6: Commit.** Review privileges before merging; do not turn generic command execution into a root RPC capability.

### Task 4: Transactional applied journal and mTLS ACK

**Files:**
- Modify (observed): internal/agent/state/store.go, activation.go
- Modify (observed): internal/agent/reconcile/reconciler.go
- Create (proposed): internal/agent/gateway/desiredapi/applied.go
- Test (proposed): internal/agent/gateway/desiredapi/applied_test.go
- Modify (observed): internal/control/desiredpublish/publisher.go
- Test (observed): internal/control/desiredpublish/postgres_integration_test.go

**Interfaces:**
- Consumes: the signed revision scope, native candidate digest, independently accepted evidence digest and authenticated node TLS identity.
- Produces (proposed): CommitApplied(ctx, scope, receipt) which transactionally advances *only* the exact revision; POST /v2/nodes/self/applied with exact node mTLS identity, revision/epoch/sequence/candidate digest, monotonic node event ID and evidence digest; immutable receipt bound to control-plane transaction commit.

- [ ] **Step 1: Add failing tests.** Same revision repeated is idempotent; two different digests at same sequence conflict; remote ACK lost yields bounded retry and no local success; stale epoch rejected; two simultaneous ACKs one winner; unknown mTLS node and claim of other node rejected; crash after control commit before response recovers idempotently; stale candidate cannot become LKG.
- [ ] **Step 2: Verify relevant failure.** Run: go test -count=1 ./internal/agent/state ./internal/agent/reconcile ./internal/agent/gateway/desiredapi ./internal/control/desiredpublish. Expected absent ACK endpoint and commit operations to fail focused tests.
- [ ] **Step 3: Implement minimum.** Node commits applied state only on verified host+network witness and durable authenticated receipt, uses WAL transaction/single-owner fencing; control plane checks approved publication, epoch and exact manifest/candidate digest; ACK never contains private config.
- [ ] **Step 4: Focused pass.** All replay/concurrency/restart/forgery tests pass.
- [ ] **Step 5: Integration.** PostgreSQL 17 integration + real mTLS loop; disconnect control mid-ACK and confirm no false applied update. Run make test-go.
- [ ] **Step 6: Commit.** Keep separate from presentation-only changes and require review of all invariants.

### Task 5: Independent nonce-bound reference-client witness

**Files:**
- Create/continue (existing unverified development branch): internal/agent/healthattestation/attestation.go and attestation_test.go
- Create (proposed): internal/agent/healthattestation/durable.go, durable_test.go
- Create (proposed): lab/runtime/external-client-witness.sh
- Modify (observed): contracts/lab-evidence.schema.json
- Test (proposed): tests/contracts/external-health-evidence.test.ts

**Interfaces:**
- Consumes: authority-pinned Ed25519 reference client identity, node+epoch+candidate generation, nonce, observed data-path challenge/protected-route test suite digest, bounded deadline.
- Produces: VerifyWitness(ctx, signedEvidence) acceptance bound to durable one-time challenge record and cryptographically authenticated signer. This result is **an evidence input**, not an automatic release stamp.

- [ ] **Step 1: Add failing tests.** Replayed nonce, unknown key, wrong generation/epoch/node, missing proof, fake local SOCKS responder, prior expiry/future timestamps, forged or duplicate JSON keys, crash/restart persisted replay, report never observed by real reference client. A valid signature on a fabricated report must not be described as network proof.
- [ ] **Step 2: Verify relevant failure.** Run: go test -count=1 ./internal/agent/healthattestation; npm run check:contracts. Expected missing durable challenge and actual runner tests fail before implementation. Do not accept existing in-memory prototype tests as complete.
- [ ] **Step 3: Implement minimum.** Require challenge issued after activation by trusted server, persist nonce consumed state atomically, verify domain-separated signature, enforce unique run ID and bounded evidence schema; independent client sends real Reality/Vision traffic + controlled protected egress tests and reports sanitized transcript. Separate witness signing key must not live on target VPS.
- [ ] **Step 4: Focused pass.** All negative tests pass, including replay after restart, no signature bypass.
- [ ] **Step 5: Integration.** External network harness connects from a separate client machine/network using qualified reference clients. At least one known false-positive host-only scenario must fail the external witness. Run signed CI and capture sanitized exact binary/source digests.
- [ ] **Step 6: Commit.** Do not merge unverified earlier branch or claim M0 unless independently reviewed network evidence exists.

### Task 6: Reproducible public VPS acceptance and release evidence

**Files:**
- Create (proposed): lab/runtime/run-public-reference-client.sh
- Create (proposed): lab/runtime/reference-client-evidence-check.go
- Modify (observed): lab/gate.ts, contracts/lab-evidence.schema.json
- Modify (observed): docs/implementation/status.md

**Interfaces:**
- Consumes: qualified exact-head backend, signed runtime binary digest, actual external destination and authenticated reference-client evidence.
- Produces: redacted evidence bundle with source SHA, test protocol and artifact digest, timestamps, host/OS/network, successful client bytes, protected route refusal, restart/revoke scenario and reviewer verdict. Production gate only opens from inspected evidence, never a static test flag.

- [ ] **Step 1: Add failing tests.** Gate must refuse localhost-only, same-netns reference client, absent real transfer, unverifiable signer, mismatched runtime digest, missing protected IPv6 path and missing restore verification.
- [ ] **Step 2: Verify relevant failure.** Run: npm run gate:lab with synthetic/omitted proof. Expected nonzero blocked exit and explicit missing evidence.
- [ ] **Step 3: Implement minimum.** Disposable external host provision and teardown, independent client challenge, signed evidence collection, immutable digests, sanitized transcript, manual reviewer acknowledgment.
- [ ] **Step 4: Focused pass.** Negative gates fail with stable error identifiers; valid externally reviewed bundle is accepted only when all mandatory schema and transcript checks exist.
- [ ] **Step 5: Integration.** Run the complete public M0 matrix, failure injection (restart/SIGKILL/revocation), and compare actual accepted generation to durable cursor at exact SHA. Keep logs free of keys.
- [ ] **Step 6: Commit.** Update issue #14 with reviewed proof, retain M1/M2 blocked until their own tests finish.

## Dependencies and open decisions

**Order:** Task 1 -> 2 -> 3 -> 4 -> 5 -> 6, with Task 2 policy enforcement designed before privileged candidate apply. Independent service/operator UX work may proceed in parallel **without** impersonating applied state. For lower-effort route, Tasks 2 and 5 may independently start in TDD PRs, but may not be marked qualified before integration.

**Operator-visible unresolved seams:** first supported external test OS, reference client/platform versions, and whether a protected-private access exception is needed for deliberately hosted LAN services. These require explicit reviewed profiles; this plan defaults to denial, not a broad exception.

**Hard acceptance:** issue #14 remains open until actual public VPS + independent client evidence and subsequent M1/M2 gates are reviewed. This plan intentionally contains no commercial/reseller deliverable.
