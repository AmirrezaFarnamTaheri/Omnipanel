# Runtime Evidence and Driver Contract Implementation Plan

> **For agentic workers:** Use the host's available task-by-task implementation workflow. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a reproducible, fail-closed runtime laboratory and typed Go driver boundary that can support one real VLESS/Reality/Vision vertical slice without mislabeling synthetic checks as production qualification.

**Architecture:** Keep the existing signed, node-scoped `internal/manifest` as intent verification only. Put runtime render/validate/preflight/health/metering in bounded `internal/drivers` adapters, perform isolated Linux network-namespace tests before public VPS tests, and persist observable application results in a small SQLite-WAL agent journal. Unimplemented operations return typed unsupported-capability errors; no driver may accept arbitrary commands.

**Tech Stack:** Go standard library and exact runtime APIs, Sing-box source-pinned local build, GitHub Actions build provenance, Linux network namespaces/systemd, SQLite WAL, existing JSON Schema/OpenAPI contracts, Linux-hosted Go/race tests.

## Global Constraints

- No untrusted manifest may modify node configuration; signer, node, epoch, schema, build digest, allowed operations and effective ingress sockets are checked before staging.
- A build passing native syntax checking is not a real-client connectivity or quota-enforcement guarantee.
- Runtime processes remain separate systemd services and survive the agent's own restart.
- Keep ingress/egress restrictions, protected management reachability, known-good revision and explicit disruption class in every proposed plan.
- Report cumulative per-principal upload/download counters with process generation, direction semantics and observed gaps; no duplicate relay billing.
- Record credential removal effects for *new authentication*, *new streams on existing sessions* and *established streams* separately.
- Signatures, attestation and real client tests must be independently verifiable. Never use synthetic signer data to mark a build qualified.

---

## Observed inputs and evidence limits

Observed on unified PR #2: `internal/manifest/{types,verify,preflight,canonical}.go`, `internal/agent/sessions/registry.go`, `lab/runtime/{build-sing-box.sh,run-local-reality.sh,stats.proto,echo_server.py,socks5_probe.py}`, `contracts/desired-state.schema.json`, `contracts/lab-evidence.schema.json`, `capabilities/runtime.json`, `Makefile`. Go control-plane, runtime drivers, agent, privileged helper and durable journal are **proposed**, not implemented.

At commit `0b3932f`, the foundation check passed; runtime-smoke build succeeded, attestation failed, and downstream connection/counter tests were skipped. The workflow failure is a release blocker for evidence provenance, not grounds to turn off attestation. `make gate-lab` remains BLOCKED until external client/network, agent and Hysteria2 experiments are completed.

### Task 1: Restore independently verifiable runtime provenance

**Files:**
- Modify: `.github/workflows/runtime-smoke.yml` (observed)
- Modify: `lab/runtime/build-sing-box.sh` (observed)
- Create: `lab/runtime/verify-provenance.sh` (proposed)
- Create: `lab/runtime/verify-provenance_test.sh` (proposed)
- Modify: `lab/README.md` (observed)

**Interfaces:**
- Consumes: source-pinned upstream commit, exact build tags/toolchain, built binary, workflow identity and GitHub Actions artifact attestation.
- Produces: `verify-provenance.sh <artifact> <attestation-or-trusted-identity>` exit 0 only when artifact SHA-256 and independently trusted signer/source identity match; redacted provenance report.

- [ ] **Step 1: Add failing verifier tests.** Test a correct fixture; changed binary bytes; wrong commit/repository/signer; expired or absent trust; missing attestation. Nonconforming inputs fail nonzero with no success report.
- [ ] **Step 2: Verify relevant failure.** Run `bash lab/runtime/verify-provenance_test.sh`; expected: failure because the verifier has not been implemented. Retrieve the latest failed GitHub Actions attestation step logs and classify the actual permission/provenance error before changing workflow permissions.
- [ ] **Step 3: Implement smallest trusted verification path.** The observed GitHub Actions failure is specific: GitHub's attestation-storage API returns `Feature not available for user-owned private repositories`. Keep the source-commit verification and patch-pinned build. Sign both the binary and build metadata with keyless Cosign/Sigstore; verify both bundles against the exact workflow file, repository, triggering ref and GitHub OIDC issuer; verify the signed metadata's source commit, toolchain, build tags and artifact digest; retain the bundles as workflow artifacts. Fork PRs skip this identity-signing job. Never disable signature or digest verification, use `|| true`, or accept a different signer identity.
- [ ] **Step 4: Verify focused pass.** Run `make test-provenance` and `bash -n lab/runtime/build-sing-box.sh lab/runtime/run-local-reality.sh lab/runtime/verify-provenance.sh`; expected: valid artifact/metadata signatures accepted and digest mismatch, wrong version, missing bundle, signature failure, wrong workflow identity and symlinked inputs rejected.
- [ ] **Step 5: Run affected integration.** Re-run GitHub `Local Sing-box runtime smoke` with attestation verification; expected: both attestation steps pass, then the actual namespace/proxy tests are allowed to execute. Do not describe skipped tests as passed.
- [ ] **Step 6: Commit independently passing work.** Commit the verifier, tests, workflow fix and documentation together with `fix(lab): verify reproducible Sing-box build provenance`.

### Task 2: Introduce typed runtime driver contracts and first Sing-box adapter

**Files:**
- Create: `internal/drivers/driver.go`, `internal/drivers/errors.go`, `internal/drivers/types.go` (proposed)
- Create: `internal/drivers/singbox/config.go`, `internal/drivers/singbox/config_test.go` (proposed)
- Create: `internal/drivers/driver_test.go` (proposed)
- Modify: `contracts/runtime-registry.schema.json` only if an evidenced contract mismatch is found

**Interfaces:**
- Consumes: verified `manifest.Component`, qualified exact build identity, bounded typed configuration and designated component dependencies.
- Produces: a `Driver` with `Capabilities(context.Context, BuildIdentity) (CapabilitySet, error)`, `Render(context.Context, ComponentPlan) (ConfigArtifact, error)`, `Validate(context.Context, ConfigArtifact) error`, `Preflight(context.Context, ComponentPlan) (PreflightReport, error)`, `ClassifyDisruption(context.Context, ComponentPlan) (Disruption, error)`, `ApplyStructure(context.Context, ComponentPlan) (ApplyResult, error)`, `ApplyMembership(context.Context, MembershipDelta) (ApplyResult, error)`, `Health(context.Context) (HealthReport, error)`, `ObserveCounters(context.Context) (CounterBatch, error)`, `RevokeSessions(context.Context, []PrincipalRef) (RevocationReport, error)`, `Rollback(context.Context, ConfigArtifact) (ApplyResult, error)`, and `Diagnose(context.Context) (DiagnosticReport, error)`. Define these named request/result types in `internal/drivers/types.go`; `CapabilityError` must support `errors.Is(err, ErrUnsupportedCapability)`.

- [ ] **Step 1: Add failing tests.** An unknown build/digest is rejected; config rendering is deterministic; shell/command/path injection cannot appear as a typed operation; TCP/UDP listener conflicts are rejected; unsupported dynamic membership and session closure yield `ErrUnsupportedCapability`, not success.
- [ ] **Step 2: Verify relevant failure.** Run `go test ./internal/drivers/...`; expected: missing package/interface failure before implementation.
- [ ] **Step 3: Implement narrow behavior.** Add a typed capability declaration and Sing-box Reality/Vision renderer/validator referencing an exact qualified binary and only allowed configuration storage. Driver methods needing real systemd/helper execution return explicit unsupported until Task 4 provides verified execution. Do not create a generic `exec(string)` operation or trust runtime capabilities from manifest input.
- [ ] **Step 4: Verify focused pass.** Run `go test -race -count=1 ./internal/drivers/...`; expected: deterministic renderer and negative capability cases pass.
- [ ] **Step 5: Run affected integration.** Run `make test-go` and `make check-contracts`; expected: no regression in signature, socket or schema validation.
- [ ] **Step 6: Commit independently passing work.** Commit typed interface, tests and the first bounded adapter as `feat(drivers): define capability-gated runtime contract`.

### Task 3: Produce real-client, revocation and accounting lab evidence

**Files:**
- Modify: `lab/runtime/run-local-reality.sh`, `lab/runtime/socks5_probe.py`, `lab/README.md` (observed)
- Create: `lab/runtime/test-reality-revocation.sh`, `lab/runtime/test-hysteria2-comparison.sh` (proposed)
- Create: `testdata/golden/reality-vision/`, `testdata/golden/hysteria2/` (proposed; redacted, version-pinned fixtures only)
- Modify: `contracts/lab-evidence.schema.json` only for documented missing evidence semantics

**Interfaces:**
- Consumes: verified build provenance, exact runtime build/protocol, generated client config, unique probe principal, controlled network/test endpoint and the driver counter/revocation contract.
- Produces: machine-readable evidence with exact runtime+client version/digest, provenance, L1/L2/L3 results, tested packet impairments, known error bounds, counter directions/generations, revocation and reload effects, and redacted reproducible command transcript.

- [ ] **Step 1: Add failing lab assertions.** Cover successful native validation, real client import, authenticated L3 canary, intentionally invalid config preserving active listener, rejected removed credentials, continuing-vs-terminated existing stream, user-attributed uplink/downlink and process-generation reset; include blocked UDP, delay and loss against both embedded and standalone Hysteria2 candidates.
- [ ] **Step 2: Verify relevant failure.** Run the narrower preexisting `make test-runtime` on a privileged Ubuntu 24.04 amd64 lab host; expected: it cannot establish the complete asserted evidence for revocation and both Hysteria2 candidates before the new harness is written.
- [ ] **Step 3: Implement evidence capture.** Use real client/core binaries rather than string-only unit tests. Sample counters from the authenticating core, explicitly classify baselines and resets, include bounded payload error, and compare new/established sessions separately. Redact credentials and IP/user metadata from reports; never copy an unreviewed local report directly into the production capability registry.
- [ ] **Step 4: Verify focused pass.** Run `bash lab/runtime/test-reality-revocation.sh` and `bash lab/runtime/test-hysteria2-comparison.sh` in the documented lab; expected: each case emits a machine-readable measured result, or exits nonzero with an explicit unsupported/error classification.
- [ ] **Step 5: Run affected integration.** Run `make check-contracts`, `make test-contracts` and `make test-go`; expected: evidence schemas accept complete records and reject ambiguous or unsupported claims. Independently review any proposed registry promotion.
- [ ] **Step 6: Commit independently passing work.** Commit reproducible harness and redacted fixtures as `test(lab): measure client connectivity, revocation and metering`.

### Task 4: Journaled agent-initiated reconciliation skeleton

**Files:**
- Create: `cmd/omni-node/main.go`, `internal/agent/state/store.go`, `internal/agent/state/store_test.go` (proposed)
- Create: `internal/agent/reconcile/reconciler.go`, `internal/agent/reconcile/reconciler_test.go` (proposed)
- Create: `cmd/omni-confirm-watchdog/main.go`, `internal/agent/reconcile/watchdog_test.go` (proposed)
- Create: `lab/agent/mock-gateway.go`, `lab/agent/reconcile_integration_test.go`, `deploy/systemd/omni-node.service` (proposed)

**Interfaces:**
- Consumes: `manifest.Verifier.Verify([]byte) (manifest.Verified,error)`, explicit agent-issued authenticated polling, qualified driver, protected node-local storage and a mock gateway emitting scoped signed manifests and membership deltas.
- Produces: `state.Store` with durable `RecordReceived`, `RecordTransition`, `RecordComponentResult`, `CommitVerifiedCursor` and `LastKnownGood` methods; `reconcile.Reconciler.Apply(ctx, verifiedManifest) (DeploymentReport,error)`; commit-confirm watchdog over an independently owned process/service for network-affecting changes.

- [ ] **Step 1: Add failing tests.** Duplicate revision is idempotent; untrusted/lower revision cannot modify files; invalid preflight retains prior good config; agent crash/restart resumes from durable journal; simulated network-change failure triggers watchdog rollback without a running agent; protected management path remains untouched; core service survives agent exit.
- [ ] **Step 2: Verify relevant failure.** Run `go test ./internal/agent/state/... ./internal/agent/reconcile/... ./lab/agent/...`; expected: missing package and journal tests fail before implementation.
- [ ] **Step 3: Implement minimum safe flow.** Store the node's epoch, separate structural/membership cursors, component outcomes, pending observations and last-good artifact references in SQLite WAL. Drive the explicit `RECEIVED` through `VERIFIED` state machine; on failure emit `FAILED`, `ROLLING_BACK`, `ROLLED_BACK` or `DEGRADED_REQUIRES_OPERATOR` with evidence. Use generation directories, dependency ordering and narrowly allowlisted host operations; no arbitrary uploaded binary/file path. Schedule the network watchdog in an independent service, not an agent goroutine.
- [ ] **Step 4: Verify focused pass.** Run `go test -race -count=1 ./internal/agent/... ./lab/agent/...`; expected: deterministic restart/replay results and 20/20 injected crash states diagnosable and recoverable under the harness.
- [ ] **Step 5: Run affected integration.** Run `make test-go`, `make check-contracts` and a mock-gateway test proving **agent-initiated** reconciliation; expected: verified config remains active after agent restart and bad manifests have no host effects. Do not claim mTLS enrollment or live VPS network recovery until independently tested.
- [ ] **Step 6: Commit independently passing work.** Commit agent, WAL journal, independent watchdog and integration harness as `feat(agent): journal verified desired-state reconciliation`.

## M0 acceptance and mandatory exclusions

Task 1–4 success is a foundation for `gate-lab`, not automatic M0 acceptance. The gate remains BLOCKED until an authorized Ubuntu VPS, a reference client on a realistic external network, authenticated L2/L3, tested node enrollment/communication, last-good restoration and both Hysteria2 alternatives produce accepted versioned evidence. Do not advertise a working quota or failover mechanism from local namespace tests.

## Unresolved externally observable decisions

- Production exact Sing-box, Xray and Hysteria2 builds/patches must be selected from successful reproducibility and compatibility tests.
- Runtime-specific revocation SLA for existing streams must follow measured driver behavior; the default product contract only promises denial of new authentication where verified.
- The operator/security team must approve exposed lab destinations, trusted signing authorities and privileged systemd/nftables allowlists before any real-node testing.
- Hard quota and offline grace remain product/security decisions; this plan must not pre-activate them.


**Progress note (4 November 2026):** The reviewed Go driver interface and
fail-closed default adapter have been added in `internal/drivers` with
synthetic negative tests. The separate Sing-box renderer/native validation
and signed artifact provenance remain pending. This task is **not completed**;
the private GitHub attestation endpoint is not available in this user-owned
repository, and no production gate is unblocked.
