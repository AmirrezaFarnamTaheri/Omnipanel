# Implementation and verification status

As of 2026-11-04. **The isolated Sing-box Reality/Vision smoke passed; no M0 walking-skeleton, M1 or M2 production acceptance is claimed.**

## This increment

Implemented and locally exercised:

- Strict Draft 2020-12 schemas for desired-state envelope, endpoint IR, lab
  evidence, candidate runtime, exact client release and metering registries.
- Contract preflight: unknown-field/version rejection, safe integers, dependency
  graph validity, effective socket conflict checks and validity ordering.
- Pure ingress planner: TCP/UDP independence, IPv4/IPv6 wildcard and mapped-IP
  conflicts, explicit IPv6-only semantics, literal binding validation.
- Lab evidence loader: exact runtime/version/digest/platform matching, required
  claims, exact client-release references, metering contract references, 90-day
  freshness, latest-result handling, duplicate/ambiguous results, bounded local
  artifacts/digests and artifact symlink escape rejection. Passing accounting
  evidence needs measured bidirectional payloads within its declared error bound
  (at most 5% in this initial lab harness, not a billing SLA).
- Fail-closed legacy admission and subscription filtering: empty reviewed-build
  qualification set; historical notes cannot activate any driver or strict quota.
  Corrected BPB unmanaged-source labeling and removed its hard-quota candidacy.
- Candidate v2 OpenAPI and documented target architecture/threat model.

- Local runtime smoke harness added under `lab/runtime/`: a source-pinned
  Sing-box v1.14.4 build with `with_v2ray_api`, isolated server/client network
  namespaces, real Reality/Vision TCP proxy traffic and per-user counter
  comparison. The original GitHub attestation step failed because GitHub does
  not support storing attestations for user-owned private repositories. The
  replacement keyless Cosign/Sigstore workflow signs the binary and metadata,
  verifies exact workflow/ref identity and artifact digest, and retains both
  bundles. The complete authenticated local test later passed in
  [run 41809579179](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41809579179).
  This is local runtime evidence only, not M0 acceptance or external client qualification.
- Go `internal/manifest` verification core: strict typed envelope and canonical
  digest checking, Ed25519 trust, node/epoch authorization, time and replay
  checks, exact-build capability gating, dependency/port preflight and focused
  adversarial tests. This does not apply configuration or run an agent.

These are contracts and test infrastructure, **not a real network service**.
The schemas intentionally cover a narrow initial vocabulary; they do not define
all future membership, enrollment, quota, protocol or upgrade operations.

## Gate status

| Command | Status / meaning |
| --- | --- |
| `make check-contracts` | Local schema compilation + registry/unsigned fixture validity |
| `make test-contracts` | Local deterministic unit tests; includes synthetic evidence in isolated temporary directories |
| `make test-go` | Go manifest-verifier tests (including race detector) and vet; synthetic signer/manifest, no host actions |
| `make test-provenance` | Fail-closed verifier tests with mocked Cosign CLI; actual Sigstore signature verification is performed in the runtime workflow |
| `make test-runtime` | PASSED in GitHub Actions run 41809579179 (commit e97272f); local namespace-only Reality/Vision, raw TCP and per-user counter smoke; not M0 acceptance |
| `make gate-lab` | BLOCKED: no external VPS, reference application, agent pull/report, Hysteria2 comparison or reviewed production evidence |
| `make gate-control` | BLOCKED: Go secure service/DB/auth migration and integration harness missing |
| `make gate-agent` | BLOCKED: deployable agent/helper/drivers/recovery/lease harness missing |
| `make gate-subscription` | BLOCKED: native validators and real client conformance missing |
| `make gate-resilience` | BLOCKED: independent providers, real vantages/failover/soak missing |
| `make gate-security` | BLOCKED: hardening, key lifecycle, security verification missing |
| `make gate-dr` | BLOCKED: funded backup/PITR+key restore and epoch drill missing |

TypeScript typecheck passes. ESLint passes with two existing image-optimization
warnings. The obsolete Go scaffold (which had stale imports and constructors) has
been removed. A standalone Go manifest-verification library and local Sing-box
runtime smoke are now present, but no deployable Go agent or control-plane
implementation exists. No public VPSs, representative mobile/desktop clients,
provider diversity or production topology are available for external connectivity
or production verification. The local runtime smoke passed in run 41809579179,
including independently verified keyless Sigstore/Cosign bundles and authenticated
Reality/Vision connectivity. This does not satisfy external connectivity,
client qualification or production recovery evidence.

The old pg-mem E2E script was retired because it bypassed real transaction/
concurrency primitives and its admission assumptions conflict with fail-closed
runtime qualification. Real database and networking tests remain outstanding.

`npm audit` reports 22 unresolved vulnerabilities in the legacy dependency tree
(19 moderate, 2 high, 1 critical at inspection), including Next.js/PostCSS/sharp.
New direct harness dependencies are patch-pinned; this change is not dependency
security sign-off. Upgrade or retire the affected prototype dependencies with
regression checks before any exposure. Never run an uncontrolled major-version
`audit fix --force` as a substitute for review.

## Next bounded increments

1. **Task 1 real lab:** provision Ubuntu 24.04 amd64 lab node and reference client;
   select exact signed runtime builds; implement typed render/validate/driver
   contracts; prove one user Reality/Vision L3, revocation/session effects,
   attributable counters, outbound agent pull/report and last-good recovery.
   Compare both Hysteria2 implementations, including UDP impairment and reload
   generations. Record native validators and redacted reproducible transcripts.
2. **Contract freeze and Task 2:** patch-pin a supported Go toolchain/PostgreSQL,
   implement service entrypoints with isolated identities, organization-
   scoped schema, MFA/bootstrap/RBAC/CSRF, endpoint-secret lifecycle, concurrent
   revisions/idempotency, transactional outbox+audit, signer/PKI and mTLS enrollment.
   Generate server/client types; migrate static UI to Vite without independent auth.
3. **Task 3:** SQLite WAL journal and metering queues, typed helper, independent
   systemd units, generation configs, external commit-confirm watchdog, separate
   structural/membership streams, accounting continuity/dedup and measured local
   entitlement behavior. No hard quota until bounded lease/session tests pass.
4. **Task 4 M1:** two independent providers/ASNs, real multi-vantage L2/L3 probes,
   client compatibility/conformance, authenticated independent mirror, canary
   rollout, load/chaos/24h soak, keys+PITR restore and compromise runbooks.
5. **M2 separately:** XHTTP, CDN, one-hop relay, approved alternate egress and
   restricted external BPB. Gate each before including it in subscriptions.

Do not publish production golden configs, support claims, quota bounds, uptime,
RPO/RTO or benchmark numbers until the corresponding real evidence exists.

## Repository consolidation and cleanup

The stacked foundation PRs were unified without merging either into the default
branch. Removed non-operational milestone-specific integrations, fabricated demo
runtime state, the duplicate login route with hard-coded demo credentials, the
no-op settings mutation and the non-buildable Go scaffold. Settings are now
explicitly read-only, and the main navigation reports prototype status rather
than a fabricated operational signal. The historical optional-integration SQL
migration remains in place to avoid breaking already-migrated databases.

A tracked development key was removed from the working tree. Revoke or rotate
keys and affected credentials in any environment that consumed it; Git history
still contains the prior blob until separately remediated. No production safety
claim follows from the cleanup. End-to-end validation requires CI and a real
networking laboratory.


The local runtime smoke is intentionally separate from the evidence gate. It
uses a source-pinned custom Sing-box build and a synthetic local echo target. Its
report is written under ignored `.data/lab-runtime/evidence/`; it is not copied
into `capabilities/runtime.json`, `capabilities/clients.json` or the reviewed
lab evidence registry. A green smoke workflow does not make the runtime
production-qualified.

## Selective S-UI / 3X-UI integration increment

The source audit and adoption decisions are documented in
`docs/research/source-project-review.md` and ADR 0002. Both reference projects
declare GPL-3.0 and their READMEs warn against production use. No source code was
copied or vendored.

Implemented:
- `src/lib/protocol-compatibility.ts` provides a narrow explicit matrix for
  sing-box/Xray VLESS Reality/Vision over TCP and sing-box/standalone Hysteria2
  over UDP. It validates server name, Reality public key, short ID, flow and
  fingerprint before subscription IR admission.
- `src/lib/subscription.ts` now excludes incompatible endpoint configurations
  with an explicit reason before any emitter can see them, rejects paths
  unsupported by the requested output format, and requires verified exact-release
  client compatibility evidence before client-specific admission. VLESS/Reality/Vision keeps one
  canonical protocol ID across Sing-box and Xray rather than a stale
  runtime-specific alias.
- `internal/agent/sessions` tracks opaque runtime session IDs, endpoint-principal
  identity and credential generation. It distinguishes successful closure from
  sessions that can only be blocked from opening new routed flows. Close callbacks
  run outside the registry lock; idle sessions are pruned and failed closers are retried.

The new Go registry and TypeScript compatibility tests are synthetic unit tests.
The session registry is not yet connected to Sing-box, Xray or Hysteria2 drivers;
the protocol matrix is not exact-build qualification. No new runtime, client,
metering or production capability is activated by this increment.

Deferred from the source review: deterministic host ordering and per-format
exclusions, client-side balancer documents/observatory, event streaming, bulk
lifecycle/renewal and dry-run-first S-UI/3X-UI migration.

## Runtime provenance blocker (4 November 2026)

[Runtime smoke run 41735253666](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41735253666)
built the pinned Sing-box artifact, then failed at GitHub's `attest-build-provenance`
step: `Feature not available for user-owned private repositories`. Go setup,
Linux dependencies, script checks and compilation passed; **no real networking,
revocation or accounting tests ran** in that workflow. This is an external
attestation-persistence limitation, not proof of runtime failure or success.

Do not skip provenance verification, mark the runtime qualified, or weaken the
production gates. A replacement keyless Sigstore/Cosign workflow now signs the
binary and metadata and validates their bundles against the repository workflow
identity. The signing and verification stages passed in run 41738645706; the
subsequent connectivity and accounting stages require separate successful results.
This is still a local test, not production runtime qualification.

## Capability-gated Go driver interface (foundation only)

The `internal/drivers` Go package introduces typed inputs and outputs for
runtime rendering, native validation, preflight, structural application,
membership, health, metering, revocation, rollback and diagnostics. The
`Unsupported` adapter returns a typed `ErrUnsupportedCapability` for **all**
operations. Unit tests exercise every method and prevent false-success no-ops.

This is a contract skeleton, **not** a Sing-box/Xray/Hysteria2 runtime adapter.
No binary has been accepted, rendered or applied, and no native validation,
quota guarantee, ingress policy, real session revocation or lab gate is passed.
The separately approved and authenticated runtime-driver implementations must
supply these behaviors, with explicit release evidence.

## Sing-box Reality/Vision inbound fragment renderer (foundation only)

`internal/drivers/singbox` supplies a deterministic, strictly typed
VLESS/Reality/Vision **inbound fragment** renderer. It checks the referenced
verified manifest decision, pinned runtime build identity, matching listener,
allowlisted protocol capability, protected-egress policy marker, member IDs,
UUIDs, short IDs, and Reality key encoding. Stable member sorting and
input-rejection tests are included. The emitted artifact contains secrets; it
must never be logged or returned to untrusted callers.

This renderer **does not emit a deployable complete configuration**: it has no
route/outbounds, no on-host firewall protection, no native Sing-box validation,
no privileged helper, and no reconciliation/rollback. `Validate`,
`Preflight`, `ApplyStructure`, metering and revocation still return
`ErrUnsupportedCapability` on this adapter. Native binary validation and representative external-client evidence remain
unqualified. Keyless Sigstore provenance is available for local lab experiments,
but neither it nor this renderer proves deployable network-service behavior.

## Local Reality runtime smoke failure and build-tag correction (4 November 2026)

The first Sigstore-signed runtime attempt
([run 41738645706](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41738645706))
passed compilation, signing, bundle verification and upload but failed on
Sing-box startup: `uTLS, which is required by reality is not included in this
build, rebuild with -tags with_utls`. No actual L3 connectivity or counter
measurement completed in that run. The source-pinned lab build has therefore
been revised to `1.14.4+omni.2` with both `with_utls` and `with_v2ray_api`.
The Sigstore-verified signed metadata and negative tests require exactly both
tags; a build missing either is rejected. The next runtime run must establish
independent success before lab evidence can be reviewed. M0/M1 gates remain
blocked regardless of a successful local namespace run.

## Runtime version handshake regression (4 November 2026)

The next signed runtime run (41739272066) passed binary build, signing, and
signature verification, but its smoke runner still required the prior custom
version `1.14.4+omni.1`; it stopped at its version check before any L3 test.
The runner is updated to `1.14.4+omni.2` and provenance tests now assert exact
version agreement across the builder, signed metadata fixture and smoke runner.
The new run must still pass connectivity and metering before local lab evidence
can be recorded.

## Reality client uTLS setting (4 November 2026)

After the binary included `with_utls` and provenance passed, the local smoke
run (41739951775) reached client startup but Sing-box rejected the outbound
with `uTLS is required by reality client`. The fixture previously omitted the
client-side `tls.utls.enabled` and fingerprint fields. The client fixture now
sets `utls: {enabled: true, fingerprint: "chrome"}`, and a structural check
asserts that required client configuration before native validation.
That historical run was not a successful authenticated traffic transfer or
accounting result; the later run 41809579179 established the limited local
smoke result described below.

## Verified isolated Reality/Vision smoke and explicit SNI contract (4 November 2026)

[Runtime smoke run 41809579179](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41809579179)
completed successfully at commit `e97272f`. It built the source-pinned
`sing-box 1.14.4+omni.2` with both required tags, verified keyless Sigstore
signatures for the binary and build metadata, and executed a real
VLESS/Reality/Vision server and client in two isolated Linux network
namespaces. The controlled raw TCP echo check transferred **1,048,576 bytes
per direction**; the authenticating runtime reported 1,048,576 uplink and
1,048,576 downlink bytes (0% measured payload error in this single experiment).
The native checker rejected a deliberately unsupported inbound type without
interrupting the already running service. A core restart terminated the
observed established session; the removed UUID failed to reconnect and the
replacement UUID succeeded. This does **not** establish hot user removal,
billing-grade accounting or hard quotas.

That experiment also resolved a server/client Reality SNI mismatch: the
inbound must explicitly declare the accepted `tls.server_name`, which is
distinct from the decoy handshake destination. The typed Go
`internal/drivers/singbox` inbound-fragment renderer now accepts a bounded,
explicit `ServerName`, emits it as `tls.server_name`, and rejects missing,
malformed, IP-address and invalid-label values. A regression test first failed
on the omitted SNI before the renderer change. The renderer remains
**non-deploying**, with native preflight, structural application, session
revocation, metering and rollback unsupported. Check CI on the current PR HEAD
before interpreting Go test status as green.

This evidence is local to Linux namespaces and the Sing-box CLI client.
Public VPSs, exact external clients, Hysteria2 comparison, agent-initiated
reconciliation, durable last-good rollback, real packet impairment and all
M0/M1/M2 production gates remain blocked. Do not promote the report into a
production capability or client registry.

## Protected SQLite WAL journal foundation (4 November 2026)

The first bounded part of the journaled node-agent task has landed in
`internal/agent/state`. It uses pinned `github.com/mattn/go-sqlite3 v1.14.52`
(with verified Go module checksums and a CGO-capable Linux build) and
requires an existing owner-only journal directory. The SQLite database is
created with mode `0600`, refuses symlinks and permissive storage, and
enforces `journal_mode=WAL` with `synchronous=FULL`. A persisted
node ID and authorized control-plane epoch prevent a different caller from
silently taking over the same journal.

`RecordReceived` accepts only an already-verified desired-state result
from the separately trusted `manifest.Verifier.Verify` boundary. It
records a monotonically increasing structural revision, membership cursor,
content digest and `RECEIVED`/`VERIFIED` stage; exact repeats are
idempotent and conflicting or lower revisions fail closed. The journal
survives closing and reopening its database. **A verified revision does not
advance the applied cursor**, and the last-known-good reference remains empty
until a real, separately verified apply/confirm implementation exists.

The new store was implemented with red-green tests: the initial tests failed
against an unimplemented journal; the later
[foundation CI run 41813868712](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41813868712)
passed Go race tests, `go vet`, TypeScript contracts and lint.
A Go 1.27 test-fixture permissions issue was fixed by using a private `0700`
subdirectory; **production permission checks were not weakened**.

This is **not** a deployable agent or a completed Task 4. There is no
deployed node gateway/enrollment service, runtime application helper,
separate structural/membership delivery, per-component apply journal,
network commit-confirm watchdog, autonomous rollback, restored last-good
generation or crash-injection matrix. The verification-only polling processor and a local mTLS transport test client
are now separate additions; real credential enrollment, deployed gateway, host
application and recovery must not be inferred from the durable journal. All production gates remain BLOCKED.

## Four-panel reference assessment and verification-only node polling (4 November 2026)

The supplied S-UI, 3X-UI, Hiddify-Manager and 1Panel forks were reviewed at
specific source commits in the
[four-panel integration assessment](../research/four-panel-integration-assessment.md).
This is a source/design review, not production qualification or a code import.
The root repositories each contain GPL-3.0 licenses; the separate
Hiddify-Panel submodule and any separately licensed/proprietary features
require their own review. In particular, 1Panel's current README identifies
multi-node management as outside its free OSS edition. No third-party source
files or scripts were copied into OmniPanel.

`internal/agent/reconcile` now provides a **verification-only** `Processor`
with an injected, caller-authenticated `AuthenticatedPuller` interface.
`PollOnce` requests the configured node's desired state, and `Process`
uses the trusted `manifest.Verifier.Verify` before recording a revision
in the private SQLite WAL journal. Duplicate signed intent remains idempotent;
invalid signatures, other-node manifests and lower revisions are rejected.
A restart reopens and replays journaled `VERIFIED` intent without modifying
the applied cursor or last-known-good state. The initial tests used an
injected mock puller; separate local HTTPS/mTLS tests were added later,
without deploying enrollment or a production gateway.

The failing test was first observed in
[foundation run 41815727545](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41815727545)
against an explicitly unimplemented processor. The implementation then
passed its behavior, Go race and contract tests in
[foundation run 41815886651](https://github.com/AmirrezaFarnamTaheri/Omnipanel/actions/runs/41815886651).
A dedicated `gofmt` gate covers the new Go package; the latest branch-head
CI status must be inspected separately after subsequent formatting/doc edits.

**Not yet implemented:** deployed mTLS gateway, certificate enrollment/revocation or trusted node identity mapping; agent daemon,
poll loop/backoff, separate structural/membership streams, trusted component
staging/preflight, on-host helper or service execution, independent watchdog,
observed deployment cursor, last-good commit/rollback, crash-injection matrix,
full external-client/Hysteria2 lab, or production qualification. All M0/M1/M2
production gates remain BLOCKED.

## Bounded authenticated desired-state fetcher (4 November 2026)

The new `internal/agent/gateway` client implements the approved draft
`GET /v2/nodes/self/desired` transport seam using real HTTPS and TLS 1.3
mutual certificate authentication. Configuration is supplied by a trusted
provisioning caller, **never** from an untrusted manifest. It requires an
explicit CA PEM, a client-auth certificate and matching key, a fixed HTTPS
origin without URL credentials or caller-controlled route/query, and rejects
ambient proxies, redirects and compressed responses. Requests carry the
authorized `controlPlaneEpoch` and the node's separate **applied** structural
and membership cursors. The path uses `self`; the gateway must derive the
node's identity from the validated client certificate rather than any
untrusted node ID header or path parameter.

Only a successful HTTP 200 JSON response with private/no-store cache policy
may return a bounded desired-state envelope (default 1 MiB, hard ceiling
4 MiB). An HTTP 204 is a typed `ErrNoChange` result. Untrusted response
bodies and status errors are not logged or retried automatically.
`internal/agent/reconcile` verifies signed content before SQLite writes;
neither HTTP 200 nor 204 commits an observed apply cursor or last-good
generation. The gateway's certificate **revocation, enrollment and node-to-
certificate authorization policy** require a real server implementation;
the mere existence of a client certificate does not satisfy those gates.

The mTLS package was developed with locally observed red/green focused tests:
`go test -race -count=1 ./internal/agent/gateway` and `go vet` passed
in an isolated scratch module. The first transfer into GitHub introduced an
accidental extra UUID regex segment; Go CI caught the regression and it was
corrected at `0d52eb9`. The epoch-cursor/204 tests first failed against the
old processor, then the behavior was updated at `3f10277`.
`mtls_integration_test.go` now composes an in-process mTLS gateway simulator,
signed manifest verifier and protected SQLite WAL journal, requiring the
observed cursor to remain unchanged. Inspect the final **PR-head CI** for
actual repository-wide pass/fail status; a green local client test is not
a production network security claim.

Production gates remain BLOCKED: no deployed gateway, enrollment or
revocation, no actual daemon/poll scheduler, no privileged apply,
native driver activation, independent rollback watchdog, multi-node
reconciliation, external VPS client qualification, or M0/M1 acceptance.


## Bounded node-enrollment authority and credential ledger (4 November 2026)

`internal/pki/enrollment` now contains an issuer-side **library only**. It
generates 256-bit bearer token grants (store only SHA-256 token digests);
verifies bounded Ed25519/P-256 CSR proof-of-possession; derives the node UUID
solely from a short-lived, single-use authorized grant rather than the CSR's
subject/SAN claims; and emits a client-auth-only URI-SAN certificate with a
maximum 24-hour lifetime under a caller-provided CA signer. It rejects a
mismatched signing key, expired authority, malformed CSR and replayed token.
Token expiration is re-evaluated at the atomic redemption to prevent a
certificate issuance delay from extending the grant's lifetime.

`SQLStore` records the grant consumption and certificate registration in a
single transaction, and tracks node/serial/key-specific revocation. The
candidate PostgreSQL migration is `db/migrations/0003_agent_enrollment.sql`;
it is not a migration of legacy browser-panel identities to the new UUID
model. The SQL integration tests use SQLite as a local transaction surrogate;
**no deployed PostgreSQL instance or recovery failover is qualified**.

Enrollment key material must be protected by a separately authorized issuer
service. The included `AuthenticatePeer` helper requires verified TLS 1.3
chains and an active, unrevoked node-certificate ledger entry. It is not
wired to a public gateway; authorization checks for administrative grant
creation, identity enrollment, issuer custody, renewal, CA rollover and online
revocation distribution remain to be implemented and independently tested.
No node enrollment service is deployed, no runtime configuration is applied,
and all production acceptance gates remain BLOCKED.

This code was developed with locally observed failing and then passing Go
race-enabled tests for one-time grants, CSR impersonation, revocation and
expiration during issuance. **Check the current PR-head CI** for Go, formatting, TypeScript and Sing-box
results. PostgreSQL migration semantics now have a separate disposable-server
CI gate; production migration and restore/PITR remain unqualified.

## TLS bootstrap enrollment handler and PostgreSQL integration gate (4 November 2026)

`internal/pki/enrollment/httpapi` adds a bounded **non-deploying** HTTP
bootstrap exchange at `POST /v2/nodes/enroll` and a separate OpenAPI
operation with bearer-token authentication overriding the node's mTLS-only
desired-state API. The handler requires direct TLS 1.3, the 43-character
single-use bearer header, exactly one bounded `csrPem` JSON field,
and a caller-injected **fail-closed** rate-limiter. It ignores forwarded
client-cert and forwarded IP identity claims; no request-controlled node ID
is accepted. Errors are short generic RFC 9457 problem JSON with
`Cache-Control: private, no-store` and never reflect tokens, CSRs or signing
errors. The handler has tests for a real TLS 1.3 handshake, valid token-bound
certificate issuance, replay, malformed/duplicate JSON, untrusted headers,
limiter outage and signing error sanitation.

`.github/workflows/enrollment-postgres.yml` adds a separately gated,
**disposable** PostgreSQL 17 integration job. It applies the exact
`0003_agent_enrollment.sql` migration and checks `SQLStore` one-time
consumption, certificate scope/revocation, rollback after injected insert
failure, concurrent redemption and bytea digest constraints using a pinned
test-only PostgreSQL driver. This is not proof of production PostgreSQL
PITR, failover or an approved node registry.

**Unimplemented:** a runnable enrollment service and protected signer
process, administrator grant approval/audit, shared limiter deployment/key custody and edge protections,
issuer custody/rotation, certificate renewal and online revocation delivery,
node identity-to-organization mappings, disaster recovery, privileged host
apply or a crash-surviving rollback watchdog. Do not promote this endpoint
library or the local database test into production acceptance.
CI for the current PR head must pass before this increment is considered
verified. All M0/M1/M2 production gates remain BLOCKED.


## Shared PostgreSQL enrollment admission limiter (4 November 2026)

`internal/pki/enrollment/httpapi/pg_limiter.go` introduces a
non-deploying, dependency-injected PostgreSQL `Limiter`: transactional
fleet-wide and canonical peer-IP 60-second budgets use the **database clock**
and durable rows to prevent per-process reset. The only stored peer
identifiers are fleet-keyed HMAC-SHA256 digests. Invalid IPs and unavailable
PostgreSQL storage are refused. A denied peer does not consume the shared
global counter because the combined transaction rolls back. Bypass attempts
using client-supplied forwarded IP headers remain ineffective in the existing
TLS enrollment handler. A trusted explicit pruning operation removes
windows older than 24 hours; it does not run automatically.

Migration `0004_agent_enrollment_rate_limits.sql` and a tagged integration
test extend the existing disposable PostgreSQL Actions job. The test checks
atomic cross-instance budgets, concurrency near a global threshold,
forwarded header spoofing, migration constraints, DB outage failure and
pruning. Local red/green tests for configuration rejection and canonical
HMAC peer identity passed with race detection. **Final PR-head CI is required
before claiming the PostgreSQL integration is green.**

There is still no configured HMAC key management, deployed gateway, actual
administrator-approved grant workflow, edge rate controls, CA key custody,
cert renewal, multi-gateway revocation delivery or privileged agent apply.
All production acceptance gates remain BLOCKED.

## Administrator-authorized single-use grant foundation (4 November 2026)

`internal/pki/enrollment/grants` adds a **non-HTTP** PostgreSQL issuer
requiring a live owner session, bounded session idle/absolute age, a recent
trusted TOTP step-up record, organization-level grant permission, an explicit
v2 UUID-to-legacy integer node binding, and a different authorized approver.
The legacy node must still be pending enrollment. It makes a grant, its digest,
organization/actor/session metadata and append-only audit entry atomically:
storage failure or duplicate/pending grants return no bearer.

Migration `0005_agent_admin_grants.sql` adds the namespace, approval scope
and audit schema; a tagged PostgreSQL integration test exercises genuine
SQL constraints, competing calls, session and node rejection and audit
rollback. The unsafe exported `SQLStore.CreateGrant` convenience method is
removed from production and replaced by test-only fixture provisioning.

**Production blockers:** a real owner authentication/MFA step-up route,
authorized organization/node approval writes, safe one-time token delivery,
redemption-time revocation/scope recheck, CA key custody, certificate
rotation, durable independent apply/rollback and the real legacy `0001`
schema migration verification. The integration test deliberately uses only
the legacy columns required by this library, and does not certify complete
migration of the Next.js prototype database. No control-plane listener,
host agent apply, or release gate is enabled. Check final PR-head CI before
calling this integration verified.

## Redemption-time approval revalidation (4 November 2026)

A proposed `ApprovedSQLStore` wraps the previously unaudited generic
certificate ledger with a PostgreSQL approval gate. It only accepts
single-use grants that have a matching persisted issuance audit, a live
legacy node UUID binding, an active organization, current issuing and
independent-approver scopes, and an unexpired issuer session. `Lookup`
runs the preliminary check; `Commit` revalidates under row locks, consumes
the token and registers the certificate atomically. Active certificate
admission also checks the current organization, approved binding and
legacy node state so a quarantined node is not admitted merely because its
certificate has not expired.

The regression test first failed against the unprotected SQLStore on a
real PostgreSQL 17 test service: revoking the binding between lookup and
commit still produced a certificate. A corrected, fail-closed adapter and
additional negative tests now require *final-head CI verification*.
No public endpoint is wired to this adapter yet, and the unapproved raw
SQLStore remains available only for backward-compatible ledger fixtures.
This is **not** a deployed issuer, PKI rollover, secure operator approval
writer, or distributed revocation acceptance test. All production
acceptance gates remain BLOCKED.

## Logout-safe grant revocation (4 November 2026)

Migration 0005's RESTRICT foreign key from `agent_grant_issues.session_id`
to `admin_sessions` made administrator logout impossible once any issuance
history existed: deleting the session row failed with a foreign-key
violation. The forward-only `0006_agent_grant_logout_revocation.sql`
records the issuing session's credential hash as an immutable issuance
fact (backfilled from the still-referenced session rows, which the 0005
RESTRICT key guarantees exist), drops that referential link, and makes
`agent_grant_issues` append-only like `agent_grant_audit`.

`ApprovedSQLStore` now requires the issuing session to exist with the
exact recorded credential hash, both at lookup and again under the
certificate-commit row locks. Logout therefore invalidates every
outstanding token from that session immediately, and a later login that
recycles the deleted serial session id cannot resurrect an old bearer.
Step-up rows already cascade on session deletion. Already-issued node
certificates are intentionally unaffected by administrator logout: online
admission keeps depending on the approved binding, organization and legacy
node status. Issuance and audit history are preserved verbatim.

The defect was reproduced locally on a disposable PostgreSQL 16.2
instance: logout was rejected under the 0005 schema, then accepted after
applying 0006 over pre-existing history with a correct credential-hash
backfill. The extended tagged integration suite proves that an outstanding
token fails closed at lookup and at commit after logout and is not
consumed, that history rows survive unchanged and reject UPDATE/DELETE,
that a recycled session id cannot re-authorize the old grant, and that a
fresh login can still issue new grants. The narrow gofmt failure in the
grants integration test is corrected in the same increment. **Final
PR-head CI on the PostgreSQL 17.6 service remains the verification gate.**
No trusted logout writer or session HTTP API exists yet; the regression
performs the same session-row deletion a future session service will
execute. All production acceptance gates remain BLOCKED.

## Four-panel selective adoption increment (4 November 2026)

The four supplied reference forks (S-UI, 3X-UI, Hiddify-Manager, 1Panel)
were re-fetched and re-verified at the pinned revisions in
`docs/research/four-panel-integration-assessment.md`; all heads are
unchanged and the Hiddify-Panel submodule (CC BY-NC-SA 4.0) remains
excluded. Three bounded behaviors were adopted as independent, tested
implementations — no source was copied or vendored:

- `internal/agent/metering`: a fail-closed traffic accumulator absorbing
  S-UI's destructive-drain retention and bounded folding lessons, extended
  with generation-scoped counters, idempotent drain replay, stale-generation
  and counter-regression refusal, explicit pending-window capacity and
  absolute-total flush semantics for idempotent stores. This is an
  in-memory foundation, not billing-grade accounting; durable delivery,
  restart rehydration and runtime wiring remain blocked.
- `internal/agent/state`: the SQLite journal now verifies caller ownership
  (uid, not just mode bits — studied from 1Panel's agent socket checks) of
  its parent directory and database, and refuses hostile `-wal`/`-shm`
  sidecars before open. Symlinked, permissive, non-regular and foreign-owned
  companions fail closed with tests.
- `tests/contracts/subscription-determinism.test.ts`: 3X-UI's deterministic
  ordering discipline is pinned as regressions — byte-stable emitters,
  exact IR-order preservation, stable per-format exclusion diagnostics and
  refusal of diagnostic-carrying IRs.

The Foundation gofmt gate now covers the new metering package. Local Go
race/vet/gofmt and the TypeScript contract suite pass; final-head CI
remains the verification gate. No production capability, deployed service
or release gate is promoted by this increment.

## Verified MFA step-up writer boundary (4 November 2026)

`internal/pki/enrollment/grants/stepup.go` adds a **non-deploying** TOTP
step-up verification service. It derives the session/owner from a valid
live legacy `admin_sessions` credential, obtains the current time from
PostgreSQL, and requires an externally injected `TOTPSecretOpener` to
decrypt the existing encrypted administrator TOTP secret. It verifies
RFC 6238 HMAC-SHA1, six-digit, 30-second codes with a ±one-step window,
enforces a monotonic counter across all sessions for that admin, and
persists failed attempts under a shared five-minute per-admin budget.
Missing KMS, database, owner session or factor authorization fails closed.

Forward-only migration `0007_agent_grant_verified_stepup.sql` adds
`verified_source` (default `legacy`) and `verified_counter` to step-up
records, plus durable replay counters and attempt windows.
`grants.Service.Issue` now requires
`verified_source='trusted'` and a persisted counter, preventing a legacy
manually populated step-up timestamp from satisfying enrollment-grant
authorization by default. A PostgreSQL integration regression exercises
legacy rejection, a verified owner session, bad factor, replay within/across
sessions, role demotion and exhausted attempt budgets.

## Backup task durability follow-up (4 November 2026)

Advanced the previous in-memory task contract with `internal/backup/repository.go`:
SQLite WAL plus `synchronous=FULL`, caller-owned private absolute directory/database
checks, regular-file and private-mode validation for database and `-wal`/`-shm`
sidecars, serialized lifecycle updates, and state/timestamp compare guards. Tests
prove repository reopen persistence, required durability PRAGMAs, duplicate and
missing ID behavior, and rejection of permissive directories/files and symlinked
WAL sidecars. This is a durable local task-metadata ledger, **not** a backup
engine, artifact store, key recovery system, distributed lease, or PostgreSQL
outbox; process-wide multi-writer coordination and power-loss filesystem testing
are not claimed. Backup providers, encryption, restore verification drills and
PITR remain open. All production gates remain BLOCKED.

## Read-only node resource snapshot contract (4 November 2026)

Added `internal/observability` as a small 1Panel-monitoring-informed contract:
bounded node/generation identity, sample timestamp, finite CPU percentage,
non-overflowing memory/filesystem values, unique filesystem/interface IDs, and
fresh/stale/unknown classification. Invalid and future samples are `unknown`;
resource freshness says nothing about proxy listener reachability, traffic,
client connectivity, enforcement, or billing. No host collector, process data,
filesystem probing, firewall access, persistence, or alert delivery is wired.
Tests exercise bounds, duplicates, stale/future cases and the explicit separation
from proxy health. The Foundation gofmt list now includes this package. Firewall
inventory and other operations remain deferred; production gates are unchanged.

## Bounded node-feed page contract (4 November 2026)

Added `internal/agent/syncfeed` following the Hiddify node-feed review: pages
carry a base/next cursor, bounded records, explicit tombstones, contiguous
sequence checks, duplicate-ID rejection, payload/record caps, and a deterministic
length-prefixed ordered digest. Sequence gaps return a distinct resynchronization
error. The digest is an integrity checksum only, **not authentication or a
signature**. The package neither persists cursors nor applies membership, and
is not connected to manifest verification, gateway polling, PKI/cert inventory,
or a running node. Race-tested validation covers page shape, sequence, tombstone
semantics, digest, identity and bounds. Foundation gofmt gate includes the
package; enrollment/authentication, durable cursor, full snapshot resync and
certificate inventory remain open.

**Unimplemented:** a protected real `TOTPSecretOpener` backed by deployed
key custody, trusted HTTP/CSRF and origin boundary, full legacy schema
qualification, approval writer, token delivery, production rate/availability
tuning and HSM-backed certificate issuer. CI on the final PR head is required
before marking these library contracts verified. M0/M1 production gates
remain BLOCKED.

## Subscription metadata and expiry-presentation contract (4 November 2026)

Added `src/lib/subscription-profile.ts` with client metadata header validation:
UTF-8 base64 Profile-Title/Announce encoding, HTTPS-only Support-Url and
Profile-Web-Page-Url, length bounds and control-character rejection. The public
subscription route now uses base64 title metadata and a shared Subscription-
Userinfo formatter. Expiry remains canonical in storage; the pure formatter
supports exclusive (default) and inclusive presentation (minus one displayed
second) without mutating the source Date. Contract tests cover UTF-8, CRLF and
unsafe-URL rejection, expiry boundaries, absent expiry and invalid counters.
Optional URLs/announce are not yet configurable in the admin product, and this
is not evidence of interoperability with a particular client release.
