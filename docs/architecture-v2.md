# OmniPanel v2 architecture and delivery contract

Date: 2026-11-03. Engineering baseline derived from the supplied Final Master
Architecture, Implementation and Verification Specification. This is a repository
implementation summary, not a claim that its requirements are satisfied or that
external product/financial decisions have been approved.

## Product invariant

Intent → capability validation → deployment plan → immutable revision → safe
application → observed connectivity → accounting/enforcement → subscription output
→ auditable operation. Every transition consumes evidence from the previous one.
Unknown support is unsupported for production guarantees. A dashboard entry is
not a driver, native syntax validation is not connectivity, and a live process
is not a healthy end-to-end path.

## Locked destination architecture

- Go control plane and agent, tested patch-pinned toolchain; chi, pgx/sqlc,
  OpenAPI-generated types, standard cryptography and OpenTelemetry.
- Static React + TypeScript + Vite + Tailwind/shadcn UI. Go alone authorizes.
- PostgreSQL 17 at a tested minor for canonical intent, outbox, jobs, immutable
  revisions, audits and accounting. PostgreSQL 18 needs restore/tooling validation.
  No mandatory Redis, message broker or Kubernetes for M1.
- Separate `omni-admin`, `omni-agent-gateway`, `omni-sub` processes and restricted
  database roles/pools/resource budgets. Subscription floods must not starve
  reconciliation. Admin is private/operator-gateway protected, agent transport
  end-to-end mTLS, subscription transport high-entropy bearer authorization.
- Unprivileged outbound-initiating `omni-node`; SQLite WAL durable journal,
  accounting queues/checkpoints, leases, identity and last-good references.
- Typed, narrow privileged helper; no shell commands, arbitrary executable
  uploads or arbitrary paths. Runtimes are independent systemd units, not
  children whose lifetime follows the agent.
- Runtime drivers for sing-box, standalone Hysteria2, Xray and later relay.
  Never require every engine on every VPS. Unsupported operations return typed
  capability errors, not successful no-ops.

## Runtime and ingress contract

Drivers declare capabilities, render/validate typed config, preflight, classify
disruption, apply structure/membership, verify health, collect counters, revoke
supported sessions, roll back and expose bounded diagnostics. Their declarations
must name exact build, platform and evidence.

M1 initially allocates TCP 443 to the chosen Reality runtime and independently
UDP 443 (or a separately verified alternative) to the chosen Hysteria2 runtime.
CDN-compatible origin TLS, management and protected SSH/console have separate
bindings. HAProxy is not mandatory. Any demultiplexer requires explicit normal,
missing-SNI, unexpected-SNI and malformed traffic tests.

Ingress ownership covers effective sockets, including IPv4/IPv6 wildcards and
IPV6_V6ONLY. SNI does not make two processes sharing one listening socket safe.
The pure planner in `src/lib/ingress.ts` is a contract preflight only; transactional
allocation, external listener inventory and on-host preflight are still required.

Immutable user egress policy must deny loopback, link-local/metadata, management,
database, secrets and restricted internal destinations, including operator-specific
networks and resolved addresses. Infrastructure exceptions are separately authorized.
Management routing is independent. M1 direct egress only. Approved alternate egress
must have explicit failure policy, never silently downgrade a fail-closed policy.

## State and identity

Administrative intent, desired structure, desired membership and observed state
are separate domains. Each authorized control-plane history has a UUID epoch;
each node has distinct structural/membership cursors. Revisions are immutable,
node-scoped and content-addressed. Rollback creates a higher revision. Database
PITR requires separately authorized, signed epoch recovery; agents must not
silently accept an old conflicting sequence. Meter identities and process
generations are not epoch aliases.

Model organization boundaries even for M1's single organization. Endpoint
principals are per-user, per-inbound, uniquely attributable, independently
credentialed and lifecycle-managed. Scope foreign keys and every object query.
Never reuse retired credentials where supported. Version protocol-specific JSON.
Audit destructive operations and document retention/deletion.

Admin baseline: MFA/recovery, secure HttpOnly sessions, CSRF, bounded idle and
absolute lifetime, RBAC/object authorization and high-risk step-up. Argon2id if
passwords are used. Single-use, short-lived node-scoped enrollment token
establishes identity, not arbitrary CSR fields. Separate root/issuer, server
identity and manifest signing; renew certificates and enforce revocation.
Signatures authorize structured, bounded operations only. Envelope-encrypt
secrets with independent KEK recovery. Redact all previews, logs and diagnostics.

## Accounting and quota contract

Authoritative user meter is normally the authenticating core. Relay traffic is
capacity telemetry, never another billable stream. Record exact runtime build,
user key, direction, overhead, counter semantics/lifetime, process generation,
API auth/interval, gaps and measured session-revocation effects.

Cumulative observations identify node, installation epoch, core instance,
process generation, stream and sequence. Compute nonnegative deltas only on
established continuity; detect conflicting duplicates, resets, missing baselines
and rollback. Durably queue bounded observations and explicitly report overflow.
PITR missing acknowledged traffic is uncertainty, not reconstructible zero.
Quality is complete/partial/estimated/unknown/unmetered. Unverified estimates
must not cause automatic billing or suspension. Adjustments are attributable
and reversible.

Hard quotas require verified local byte/time enforcement with a maximum
overshoot bound and distributed non-double-spend expiring leases. Unlimited
established sessions after exhaustion disqualify the claim. Otherwise label
metered/delayed/advisory and disclose session effects and measured delay. Offline
quota-controlled nodes use bounded unexpired grants/grace, not unlimited fail-open.
Subscription hiding is not runtime revocation. Unmanaged shared emergency paths
cannot inherit managed quota guarantees.

## Subscriptions, health and lifecycle

Compile deterministic native artifacts from a canonical typed IR, not rewritten
arbitrary strings. Model credentials by reference, client-required fields, actual
TLS termination, direct/CDN/relay classification, provenance, revision, health and
enforceability. Required security incompatibility fails compilation. Planned
families: sing-box JSON, Mihomo YAML, Xray client JSON, target-specific URI bundles.
Each client application/release/OS/core has evidence for import/refresh, feature
fields, routing/DNS and actual new-connection failover behavior.

One logical subscription may have independently hosted authenticated delivery
URLs. Credential responses use `Cache-Control: private, no-store`. Mirrors and
internal projections are access-controlled; signatures alone do not protect
credential confidentiality. Separate token rotation from network credentials.

L0 process/socket, L1 handshake, L2 synthetic authentication and L3 controlled
canary evidence are distinct. New paths require L2/L3. Probe principals are not
paying users. Aggregate by endpoint, vantage/network, transport and time; never
infer universal reachability from one datacenter probe. Use corroborated,
fresh, hysteretic transitions: healthy → degraded → suspected → confirmed →
draining/quarantined → recovering → healthy. Recovery needs repeated success
and cooldown. No candidates means capacity shortfall, not fabricated health.

Track IP/domain provider, ASN, lifecycle, certificates, capacity and reachability.
M1 rotation is operator-approved and includes DNS validation, subscription reissue
and drain. Provider diversity is mandatory; another IP in the same ASN is not
independent recovery. External/BPB sources require isolated SSRF-safe fetch,
redirect/decompression/size/time limits, strict parse/re-emission, provenance,
approval, snapshot freshness and explicit unmanaged guarantees.

## Delivery boundaries and acceptance

| Milestone | Scope | Required evidence |
| --- | --- | --- |
| M0 / Task 1 | One test node/user, Reality/Vision + sing-box artifact; compare embedded/standalone Hysteria2 | Real imports/connectivity, user counters/revocation, outbound reconciliation, last-good recovery, impairment tests |
| M1 / Tasks 2–4 | Secure separated Go control plane, headless durable agent, managed users and verified metering; two independent exits; narrow tested clients | Auth, object scopes, atomic intent/outbox/audit, signed state + mTLS, crash/recovery, accounting, protected management, health, restore/load gates |
| M2 | XHTTP/CDN, constrained relay, approved alternate egress, restricted BPB, more tested formats/clients | Independent compatibility, cryptographic identity, accounting and safe-failure gates per integration |
| M3 | Importer and additional protocol plugins | Separate admission, driver, client and operational evidence |

Task order: decision/lab and contract freeze → overlapping control-plane and agent
implementation → two-node M1 qualification → separately gated M2 integrations.
The supplied 24–36 week M2 estimate assumes 3–4 experienced engineers plus QA,
security/SRE and a funded lab; it is not a release commitment.

Reconciler states: RECEIVED → SIGNATURE_VERIFIED → VALIDATED → STAGED → PREFLIGHTED
→ APPLYING → APPLIED_UNVERIFIED → VERIFIED. Failure: FAILED → ROLLING_BACK →
ROLLED_BACK, or DEGRADED_REQUIRES_OPERATOR. Persist component results, use
generation directories, dependency-aware operations and a crash-surviving
commit-confirm watchdog independent of the agent process.

Initial **test targets, not measured capacity**: 10 nodes, 2,000 users, 1–5 operators,
50 subscription RPS burst, 1,000 accounting observations/s, 1,000 membership
changes/hour, Ubuntu 24.04 amd64. Test loss of largest node too. Proposed checks:
membership p95 <60s; zero duplicate billing across 1,000 replays; 20/20 crash
recoveries; subscription p95 <200ms at defined 50 RPS/output size; offline alert
within 120s; every accounting gap classified; independent new-connection path
survives primary loss; 24h soak and full failure-injection qualification.
15-minute RPO/60-minute RTO and any 99.9% SLA remain conditional on funded,
measured restoration and deployment topology.

Retention proposals pending legal review: raw usage 30 days, hourly aggregates
180 days, daily summaries 13 months where needed, source IP preferably 24h,
audit one year, no destination browsing history by default. Keys/configuration
secrets are never analytics. Require acceptable-use/provider/license review,
abuse handling, privacy/disclosure procedures and compromise response before
real-user pilots. No automatic rotation to bypass provider abuse/suspension review.

External decisions remain open: quota classes, outage grace, existing-session
revocation, client support list, suspended-subscription semantics, funded provider
diversity/recovery, regional/privacy policy, mirror trust, WARP terms/failure
policy, rotation approvals, advisory device/IP enforcement and upgrade authority.
No implementation default implies product/security/legal approval.

## Selective reuse from existing panels

The source audit is recorded in [`docs/research/source-project-review.md`](research/source-project-review.md)
and [ADR 0002](adr/0002-source-project-reuse.md). S-UI contributes a valuable
session-level revocation pattern for protocols that authenticate once and then
open multiple streams. 3X-UI contributes explicit protocol/transport capability
predicates, deterministic subscription ordering, format-specific exclusions,
client lifecycle and client-side subscription-balancer patterns.

Two clean-room foundations now exist:

- `src/lib/protocol-compatibility.ts` rejects unsupported Reality/Vision and
  Hysteria2 runtime/transport combinations and malformed Reality identity fields
  before subscription emission. The compiler also rejects paths unsupported by
  the requested output format and uses one canonical VLESS/Reality/Vision ID
  across runtime drivers. This is structural preflight only; exact runtime,
  client and connectivity qualification remain separate.
- `internal/agent/sessions` tracks opaque runtime session IDs against endpoint
  principals and credential generations. It closes runtime sessions outside its
  lock, or blocks subsequent routed flows and reports sessions that cannot be
  closed. It is not yet wired to a runtime driver.

Both source projects declare GPL-3.0 and their READMEs warn against production
use. No source code was copied. The migration roadmap, deferred features and
license boundary are documented in the source review.
