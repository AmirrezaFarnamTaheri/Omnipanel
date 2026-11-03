# ADR 0002 — Selectively adopt S-UI and 3X-UI behaviors

- Date: 2026-11-03
- Status: accepted for clean-room implementation; production integration pending

## Context

The supplied S-UI fork is a Sing-box-oriented panel with a runtime session registry,
traffic collection and SQLite recovery logic. The supplied 3X-UI fork is an
Xray-oriented panel with explicit protocol/transport capability predicates,
multi-format subscription behavior, deterministic host ordering, client lifecycle
features, subscription balancers and event streaming.

Both source repositories declare GPL-3.0 and their READMEs say they are intended
for personal use, not production. OmniPanel has no declared repository license.
Copying implementation code or vendoring modules would introduce licensing and
maintenance obligations that have not been approved.

## Decision

Adopt selected behaviors as independent, typed OmniPanel components. Do not
vendor either panel, transplant their database schemas, or treat their feature
lists as production evidence.

The first clean-room increment adds:

1. `src/lib/protocol-compatibility.ts`: an explicit narrow matrix for the
   currently designed Reality/Vision and Hysteria2 runtime/transport pairs.
   Subscription IR construction rejects malformed or incompatible endpoints
   before emitting artifacts.
2. `internal/agent/sessions`: a runtime-neutral registry keyed by opaque
   runtime session ID, endpoint-principal ID and credential generation. It
   closes sessions outside its lock where a closer exists; otherwise it blocks
   future routed flows and reports that the existing session may remain.

These components are not yet connected to real runtime drivers. A structural
preflight does not qualify a binary or client, and a session registry does not
prove a particular core's existing-stream behavior.

## Consequences

- Endpoint principals remain distinct per user/inbound, even though the panel
  exposes one logical user and subscription.
- Credential rotation revokes old-generation sessions; a revoked session never
  becomes valid merely because the same principal is re-enabled.
- Manual disconnect does not revoke future authentication.
- Session IDs are runtime-owned opaque handles, not client IP addresses.
- Unsupported protocol combinations fail closed.
- Exact build, native validator, real-client, accounting, revocation and
  last-good recovery evidence remain mandatory before activation.

## Deferred

Client-specific subscription exclusions and ordering, client-side balancer
documents/observatory, renewal/bulk lifecycle, WebSocket event delivery, and
one-shot S-UI/3X-UI importers are separate increments. Migration must be a
dry-run-first mapping into canonical users, endpoint principals and IR, never
a raw SQLite database replacement. Importing source traffic totals does not
make them authoritative billable observations.

See [the source-project review](../research/source-project-review.md) for the
file-level audit, licensing boundary and adoption roadmap.
