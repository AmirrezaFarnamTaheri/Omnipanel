# ADR 0001 — Adopt the v2 baseline without certifying the prototype

- Date: 2026-11-03
- Status: engineering baseline adopted for incremental work; external approvals pending
- Context: the repository implements a coupled Next.js/Drizzle prototype and
  incomplete Go scaffolds. UI representations and note-only evidence currently
  exceed demonstrated runtime behavior. No real networking lab results exist here.

## Decision

Target Go for authority/control plane and node, PostgreSQL canonical state,
SQLite WAL node durability, static React/Vite UI and independent systemd cores.
Run admin, agent gateway and subscription delivery in separate trust/resource
zones. Use native typed runtime drivers and deterministic client compilation.
Prefer a small evidence-backed vertical slice over simultaneous unverified M2 work.

Start with executable strict contracts, ingress preflight and a version-scoped
lab evidence gate. Store registries as JSON (a YAML-compatible subset) to avoid
an extra parser and ambiguous YAML scalar conversion. Null runtime pins and
empty client/metering registries deliberately mean unqualified, not "latest".
All production gates fail closed until their actual evidence exists.

Do not migrate production data or delete the existing UI in this increment.
Legacy HTTP/bearer routes are not v2 mTLS endpoints. Candidate v2 schemas and
OpenAPI are contract proposals awaiting the runtime lab and security review;
they are not generated clients or a completed contract freeze.

Historical evidence notes remain auditable, but cannot activate production
admission or strict quotas. A reviewed exact-build driver integration must
replace the empty qualification set; this is not achieved by toggling a UI flag.
That future integration must validate runtime inventory, client/IR eligibility,
manifest negotiation, metering and evidence scope together, not merely add a key
to an allowlist. No hard quota implementation is currently qualified.

## Consequences

Existing demo inbounds stop producing usable subscription paths. This intentional
compatibility change prevents unsupported guarantees; do not deploy this branch
as an upgrade to a live subscriber service. Preserve isolated legacy development
for reference while replacement contracts/services are implemented.

Lab logs may contain credentials: default evidence stays under ignored `.data/`
or protected external artifact storage. Only sanitized, reviewed golden configs
belong in Git. Schema fixtures remain explicitly unsigned/nonfunctional.

Rejected alternatives: relabeling the Next.js prototype as M1; green gate stubs;
trusting an owner's arbitrary "verified" note as runtime qualification; claiming
hard quotas from counter collection alone; interpreting BPB as a managed policy
engine; replacing all backend/agent/frontend code in one unverified change.
