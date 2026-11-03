# Initial threat model (not a security sign-off)

Date: 2026-11-03. Scope: v2 target and legacy migration. Review before contract
freeze, before installing an agent and before each production pilot.

## Assets and actors

Protect subscriber credentials/subscription tokens, endpoint principals, admin
sessions/MFA recovery, node keys/certificates, manifest/artifact signing keys,
KEKs/backups, immutable revision history, usage attribution/quota grants, private
management networks and host recovery access.

Adversaries: unauthenticated Internet clients, abusive authorized subscribers,
malicious external source operators, compromised VPS/agent/runtime, compromised
admin session, supply-chain publisher, and an operator error or corrupted/PITR
state. An issuer or root compromise is a separate high-impact incident, not a
routine node-reenrollment event.

## Boundaries, attacks and required controls

| Boundary | Attack/failure | Required control and verification |
| --- | --- | --- |
| Browser → admin | Session theft, CSRF, object-ID substitution, bootstrap race | Private operator surface; MFA/recovery; secure cookies and expiry; CSRF; scoped object queries; transactional one-time setup; concurrency tests |
| Public subscription → projections | Token guessing/log leakage, user cross-read, resource flood | High-entropy hashed tokens; redacted URLs; private no-store; isolated DB role/pool/limits; cross-user and saturation tests |
| Agent → gateway | Forged forwarded identity, stolen/revoked cert, CSR identity substitution | End-to-end mTLS; token-derived node scope; renewal/revocation; no trust in forwarded client-cert headers; negative identity tests |
| Gateway/signer → node | Replay, wrong node/epoch, unauthorized shell/path, signature downgrade | Independently authorized Ed25519 signer; canonical payload/digest; validity/schema/capability checks; typed operations; explicit signed recovery; rejection before effects |
| Agent → privileged helper | Arbitrary command, path traversal, symlink swap, broad firewall replacement | Fixed typed allowlists, peer auth, owned directories/nftables rules; no remote executable or shell; systemd units owned independently; adversarial helper tests |
| Revision → network | Port wildcard collision, lost management, partial apply/crash | Effective socket inventory/serialized allocation; dependency plan; durable journal; external commit-confirm watchdog; protected SSH/console; 20 crash points |
| User proxy → destinations | Metadata/localhost/private-network access, DNS rebinding/IPv4-mapped bypass | Immutable base deny policy, operator management ranges, resolved-address enforcement; actual runtime egress tests across IPv4/IPv6 and DNS |
| External source → compiler | SSRF, redirect to metadata, decompression bomb, malicious fields | Isolated bounded fetcher, redirect/DNS-rebinding protections, strict parse to IR; material-change approval; timeout/size/corrupt input tests |
| Runtime meter → billing | Double delivery, counter reset, generation collision, dishonest node | Authoritative authenticating core; durable continuity/dedup; typed gaps; no relay double charge; quarantine; qualified accuracy bounds |
| Control plane → leases | Duplicate grants, stale epochs, unlimited existing sessions | Transactional allocation, scoped expiring leases, local enforcement; explicit overshoot/session evidence; no hard claims until verified |
| Release → node | Same-server checksum spoof, bad architecture/version, failed start | Independently verifiable signatures/provenance; version inventory; approved rollout; known-good predecessor and rollback tests |
| Backup → restore | Missing KEK, old epoch accepted, missing billed events | Separate key custody; PITR+keys drill; authorized new epoch; account uncertainty reconciliation; measured RPO/RTO |

## Legacy blockers and current limits

The prototype does not satisfy isolated service/database roles, mTLS, production
PKI, runtime/helper allowlists, durable safe apply, local quota leases, signature-
verified artifact upgrades or full recovery. Its numeric epoch and note-only
capability records are not the v2 epoch/evidence contract. The Go scaffolds are
not tested deployable services. Do not expose them to subscribers or production
nodes. Dependency audit also reports unresolved legacy vulnerabilities; see the
implementation status. The new planner is not a host firewall or allocator.
The new schema validator is not a signature verifier or runtime config validator.

Lab evidence SHA-256 verifies local transcript integrity only, not authenticity
or scientific validity. Evidence directory and registry edits require trusted
operator review. A fabricated transcript can lie. Independently reproduce and
review a run before approving a build or promising an enforcement property.
Do not accept user uploads/remote paths into this local harness as a public API.

## Incident and review checklist

1. Stop rollout for credential disclosure, unauthorized destination access,
   accounting corruption or unrecoverable state divergence.
2. Quarantine compromised node identity at gateway; separately identify and
   rotate every credential installed there; revocation alone cannot erase secrets.
3. Preserve bounded redacted journal/audit/accounting evidence; no browsing logs.
4. Restore last-good runtime/config and protected management path independently.
5. Reconcile epochs, meter gaps and unused unreachable-node quota allocations.
6. Rotate tokens, endpoint credentials, issuer/signing keys or KEKs according to
   actual exposure; test the recovery path before resuming promotion.

Detailed operational runbooks, abuse/legal review, key ceremonies and penetration
review are still required. This document records requirements, not executed tests.
