# OmniPanel — v2 engineering baseline

OmniPanel aims to turn administrator intent into verified, recoverable, auditable
multi-protocol network service. **This checkout is a prototype, not M1 or M2.**

The existing application is Next.js + PostgreSQL/Drizzle. The non-buildable Go scaffolding has been retired rather than represented as a
working agent or control plane. The selected v2 destination is verified Go
services + PostgreSQL and a static React/Vite admin UI; that migration has
**not** been completed.

## Start here

- [Architecture and release contract](docs/architecture-v2.md)
- [Implementation status, gaps and next increments](docs/implementation/status.md)
- [Architecture decisions](docs/adr/0001-v2-baseline.md)
- [Initial threat model](docs/security/threat-model.md)
- [Lab procedure and evidence format](lab/README.md)
- [Wire-contract notes](contracts/README.md)

## Local verification

Node.js 22, npm and a supported Go toolchain are required for the full foundation checks.
CI pins Go 1.27.3. Install the locked JavaScript dependencies:

```sh
npm ci
make check-contracts
make test-contracts
make test-go
npm run typecheck
npm run lint
make gate-lab
```

Contract/unit checks and the Go desired-state verifier tests are executable without
a database or a network runtime.
`gate-lab` deliberately exits nonzero until exact runtime builds, verified
clients, metering contracts and real lab transcripts are supplied. The other
production gate names explicitly report BLOCKED; they are not passing stubs.
No synthetic fixture under `testdata/contracts/` is connectivity evidence.

**Safety change:** no runtime build is currently production-qualified.
Unqualified inbounds cannot be created or emitted in subscriptions, including
old demo inbounds. Owner-entered historical evidence notes cannot override this.
There are no production-qualified hard quotas. BPB Workers are unmanaged external
sources, not a bandwidth policy engine.

## Explore the legacy prototype (development only)

Set `DATABASE_URL` to an isolated PostgreSQL instance, apply the existing
`db/migrations/` in order, set `OMNI_SETUP_TOKEN`, then run
`npm run dev -- --hostname 0.0.0.0`. Visit `/setup`. Do not expose it as production
infrastructure or connect real subscriber credentials. The former demo seeder, which fabricated enrolled nodes and verified health,
has been removed.

Legacy configuration includes `OMNI_KEK` (base64 32-byte key) and `OMNI_PUBLIC_URL`.
Without `OMNI_KEK`, the prototype writes a development key in `.data/kek`. This is
**not** an approved production key lifecycle. Keep `.data/`, raw credentials,
lab captures and keys out of Git.

The legacy `/api/agent/*` uses bearer node credentials, not mTLS, and does not
implement the candidate v2 contracts in `contracts/`. See the status document
for security and migration blockers.

## Repository hygiene

- Application routes are named by function, not delivery milestone. Unverified
  CDN, relay, WARP, BPB and Xray prototype endpoints and demo UI have been retired.
- The historical `0002_m2.sql` migration and its ORM table mappings remain for
  existing databases; migration filenames must not be rewritten after deployment.
- Removed a locally generated key that had been committed under `.data/kek`.
  **Any environment that used that key must rotate affected secrets and keys.**
  Deleting the tracked file does not erase its contents from Git history.
- Settings are deliberately read-only until mutations can be persisted and audited.
- The obsolete pg-mem verification script was removed; use the maintained
  contract tests, and do not misinterpret them as real networking evidence.

## Signed desired-state verification (Go foundation)

`internal/manifest/` contains a standalone, fail-closed Go parser and verifier
for the candidate `ed25519-jcs-v1` desired-state envelope. It checks the exact
signed manifest digest and locally approved Ed25519 signer; node and epoch
identity; validity times; structural and membership monotonicity; exact reviewed
runtime builds and their declared capabilities; typed component dependencies;
and effective ingress conflicts. Unknown, null, duplicate or unsafe JSON fields
are rejected. No arbitrary host paths or commands are accepted.

Verification produces an **intent decision, not a deployed or observed state**.
The package is not wired to a production agent. Qualification, trusted signers,
approved epochs and replay cursors must come from durable, protected node-local
state; there are deliberately no qualified builds or signer credentials included
with the repo. No network/service functionality or release gate is claimed.
