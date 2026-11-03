# OmniPanel — v2 engineering baseline

OmniPanel aims to turn administrator intent into verified, recoverable, auditable
multi-protocol network service. **This checkout is a prototype, not M1 or M2.**

The existing application is Next.js + PostgreSQL/Drizzle. The partial `go/` trees
are scaffolding, not working production control-plane/agent implementations.
The selected v2 destination is Go services + PostgreSQL and a static React/Vite
admin UI; that migration has **not** been completed.

## Start here

- [Architecture and release contract](docs/architecture-v2.md)
- [Implementation status, gaps and next increments](docs/implementation/status.md)
- [Architecture decisions](docs/adr/0001-v2-baseline.md)
- [Initial threat model](docs/security/threat-model.md)
- [Lab procedure and evidence format](lab/README.md)
- [Wire-contract notes](contracts/README.md)

## Local verification

Node.js 22 and npm are required. Install the locked dependencies:

```sh
npm ci
make check-contracts
make test-contracts
npm run typecheck
npm run lint
make gate-lab
```

Contract/unit checks are executable without a database or a network runtime.
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
infrastructure or connect real subscriber credentials. Demo topology is illustrative
only; it does not provision network runtimes.

Legacy configuration includes `OMNI_KEK` (base64 32-byte key) and `OMNI_PUBLIC_URL`.
Without `OMNI_KEK`, the prototype writes a development key in `.data/kek`. This is
**not** an approved production key lifecycle. Keep `.data/`, raw credentials,
lab captures and keys out of Git.

The legacy `/api/agent/*` uses bearer node credentials, not mTLS. Neither those
routes nor the old Go OpenAPI file implement the candidate v2 contracts in
`contracts/`. See the status document for security and migration blockers.
