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
- [Approved Go/Vite architecture and source-reuse decision](docs/adr/0003-go-vite-migration-and-source-reuse.md)
- [Repository-aligned implementation roadmap](docs/plans/2026-11-04-omnipanel-v2-rollout.md)
- [First executable runtime/agent implementation plan](docs/plans/2026-11-04-runtime-evidence-and-driver-contract.md)
- [Hiddify Manager and 1Panel source analysis](docs/research/hiddify-1panel-review.md)
- [Initial threat model](docs/security/threat-model.md)
- [Lab procedure and evidence format](lab/README.md)
- [Wire-contract notes](contracts/README.md)

## Local verification

Node.js 22, npm and Go are required for the foundation checks. CI pins Go 1.27.3
for the manifest verifier and Go 1.26.10 for the pinned Sing-box lab build.
Install the locked JavaScript dependencies:

```sh
npm ci
make check-contracts
make test-contracts
make test-go
make test-provenance
npm run typecheck
npm run lint
make gate-lab
```

Contract/unit checks, the Go desired-state verifier tests and the fail-closed
provenance-verifier tests are executable without a database or network runtime.
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

## Local runtime smoke (not M0 acceptance)

The `.github/workflows/runtime-smoke.yml` workflow builds Sing-box v1.14.4
from its fixed upstream commit, verifies GitHub's upstream commit-signature
result, compiles the optional `with_v2ray_api` statistics service, attests the
resulting binary with GitHub Actions provenance, and verifies that attestation.
It then runs a real VLESS/Reality/Vision server and sing-box CLI client in two
isolated Linux network namespaces joined by a veth pair. A raw TCP echo target
provides known bidirectional payloads; the test checks per-user counters, invalid
configuration rejection, and credential rotation across a full core restart.

To reproduce locally on Ubuntu 24.04 with Go 1.26.10, `grpcurl`, `iproute2`,
OpenSSL, jq and Python 3:

```sh
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.3
bash lab/runtime/build-sing-box.sh
sudo env SING_BOX_BIN=.data/lab-runtime/sing-box make test-runtime
```

This is an actual local core-to-core runtime test, **not** a public VPS, mobile
client, agent, subscription compiler, safe-apply/rollback, or M0 acceptance test.
The credential-removal observation uses a core restart; it does not prove hot
per-user revocation. The full `make gate-lab` remains blocked pending external
node/client evidence and the remaining Task 1 requirements.
## Existing panel capability review

A clean-room review of the supplied [S-UI](https://github.com/AmirrezaFarnamTaheri/S-UI)
and [3X-UI](https://github.com/AmirrezaFarnamTaheri/3X-UI) repositories, including
what was adopted, deferred and excluded, is documented in
[docs/research/source-project-review.md](docs/research/source-project-review.md).
No GPL-3.0 source files were copied or vendored.
