# OmniPanel (M1 control-plane foundation)

Next.js + PostgreSQL (Drizzle) implementation of the OmniPanel control plane: administration UI,
agent-facing API, accounting, subscription compiler, health state machine and audit.

First visit `/setup` to create the owner account, enable TOTP under *Settings*, then use
*Overview → Load demo topology* to explore, or register real nodes.

## Agent protocol (pull based)
All agent calls use `Authorization: Bearer <nodeId>.<key>` (never forwarded headers).

| Call | Purpose |
|---|---|
| `POST /api/agent/enroll` `{token}` | Single-use token → node credential + signing public key + epoch |
| `GET /api/agent/desired?epoch=&structural=&membership=` | Ed25519-signed structural revision (+ secrets matching signed digests) and membership delta/snapshot. A different `epoch` triggers a signed recovery snapshot |
| `POST /api/agent/report` | Applied cursors, state machine state, per-component results, probe observations |
| `POST /api/agent/metering` | Cumulative per-principal counters `{attributionKey, generation, seq, up, down, generationStart?}` and explicit `gaps` |

Subscriptions: `GET /sub/<token>[?format=singbox|mihomo|uri]`. Admin REST: `/api/admin/users` (Idempotency-Key, If-Match, RFC 9457 errors).

## Configuration
- `OMNI_KEK` (base64, 32 bytes): key-encryption key. Without it a dev KEK is stored in `.data/kek`.
- `OMNI_PUBLIC_URL`: prefix for displayed subscription URLs. `OMNI_SETUP_TOKEN`: protects first-admin bootstrap.

## Not in this repository
The Go agent, mTLS PKI, lab/gate harness, relays/CDN/WARP/BPB integrations and real multi-vantage probes are out of scope here.
