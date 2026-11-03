# Candidate v2 contracts

These are **initial proposals**, not a frozen API or implemented agent protocol.
`openapi.yaml` is a JSON-encoded YAML document using OpenAPI 3.1. The old
`go/control-plane/api/openapi.yaml` and legacy `/api/agent/*` routes are unrelated
prototype contracts; no route adapter or generated client is provided here.

All schema objects reject unknown properties. Versions are explicit; future
schema support must be negotiated, never silently strip unknown required fields.
Sequences are positive safe integers (membership cursor can be zero); epochs are
UUIDs, not the prototype's numeric settings. Raw commands, paths and credential
values have no representation. Config/credential references must resolve only
through a node-scoped, typed authorized store. Schema validity grants no execution.

Desired-state envelope proposal: `ed25519-jcs-v1` means RFC 8785 canonicalization
of the `manifest`, SHA-256 lowercase hex of those bytes in `contentDigest`, and
Ed25519 over UTF-8 `omnipanel:desired-state:ed25519-jcs-v1\n` followed by those
canonical bytes. Signature is unpadded base64url. Signer lookup is pinned locally
and independent of HTTPS server identity. This algorithm is **not implemented or
approved** by this increment. The fixture uses dummy digests/signature/builds,
so only schema/graph/socket preflight succeeds, not cryptographic validation.

A future agent must separately verify signer authorization, digest/signature,
current validity/clock policy, its own node ID, epoch authorization, monotonic
revision, capability support, actual artifact/config digests, allowed operations
and resource limits before staging. Recovery and membership need separately
versioned signed contracts. A manifest's membership cursor does not authenticate
an unprovided membership journal. Structural rollback always allocates a new
higher sequence; no descending revision acceptance.

The endpoint IR models references, provenance, explicit Reality versus origin/CDN
TLS, client capability requirements, health and enforceability. Initial admitted
protocol vocabulary only permits Reality/TCP or Hysteria2/UDP with direct/relay
routes; it deliberately cannot represent a purported Reality/CDN combination.
The presence of route/format names is not evidence of implemented support.
Reference schemas, DNS/egress policy, runtime capability and per-client field
validation still need real implementations. Do not feed this IR directly to a core.

`validateDesiredState` performs contract preflight only, never trusted application.
Run `make check-contracts` and `make test-contracts`. Do not confuse those with
`make gate-lab`, a working data plane or production security qualification.
