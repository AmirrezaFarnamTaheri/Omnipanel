# Unprivileged Go node polling process (verified intent only)

**State:** Implemented application entrypoint, not yet an operational apply/rollback agent or an M0 lab gate.

`go run ./cmd/omnipanel-node --config /var/lib/omnipanel-node/private/node-bootstrap.json --once` performs one outbound TLS 1.3 mutual-authenticated desired-state GET at `/v2/nodes/self/desired`, verifies the scoped Ed25519 signed envelope against **locally installed** trust anchors and exact qualified-build identities, and writes a `RECEIVED → VERIFIED` intent record into the private SQLite WAL journal. A 204 response means **no change**, not proof of runtime health.

Remove `--once` to poll repeatedly on the configured interval. All poll failures remain failures; the service never acknowledges an applied revision.

## Node provisioner responsibilities

1. Create a dedicated **non-root** node agent OS user. Provision a real directory such as `/var/lib/omnipanel-node/private`, owned by that user, with mode `0700`.
2. Put `node-bootstrap.json`, server CA PEM, enrolled node client certificate PEM and client private key PEM in that directory as owner-owned regular files with mode `0600`. Symlinks and broader file/parent permissions are rejected.
3. Provision the node UUID, authorized control-plane epoch UUID, bare HTTPS gateway origin, absolute journal filename, trusted Ed25519 signer ID/public key and independently reviewed exact runtime build identity. These values **must not come from the downloaded manifest**.
4. Use a node certificate with client-auth EKU. The gateway must authenticate the node identity and map it to its own `/v2/nodes/self/desired` response. The client rejects redirects, proxies, TLS versions below 1.3, non-JSON bodies, oversized responses and unauthorized epochs.
5. Set `pollSeconds` between 5 and 3600 and `maxClockSkewSeconds` between 0 and 300. Operators should use conservative skew and retain accurate NTP time.

Example schema (**placeholders are intentionally invalid and must be replaced with reviewed values**):

```json
{
  "gatewayOrigin": "https://control.example.com:8443",
  "nodeId": "00000000-0000-4000-8000-000000000001",
  "controlPlaneEpoch": "00000000-0000-4000-8000-000000000002",
  "journalPath": "/var/lib/omnipanel-node/private/node.sqlite",
  "rootCAFile": "/var/lib/omnipanel-node/private/gateway-ca.pem",
  "clientCertFile": "/var/lib/omnipanel-node/private/node.pem",
  "clientKeyFile": "/var/lib/omnipanel-node/private/node-key.pem",
  "trustedSigners": {
    "approved-owner": "REPLACE_WITH_32_BYTE_CANONICAL_BASE64URL_ED25519_PUBLIC_KEY"
  },
  "allowedCapabilities": ["singbox-reality-vision"],
  "qualifiedBuilds": {
    "singbox": {
      "Driver": "singbox",
      "Version": "1.14.4+omni.2",
      "ArtifactDigest": "REPLACE_WITH_ATTESTED_SHA256_HEX",
      "Capabilities": ["singbox-reality-vision"]
    }
  },
  "pollSeconds": 30,
  "maxClockSkewSeconds": 5
}
```

The `qualifiedBuilds` map is operator-provisioned trust configuration, **not a substitute for an external signed build attestation or passing multi-host lab gate**. Until qualification is evidenced and approved, do not provision a runtime entry.

## Trust and deployment boundaries

The node poller cannot deploy a config, open a privileged socket, mutate firewall rules, observe production counters, revoke users, report applied health, or ACK a commit. `pending_application` is exactly that: a signed, durable request for later execution. Full deployment requires an independently tested native Sing-box driver with validate/stage/apply, watchdog recovery, health proof and a durable applied cursor. No scripts, arbitrary host commands or private keys are accepted from the desired-state response.
