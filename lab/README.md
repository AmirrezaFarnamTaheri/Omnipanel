# Decision-grade lab and evidence gate

This directory contains the evidence gate and a **local runtime smoke harness**;
it is not yet a public-node provisioner, production agent, full impairment runner,
or M0 walking skeleton. The checked-in contract fixture is deliberately fake.

## Automated local runtime smoke

`.github/workflows/runtime-smoke.yml` builds Sing-box v1.14.4 from the fixed
upstream commit `c005f35300ce76427dc285481ec5695f5b179cd2`. It checks GitHub's
cryptographic commit-verification result, builds the optional `with_v2ray_api`
tag needed for per-user counters, creates a GitHub Actions build-provenance
attestation for the resulting binary, and verifies that attestation. The local
harness starts a real Reality/Vision server and sing-box CLI client in separate
Linux network namespaces joined by a veth pair. A raw TCP echo target provides
known payload bytes in both directions. The harness checks native config
validation, actual client-to-server proxy connectivity, per-user counters with a
5% local error bound, invalid-config rejection, and credential rotation across a
full core restart.

The local smoke does **not** qualify public VPS reachability, Android/iOS/desktop
application import, mTLS enrollment, an agent-initiated control-plane exchange,
production safe-apply or last-good recovery, dynamic per-user session eviction,
Hysteria2, carrier impairment, or multi-provider resilience. In particular,
existing-session termination here is observed after a whole core restart; it is
not evidence of hot credential revocation. This smoke does not populate the
production runtime/client qualification registries or unblock `make gate-lab`.


## Reproducible procedure to implement/run on isolated lab hosts

1. Use Ubuntu 24.04 amd64 with protected independent console/SSH. Inventory public
   ingress and local listeners, IPv6 policy, provider/ASN and management routes.
2. Acquire an exact approved runtime artifact with independently verified signature,
   record version/platform/digest/provenance. Do not select `latest` in a script.
   Patch-pin the corresponding candidate in `capabilities/runtime.json`.
3. Generate isolated one-user credentials; validate typed configs with the native
   binary. Use TCP Reality/Vision and separately UDP Hysteria2, not an untested
   TCP demultiplexer. Enforce protected-destination denial and protected local APIs.
4. Import the emitted native sing-box client artifact into an exact client release
   on its recorded OS. Prove authenticated L2 and a controlled L3 canary through
   that endpoint; distinguish target/DNS/ingress/egress failures.
5. Transfer known upload/download payloads. Record authoritative per-principal
   counters, direction/overhead/error, sampling interval, process generation,
   restart/reload/reset behavior and gaps. Relay counters are capacity only.
6. Revoke the credential. Record new-auth block delay and observe an already
   established session long enough to document whether it persists or terminates.
   Do not infer hard enforcement from an API named "kick".
7. Prove outbound-initiated agent desired/report flow and independent core lifetime;
   reject unknown versions/required fields and bad configs while preserving service;
   restart/crash and restore last-good reference. Record measured interruption.
8. Compare embedded sing-box Hysteria2 and standalone Hysteria2 with their actual
   auth/stats APIs and credentials. Inject packet loss, delay and UDP filtering
   in an isolated network namespace; record commands, restoration and diagnostics.
   The harness does not execute arbitrary impairment commands for you.
9. Redact transcripts, review independently, then add exact-release client and
   complete metering registry entries. Record source timestamps and limitations.
   Only real, reproducible, reviewed results may inform qualification.

## Evidence layout

By default use ignored `.data/lab-evidence/`, or a protected directory selected by
`OMNI_LAB_EVIDENCE_DIR`. Keep raw secret-bearing captures outside the repository.
Top-level `*.json` files are evidence records. Put bounded redacted transcript
artifacts in a subdirectory (for example `artifacts/`) so artifact JSON is not
mistaken for an evidence record. Artifact paths are relative to the evidence
root; URL fetching is forbidden. Each file must be regular, ≤8 MiB and SHA-256
matched; artifact symlinks cannot escape the real root.

Records must satisfy `contracts/lab-evidence.schema.json`: unique UUID, capability,
exact runtime version/digest/platform, claim, passed/failed result, timestamp,
operator, exact client application/release/OS, summary, measurements and ≥1 artifact.
Passed claims require typed measurement fields (see schema). Accounting requires
positive bidirectional expected payload sizes and measured byte totals inside the
declared relative error bound (initial maximum 5%, not a billing commitment).
Record the chosen bound before a run; never tune it afterward to conceal a gap.

Example shape only (placeholders are intentionally not valid evidence):

```text
id: <new UUID>
capabilityId: singbox-reality-vision
runtimeVersion / runtimeArtifactDigest / platform: <exact tested build>
claim: accounting
result: passed | failed
testedAt / operator / client: <real identities, release and timestamp>
summary: <reproduction and limitations>
measurements: <schema-required expected/measured payloads and declared error bound>
artifacts: [{path: artifacts/<redacted transcript>, sha256: <digest>}]
```

Required claims per candidate: client_import, connectivity_l3,
credential_revocation, accounting, outbound_reconciliation, last_good_recovery,
version_rejection and impairment_diagnosis. Evidence expires after 90 days in this
initial lab policy; future timestamps, duplicate IDs and simultaneous ambiguous
results block. Latest matching failure supersedes an earlier pass. Wrong build,
platform or client release never qualifies another build. Client import/L3 claims
must be referenced by an exact verified client registry record; accounting must
be referenced by a complete authoritative metering registry record.

```sh
make check-contracts
make test-contracts
OMNI_LAB_EVIDENCE_DIR=/protected/lab/run make gate-lab
# Machine-readable lab decision only:
OMNI_LAB_EVIDENCE_DIR=/protected/lab/run npm run --silent gate:lab
```

Exit 0 means the supplied local evidence satisfies this preliminary lab policy;
exit 2 (or nonzero make result) means blocked. Required comparisons cannot be
removed by deleting a candidate from the registry. Approved scope-reduction
workflow is not implemented: the gate stays blocked until reviewed contract
changes are made. No UI note can substitute for this evidence.

**Limitations:** transcript hashes are not artifact signatures, operator identity
proof or proof of actual connectivity. A trusted reviewer must reproduce/check
scientific validity; fabricated logs can lie. File-size bounds are not a public
untrusted-upload security boundary. This local trusted-operator harness is not
served as an API. A passing lab gate does not install/activate a runtime, implement
leases, change the empty application qualification set or pass M1. Hard-quota
claims are deliberately blocked pending a separate lease/session enforcement gate.
