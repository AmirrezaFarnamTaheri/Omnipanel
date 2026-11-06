import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  buildRuntimeSandboxProfile,
  buildTimeSeriesPartitionPlan,
  compileNfnetlinkTransaction,
  computeSubscriptionEtag,
  evaluateDatabaseScalabilityReadiness,
  evaluateDesiredStateTransportState,
  evaluateEbpfSocketTermination,
  evaluateMultiVantageCanaryQuorum,
  evaluateSessionNetworkBinding,
  evaluateShortLivedMtlsPolicy,
  generateSlsaProvenanceAndSbom,
  matchesIfNoneMatch,
  renderOpenTelemetryPrometheusMetrics,
  runChaosFaultInjectionSuite,
  signAlertWebhookEnvelope,
  unwrapWithKmsTransitEnvelope,
  verifyAlertWebhookEnvelope,
  verifyWebAuthnStepUpAssertion,
  wrapWithKmsTransitEnvelope,
} from "../../src/lib/enterprise-hardening";
import { canonicalJson } from "../../src/lib/crypto";
import { evaluatePanelImportDryRun } from "../../src/lib/panel-importer";
import { compileClientBalancerDocument, computeAdaptiveBalancerParameters } from "../../src/lib/subscription-balancer";

test("Domain 1: HSM/KMS Transit Envelope wraps and unwraps DEK and rejects tampered AAD", () => {
  const masterSecret = Buffer.alloc(32, 0x5a);
  const plaintext = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
  const env = wrapWithKmsTransitEnvelope({
    kmsKeyUri: "kms://gcp/projects/omni/locations/global/keyRings/cp/cryptoKeys/kek-1",
    keyVersion: 3,
    kmsMasterSecret: masterSecret,
    contextAad: { nodeId: "1", epoch: "3" },
    plaintext,
  });
  assert.equal(env.version, "kms-transit-envelope-v1");

  const unwrapped = unwrapWithKmsTransitEnvelope({
    envelope: env,
    kmsMasterSecret: masterSecret,
    expectedContextAad: { nodeId: "1", epoch: "3" },
  });
  assert.equal(unwrapped.toString("utf8"), plaintext.toString("utf8"));

  assert.throws(() => {
    unwrapWithKmsTransitEnvelope({
      envelope: env,
      kmsMasterSecret: masterSecret,
      expectedContextAad: { nodeId: "1", epoch: "999" },
    });
  }, /unable to authenticate data|Unsupported state/i);
});

test("Domain 1: WebAuthn / FIDO2 Passkey Step-Up verifies Ed25519 hardware assertion and rejects signCount replay", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  const rpId = "panel.omnipanel.internal";
  const challenge = "step-up-approval-proposal-42";
  const origin = "https://panel.omnipanel.internal";

  const rpIdHash = crypto.createHash("sha256").update(rpId, "utf8").digest();
  const flags = Buffer.from([0x05]); // UP (0x01) | UV (0x04)
  const signCountBuf = Buffer.alloc(4);
  signCountBuf.writeUInt32BE(15, 0);
  const authenticatorData = Buffer.concat([rpIdHash, flags, signCountBuf]);

  const clientDataObj = {
    type: "webauthn.get",
    challenge,
    origin,
  };
  const clientDataJson = Buffer.from(JSON.stringify(clientDataObj), "utf8");
  const clientDataHash = crypto.createHash("sha256").update(clientDataJson).digest();

  const signature = crypto.sign(null, Buffer.concat([authenticatorData, clientDataHash]), privateKey);

  const verified = verifyWebAuthnStepUpAssertion({
    rpId,
    expectedChallenge: challenge,
    expectedOrigin: origin,
    credentialId: "fido2-yubikey-bio-01",
    publicKeyPem,
    previousSignCount: 14,
    authenticatorData,
    clientDataJson,
    signature,
  });

  assert.equal(verified.verified, true);
  assert.equal(verified.newSignCount, 15);
  assert.equal(verified.userVerifiedFlag, true);

  assert.throws(() => {
    verifyWebAuthnStepUpAssertion({
      rpId,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      credentialId: "fido2-yubikey-bio-01",
      publicKeyPem,
      previousSignCount: 15,
      authenticatorData,
      clientDataJson,
      signature,
    });
  }, /replay detected/i);
});

test("Domain 1: Automated short-lived SPIFFE mTLS rotation enforces 4-6h TTL and OCSP/CRL revocation push digest", () => {
  const now = new Date("2026-11-06T03:00:00.000Z");
  const policy = evaluateShortLivedMtlsPolicy({
    nodeId: 1,
    ttlSeconds: 14_400,
    now,
    revokedSerials: ["00dead", "01beef"],
  });
  assert.equal(policy.ttlSeconds, 14_400);
  assert.equal(policy.ocspStaplingRequired, true);
  assert.equal(policy.crlRevision, 3);
  assert.match(policy.revocationPushDigest, /^sha256:[0-9a-f]{64}$/);

  assert.throws(() => {
    evaluateShortLivedMtlsPolicy({
      nodeId: 1,
      ttlSeconds: 86_400, // 24h rejected
    });
  }, /between 4h \(14400s\) and 6h \(21600s\)/);
});

test("Domain 1: Scoped session binding & IP/ASN pinning detects network transitions", () => {
  const valid = evaluateSessionNetworkBinding({
    boundTlsChannelSha256: "aabbccddeeff",
    presentedTlsChannelSha256: "aabbccddeeff",
    allowedAsns: ["AS24940", "AS13335"],
    presentedAsn: "AS24940",
  });
  assert.equal(valid.valid, true);

  const asnHijack = evaluateSessionNetworkBinding({
    boundTlsChannelSha256: "aabbccddeeff",
    presentedTlsChannelSha256: "aabbccddeeff",
    allowedAsns: ["AS24940"],
    presentedAsn: "AS64512",
  });
  assert.equal(asnHijack.valid, false);
  assert.equal(asnHijack.reason, "asn_pin_violation:AS64512");
});

test("Domain 2: gRPC streaming push with bounded HTTP polling fallback, eBPF socket teardown, Seccomp sandbox & nfnetlink", () => {
  const now = new Date("2026-11-06T03:00:10.000Z");
  const streamActive = evaluateDesiredStateTransportState({
    streamConnected: true,
    lastStreamHeartbeatAt: new Date("2026-11-06T03:00:05.000Z"),
    now,
  });
  assert.equal(streamActive.mode, "grpc_bidi_stream");
  assert.equal(streamActive.streamHealthy, true);

  const fallback = evaluateDesiredStateTransportState({
    streamConnected: false,
    lastStreamHeartbeatAt: new Date("2026-11-06T02:59:00.000Z"),
    now,
  });
  assert.equal(fallback.mode, "http_mtls_polling_fallback");
  assert.equal(fallback.streamHealthy, false);

  const ebpfQuic = evaluateEbpfSocketTermination({
    principalId: "u1",
    ebpfAttached: true,
    activeTcpSockets: 2,
    activeQuicSockets: 3,
  });
  assert.equal(ebpfQuic.quicSocketsDestroyed, 3);
  assert.equal(ebpfQuic.unclosableRemaining, 0);
  assert.equal(ebpfQuic.existingStreamsGuaranteedTerminated, true);

  const sandbox = buildRuntimeSandboxProfile("singbox");
  assert.deepEqual(sandbox.ambientCapabilities, ["CAP_NET_BIND_SERVICE"]);
  assert.equal(sandbox.noNewPrivileges, true);
  assert.equal(sandbox.readOnlyRootfs, true);

  const tx = compileNfnetlinkTransaction({
    inboundPorts: [{ port: 443, protocol: "tcp" }],
    privateEgressCidrs: ["10.0.0.0/8", "192.168.0.0/16"],
  });
  assert.equal(tx.family, "NFPROTO_INET");
  assert.equal(tx.invokesHostShell, false);
  assert.equal(tx.driftDetected, false);
});

test("Domain 3: PostgreSQL time-series range partitioning planner, LISTEN/NOTIFY outbox, and PgBouncer readiness", () => {
  const now = new Date("2026-11-06T00:00:00.000Z");
  const plans = buildTimeSeriesPartitionPlan(now);
  assert.equal(plans.length, 3);
  assert.equal(plans[0]?.parentTable, "meter_observations");
  assert.match(plans[0]!.declarativeDdl, /PARTITION OF meter_observations/);

  const readiness = evaluateDatabaseScalabilityReadiness();
  assert.equal(readiness.channelName, "omnipanel_outbox_wakeup");
  assert.match(readiness.claimQuery, /FOR UPDATE SKIP LOCKED/);
  assert.equal(readiness.pgBouncerPoolMode, "transaction");
});

test("Domain 4: Multi-vantage L3 canary quorum distinguishes ISP SNI censorship from endpoint failure + OTel metrics & signed webhooks", () => {
  const censorship = evaluateMultiVantageCanaryQuorum(1, [
    {
      vantageId: "de-fra-1",
      region: "eu-central",
      asn: "AS24940",
      handshakeOk: true,
      echoOk: true,
      latencyMs: 11,
    },
    {
      vantageId: "us-iad-1",
      region: "us-east",
      asn: "AS13335",
      handshakeOk: true,
      echoOk: true,
      latencyMs: 88,
    },
    {
      vantageId: "cn-sha-isp",
      region: "ap-east",
      asn: "AS4134",
      handshakeOk: false,
      echoOk: false,
      latencyMs: 0,
    },
  ]);
  assert.equal(censorship.verdict, "regional_sni_censorship_suspected");
  assert.equal(censorship.distinctAsnCount, 3);

  const metricsText = renderOpenTelemetryPrometheusMetrics({
    epoch: 3,
    auditChainHeight: 12,
    auditChainIntact: true,
    enrolledNodes: 2,
    healthyInbounds: 2,
    activeSubscribers: 4,
    pendingProposals: 0,
  });
  assert.match(metricsText, /omnipanel_control_plane_epoch 3/);
  assert.match(metricsText, /omnipanel_audit_chain_intact 1/);

  const wh = signAlertWebhookEnvelope({
    secret: "webhook-secret-key",
    eventId: "evt-100",
    timestamp: 1_762_398_000,
    severity: "critical",
    eventKind: "isp_sni_block",
    payload: { endpoint: "eu-frankfurt-1-reality-443", asn: "AS4134" },
  });
  assert.equal(
    verifyAlertWebhookEnvelope({
      envelope: wh,
      secret: "webhook-secret-key",
      nowEpochSeconds: 1_762_398_060,
    }),
    true,
  );
  assert.equal(
    verifyAlertWebhookEnvelope({
      envelope: wh,
      secret: "wrong-secret-key",
      nowEpochSeconds: 1_762_398_060,
    }),
    false,
  );
});

test("Domain 5: Adaptive client balancer tuning and differential subscription ETag / 304 Not Modified matching", () => {
  const highJitter = computeAdaptiveBalancerParameters([18, 22, 25, 190, 240]);
  assert.equal(highJitter.intervalSeconds, 360);
  assert.equal(highJitter.tuningProfile, "degraded_battery_saver");
  assert.ok(highJitter.toleranceMs >= 120);

  const stableLowRtt = computeAdaptiveBalancerParameters([12, 14, 15, 18, 20]);
  assert.equal(stableLowRtt.intervalSeconds, 180);
  assert.equal(stableLowRtt.toleranceMs, 35);
  assert.equal(stableLowRtt.tuningProfile, "low_latency_stable");

  const etag = computeSubscriptionEtag({
    compiledBody: '{"outbounds":[]}',
    userinfoHeader: "upload=100; download=200; total=1000",
    format: "singbox",
    updateIntervalHours: 12,
  });
  assert.equal(matchesIfNoneMatch(etag, etag), true);
  assert.equal(matchesIfNoneMatch(`W/${etag}, "other"`, etag), true);
  assert.equal(matchesIfNoneMatch('"different-etag"', etag), false);
});

test("Domain 6: Automated Chaos Fault-Injection Suite, SLSA Level 3 Provenance & Property-Based Fuzzing", () => {
  const chaos = runChaosFaultInjectionSuite();
  assert.equal(chaos.allPassed, true);
  assert.equal(chaos.scenarios.length, 4);

  const slsa = generateSlsaProvenanceAndSbom();
  assert.equal(slsa.slsaLevel, "SLSA_BUILD_LEVEL_3");
  assert.equal(slsa.sbomFormat, "CycloneDX-1.5");

  // Property-based fuzzing over JCS canonicalization, balancer compilation, and S-UI/3X-UI importer
  for (let seed = 1; seed <= 25; seed++) {
    const objA = {
      z: seed * 17,
      a: `str-${seed}-✓`,
      nested: { b: [seed, seed + 1], a: seed % 2 === 0 },
    };
    const objB = {
      nested: { a: seed % 2 === 0, b: [seed, seed + 1] },
      a: `str-${seed}-✓`,
      z: seed * 17,
    };
    assert.equal(canonicalJson(objA), canonicalJson(objB));

    const balancerA = compileClientBalancerDocument({
      groupTag: `fuzz-${seed}`,
      strategy: seed % 2 === 0 ? "url-test" : "fallback",
      probeUrl: "https://cp.cloudflare.com/generate_204",
      intervalSeconds: 60 + seed,
      toleranceMs: 20 + seed,
      endpoints: [
        { tag: `ep-b-${seed}`, protocol: "vless-reality-vision", weight: 50 },
        { tag: `ep-a-${seed}`, protocol: "vless-reality-vision", weight: 100 },
      ],
    });
    const balancerB = compileClientBalancerDocument({
      groupTag: `fuzz-${seed}`,
      strategy: seed % 2 === 0 ? "url-test" : "fallback",
      probeUrl: "https://cp.cloudflare.com/generate_204",
      intervalSeconds: 60 + seed,
      toleranceMs: 20 + seed,
      endpoints: [
        { tag: `ep-a-${seed}`, protocol: "vless-reality-vision", weight: 100 },
        { tag: `ep-b-${seed}`, protocol: "vless-reality-vision", weight: 50 },
      ],
    });
    assert.equal(balancerA.digest, balancerB.digest);

    const dryRun = evaluatePanelImportDryRun(
      {
        sourcePanel: seed % 2 === 0 ? "3x-ui" : "s-ui",
        sourceVersion: `2.${seed}.0`,
        exportedAt: "2026-11-05T12:00:00Z",
        inbounds: [
          {
            tag: `fuzz-ib-${seed}`,
            protocol: seed % 3 === 0 ? "vmess-ws" : "vless-reality-vision",
            transport: "tcp",
            runtime: "singbox",
            listenPort: 10000 + seed,
            serverName: "www.cloudflare.com",
            realityPublicKey: "m4f8kLp2qR9vW1xY3zA5bC7dE9fG1hI3jK5lM7nO9pQ",
            realityShortId: "a1b2c3d4",
            clients: [
              {
                id: `uuid-${seed}`,
                emailOrName: `user${seed}@example.com`,
                enable: true,
                upBytes: seed * 1024,
                downBytes: seed * 2048,
                totalQuotaBytes: 0,
                expiryEpochMs: null,
              },
            ],
          },
        ],
      },
      [443],
    );
    if (seed % 3 === 0) {
      assert.equal(dryRun.rejectedInbounds.length, 1);
    } else {
      assert.equal(dryRun.admittedInbounds.length, 1);
      assert.equal(dryRun.historicalUsage[0]?.accountingClassification, "historical_non_billable");
    }
  }
});
