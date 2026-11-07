import "./setup-database";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  classifyResourceFreshness,
  InvalidSnapshotError,
  validateResourceSnapshot,
  type ResourceSnapshot,
} from "../../src/lib/observability";
import {
  advanceBackupTask,
  createBackupTask,
  InvalidBackupTaskError,
  InvalidBackupTransitionError,
} from "../../src/lib/backup-tasks";
import {
  computeSyncPageDigest,
  SyncFeedError,
  validateSyncPage,
  type SyncRecord,
} from "../../src/lib/syncfeed";
import {
  buildSignedEnvelope,
  PublicationApprovalError,
  validateApprovedPublicationWindow,
  validateDualOperatorApproval,
  verifySignedEnvelope,
  type ProposalRecord,
} from "../../src/lib/desired-approvals";

test("observability snapshot validates bounds, uniqueness and freshness separately from proxy health", () => {
  const now = new Date("2026-11-05T12:00:00Z");
  const valid: ResourceSnapshot = {
    nodeId: "fra-edge-1",
    generation: 3,
    sampledAt: new Date("2026-11-05T11:59:30Z"),
    cpuPercent: 24.5,
    memoryTotalBytes: 8 * 1024 ** 3,
    memoryUsedBytes: 3 * 1024 ** 3,
    filesystems: [{ id: "/", totalBytes: 80 * 1024 ** 3, usedBytes: 22 * 1024 ** 3 }],
    network: [{ interface: "eth0", receivedBytes: 104857600, sentBytes: 98304000 }],
  };

  validateResourceSnapshot(valid);
  assert.equal(classifyResourceFreshness(valid, now, 120_000), "fresh");
  assert.equal(classifyResourceFreshness(valid, new Date("2026-11-05T12:05:00Z"), 120_000), "stale");
  // Future sample is classified as unknown
  assert.equal(classifyResourceFreshness(valid, new Date("2026-11-05T11:58:00Z"), 120_000), "unknown");

  // Duplicate filesystem IDs fail closed
  assert.throws(
    () =>
      validateResourceSnapshot({
        ...valid,
        filesystems: [
          { id: "/", totalBytes: 1000, usedBytes: 200 },
          { id: "/", totalBytes: 2000, usedBytes: 300 },
        ],
      }),
    InvalidSnapshotError,
  );

  // Used memory exceeding total memory fails closed
  assert.throws(
    () =>
      validateResourceSnapshot({
        ...valid,
        memoryUsedBytes: valid.memoryTotalBytes + 1,
      }),
    InvalidSnapshotError,
  );
});

test("backup task lifecycle enforces transitions, monotonic clock, retry attempts and digest requirements", () => {
  const t0 = new Date("2026-11-05T10:00:00Z");
  const t1 = new Date("2026-11-05T10:01:00Z");
  const t2 = new Date("2026-11-05T10:02:00Z");
  const t3 = new Date("2026-11-05T10:03:00Z");

  let task = createBackupTask("bk-20261105-01", "backup", t0);
  assert.equal(task.state, "queued");
  assert.equal(task.attempt, 1);

  task = advanceBackupTask(task, "running", t1);
  assert.equal(task.state, "running");

  // Failing requires a short error code without CRLF
  assert.throws(() => advanceBackupTask(task, "failed", t2, "", ""), InvalidBackupTaskError);
  assert.throws(() => advanceBackupTask(task, "failed", t2, "", "ERR_IO\r\nINJECT"), InvalidBackupTaskError);

  task = advanceBackupTask(task, "failed", t2, "", "ERR_STORAGE_TIMEOUT");
  assert.equal(task.state, "failed");

  // Retry advances back to queued, increments attempt, and clears error code
  task = advanceBackupTask(task, "queued", t3);
  assert.equal(task.state, "queued");
  assert.equal(task.attempt, 2);
  assert.equal(task.errorCode, "");

  // Clock regression is rejected
  assert.throws(() => advanceBackupTask(task, "running", t1), InvalidBackupTransitionError);

  const t4 = new Date("2026-11-05T10:04:00Z");
  const t5 = new Date("2026-11-05T10:05:00Z");
  task = advanceBackupTask(task, "running", t4);

  // Succeeded requires artifact digest
  assert.throws(() => advanceBackupTask(task, "succeeded", t5, ""), InvalidBackupTaskError);
  task = advanceBackupTask(task, "succeeded", t5, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(task.state, "succeeded");

  // Terminal state cannot transition further
  assert.throws(
    () => advanceBackupTask(task, "queued", new Date("2026-11-05T10:06:00Z")),
    InvalidBackupTransitionError,
  );
});

test("syncfeed page validates contiguous sequences, tombstones, cursor alignment and length-prefixed digest", () => {
  const records: SyncRecord[] = [
    { sequence: 11, id: "principal-u1-i1", tombstone: false, payload: Buffer.from('{"active":true}', "utf8") },
    { sequence: 12, id: "principal-u2-i1", tombstone: true, payload: Buffer.alloc(0) },
  ];
  const digest = computeSyncPageDigest(records);

  const nextCursor = validateSyncPage(10, {
    baseCursor: 10,
    nextCursor: 12,
    records,
    digest,
  });
  assert.equal(nextCursor, 12);

  // Cursor mismatch
  assert.throws(
    () =>
      validateSyncPage(9, {
        baseCursor: 10,
        nextCursor: 12,
        records,
        digest,
      }),
    (err: unknown) => err instanceof SyncFeedError && err.code === "CURSOR_MISMATCH",
  );

  // Sequence gap triggers RESYNC_REQUIRED
  const gapped: SyncRecord[] = [
    { sequence: 11, id: "principal-u1-i1", tombstone: false, payload: Buffer.from("{}", "utf8") },
    { sequence: 13, id: "principal-u2-i1", tombstone: false, payload: Buffer.from("{}", "utf8") },
  ];
  assert.throws(
    () =>
      validateSyncPage(10, {
        baseCursor: 10,
        nextCursor: 12,
        records: gapped,
        digest: computeSyncPageDigest(gapped),
      }),
    (err: unknown) => err instanceof SyncFeedError && err.code === "RESYNC_REQUIRED",
  );

  // Non-empty tombstone payload is rejected
  const badTombstone: SyncRecord[] = [
    { sequence: 11, id: "principal-u1-i1", tombstone: true, payload: Buffer.from("not-empty", "utf8") },
  ];
  assert.throws(
    () =>
      validateSyncPage(10, {
        baseCursor: 10,
        nextCursor: 11,
        records: badTombstone,
        digest: computeSyncPageDigest(badTombstone),
      }),
    (err: unknown) => err instanceof SyncFeedError && err.code === "INVALID_PAGE",
  );
});

test("dual-operator desired-state approval enforces Ed25519 signature, distinct approver, digest match and one-time consumption", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const sign = (canonical: string) =>
    crypto.sign(null, Buffer.from(canonical, "utf8"), privateKey).toString("base64");

  const now = new Date("2026-11-05T14:00:00Z");
  const nodeUuid = "11111111-2222-4333-8444-555555555555";
  const epochUuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

  const built = buildSignedEnvelope({
    nodeUuid,
    controlPlaneEpoch: epochUuid,
    structuralSequence: 2,
    membershipSequence: 5,
    disruption: "reload",
    payload: { inbounds: [{ id: 1, port: 443, sni: "www.example.com" }] },
    keyId: "key-test-1",
    sign,
    now,
    ttlSeconds: 300,
  });

  const verified = verifySignedEnvelope(built.envelopeJson, {
    expectedNodeUuid: nodeUuid,
    expectedEpoch: epochUuid,
    publicKeyPem: pubPem,
    now,
  });
  assert.equal(verified.envelopeSha256, built.envelopeSha256);

  const proposal: ProposalRecord = {
    proposalId: "99999999-8888-4777-8666-555555555555",
    nodeId: 1,
    nodeUuid,
    controlPlaneEpoch: 1,
    structuralSequence: 2,
    membershipSequence: 5,
    disruption: "reload",
    envelopeJson: built.envelopeJson,
    envelopeSha256: built.envelopeSha256,
    proposerAdminId: 1,
    proposerEmail: "owner1@omnipanel.internal",
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
  };

  // Self-approval by proposerAdminId=1 is refused
  assert.throws(
    () =>
      validateDualOperatorApproval(proposal, {
        approverAdminId: 1,
        approverEmail: "owner1@omnipanel.internal",
        approverRole: "owner",
        expectedSha256: built.envelopeSha256,
        now,
      }),
    (err: unknown) => err instanceof PublicationApprovalError && err.code === "UNAUTHORIZED",
  );

  // A caller-controlled legacy bypass must not override independent approval.
  assert.throws(
    () =>
      validateDualOperatorApproval(proposal, {
        approverAdminId: 1,
        approverEmail: "owner1@omnipanel.internal",
        approverRole: "owner",
        expectedSha256: built.envelopeSha256,
        now,
        allowSelfApproval: true,
      }),
    (err: unknown) => err instanceof PublicationApprovalError && err.code === "UNAUTHORIZED",
  );

  // Wrong digest is refused
  assert.throws(
    () =>
      validateDualOperatorApproval(proposal, {
        approverAdminId: 2,
        approverEmail: "owner2@omnipanel.internal",
        approverRole: "owner",
        expectedSha256: "0".repeat(64),
        now,
      }),
    (err: unknown) => err instanceof PublicationApprovalError && err.code === "UNAUTHORIZED",
  );

  // Independent second owner with exact digest succeeds
  const decision = validateDualOperatorApproval(proposal, {
    approverAdminId: 2,
    approverEmail: "owner2@omnipanel.internal",
    approverRole: "owner",
    expectedSha256: built.envelopeSha256,
    now,
  });
  proposal.decision = decision;

  // Valid publication at head #1 -> #2
  validateApprovedPublicationWindow(
    proposal,
    { authorizedEpoch: 1, currentStructuralSeq: 1, currentMembershipSeq: 5 },
    now,
  );

  // Even with the old opt-in flag, self-reviewed decisions must never publish.
  const forgedSelfDecision: ProposalRecord = {
    ...proposal,
    decision: { ...decision, approverAdminId: proposal.proposerAdminId },
  };
  assert.throws(
    () =>
      validateApprovedPublicationWindow(
        forgedSelfDecision,
        { authorizedEpoch: 1, currentStructuralSeq: 1, currentMembershipSeq: 5 },
        now,
        { allowSelfApproval: true },
      ),
    (err: unknown) => err instanceof PublicationApprovalError && err.code === "UNAUTHORIZED",
  );

  // Sequence conflict if head is already #2
  assert.throws(
    () =>
      validateApprovedPublicationWindow(
        proposal,
        { authorizedEpoch: 1, currentStructuralSeq: 2, currentMembershipSeq: 5 },
        now,
      ),
    (err: unknown) => err instanceof PublicationApprovalError && err.code === "SEQUENCE_CONFLICT",
  );

  // Consumed approval cannot be replayed
  proposal.decision.consumedAt = now.toISOString();
  assert.throws(
    () =>
      validateApprovedPublicationWindow(
        proposal,
        { authorizedEpoch: 1, currentStructuralSeq: 1, currentMembershipSeq: 5 },
        now,
      ),
    (err: unknown) => err instanceof PublicationApprovalError && err.code === "UNAUTHORIZED",
  );
});

test("embedded pg-mem database seeds genesis audit chain, nodes, users, subscriptions, and governance records", async () => {
  const { db } = await import("../../src/db");
  const { verifyAuditChain } = await import("../../src/lib/audit");
  const { listUsers, usageForUser } = await import("../../src/lib/users");
  const { previewPublish } = await import("../../src/lib/revisions");
  const { buildIR } = await import("../../src/lib/subscription");
  const {
    getNodeResourceTelemetry,
    getNodeSyncFeedPage,
    listBackupTasks,
    listDesiredStateProposals,
    getSubscriptionProfileConfig,
  } = await import("../../src/lib/governance-store");

  const chain = await verifyAuditChain();
  assert.equal(chain.ok, true);
  assert.ok(chain.checked >= 10);

  const usersList = await listUsers();
  assert.equal(usersList.length, 2);

  const u1Usage = await usageForUser(db, 1);
  assert.ok(u1Usage.total > 0);

  const preview = await previewPublish(1);
  assert.equal(preview.manifest.node.name, "fra-edge-1");

  const subIr = await buildIR(1, "singbox");
  assert.equal(subIr.user.name, "Elena Rostova");

  const resTelemetry = await getNodeResourceTelemetry(1, new Date());
  assert.ok(resTelemetry.snapshot);
  assert.equal(resTelemetry.snapshot?.nodeId, "fra-edge-1");

  const syncFeed = await getNodeSyncFeedPage(1);
  assert.equal(syncFeed.verified, true);
  assert.equal(syncFeed.page.records.length, 2);

  const backups = await listBackupTasks();
  assert.equal(backups.length, 2);

  const proposals = await listDesiredStateProposals();
  assert.equal(proposals.length, 2);

  const profileCfg = await getSubscriptionProfileConfig();
  assert.equal(profileCfg.profileTitlePrefix, "OmniPanel");
});

test("read-only firewall inventory enforces SSH/loopback protection, private egress blocks and unmanaged rule separation", async () => {
  const {
    evaluateFirewallInventory,
    REQUIRED_PRIVATE_EGRESS_CIDRS,
  } = await import("../../src/lib/firewall-inventory");

  const validRules = [
    {
      ruleId: "fw-ssh-22",
      table: "inet filter",
      chain: "input",
      direction: "ingress" as const,
      protocol: "tcp" as const,
      portRange: "22",
      sourceCidr: "0.0.0.0/0",
      destinationCidr: "0.0.0.0/0",
      verdict: "accept" as const,
      ownedByOmniPanel: false,
      protectedRule: true,
      comment: "host-ssh",
    },
    {
      ruleId: "fw-mgmt-8443",
      table: "inet filter",
      chain: "input",
      direction: "ingress" as const,
      protocol: "tcp" as const,
      portRange: "8443",
      sourceCidr: "0.0.0.0/0",
      destinationCidr: "0.0.0.0/0",
      verdict: "accept" as const,
      ownedByOmniPanel: true,
      protectedRule: true,
      comment: "mgmt-gateway",
    },
  ];

  const report = evaluateFirewallInventory({
    nodeId: "fra-edge-1",
    engine: "nftables",
    generation: 4,
    sampledAt: "2026-11-05T12:00:00Z",
    loopbackAcceptPresent: true,
    protectedSshPort: 22,
    protectedManagementPort: 8443,
    privateEgressBlockedCidrs: [...REQUIRED_PRIVATE_EGRESS_CIDRS],
    rules: validRules,
  });

  assert.equal(report.valid, true);
  assert.equal(report.sshManagementProtected, true);
  assert.equal(report.loopbackProtected, true);
  assert.equal(report.privateEgressGuardComplete, true);
  assert.equal(report.invokesHostShell, false);
  assert.equal(report.ownedRuleCount, 1);
  assert.equal(report.unmanagedRuleCount, 1);

  // Dropping SSH port 22 before an accept rule is flagged as unsafe
  const droppingSsh = evaluateFirewallInventory({
    nodeId: "fra-edge-1",
    engine: "nftables",
    generation: 5,
    sampledAt: "2026-11-05T12:00:00Z",
    loopbackAcceptPresent: true,
    protectedSshPort: 22,
    protectedManagementPort: 8443,
    privateEgressBlockedCidrs: [...REQUIRED_PRIVATE_EGRESS_CIDRS],
    rules: [
      {
        ruleId: "fw-drop-ssh",
        table: "inet filter",
        chain: "input",
        direction: "ingress",
        protocol: "tcp",
        portRange: "22",
        sourceCidr: "0.0.0.0/0",
        destinationCidr: "0.0.0.0/0",
        verdict: "drop",
        ownedByOmniPanel: true,
        protectedRule: false,
      },
      ...validRules,
    ],
  });
  assert.equal(droppingSsh.valid, false);
  assert.equal(droppingSsh.sshManagementProtected, false);
});

test("certificate & ACME TLS boundary inventory enforces trust isolation, SPIFFE SANs and backoff without insecure fallback", async () => {
  const { evaluateCertificateInventory } = await import(
    "../../src/lib/certificate-inventory"
  );
  const now = new Date("2026-11-05T12:00:00Z");

  const summary = evaluateCertificateInventory(
    [
      {
        certId: "cert-mtls-1",
        nodeId: "fra-edge-1",
        domainOrSan: "spiffe://omnipanel/node/11111111-2222-4333-8444-555555555555",
        boundary: "node_mtls",
        issuer: "OmniPanel Internal Root CA",
        serialHex: "01ab23cd45ef6789",
        sha256Fingerprint: "a".repeat(64),
        notBefore: "2026-11-05T00:00:00Z",
        notAfter: "2026-11-06T00:00:00Z",
        autoRenewEnabled: true,
        failedRenewalAttempts: 0,
        allowInsecureFallback: false,
      },
      {
        certId: "cert-acme-1",
        nodeId: null,
        domainOrSan: "panel.omnipanel.internal",
        boundary: "acme_public_tls",
        issuer: "Let's Encrypt E6",
        serialHex: "99ab23cd45ef6789",
        sha256Fingerprint: "b".repeat(64),
        notBefore: "2026-10-15T00:00:00Z",
        notAfter: "2026-11-10T00:00:00Z",
        autoRenewEnabled: true,
        failedRenewalAttempts: 2,
        nextRetryAt: "2026-11-05T14:00:00Z",
        allowInsecureFallback: false,
      },
    ],
    now,
  );

  assert.equal(summary.valid, true);
  assert.equal(summary.counts.rate_limited_backoff, 1);

  // Self-signed fallback or allowInsecureFallback is rejected
  const badSummary = evaluateCertificateInventory(
    [
      {
        certId: "cert-bad",
        nodeId: null,
        domainOrSan: "panel.omnipanel.internal",
        boundary: "acme_public_tls",
        issuer: "Self",
        serialHex: "11223344",
        sha256Fingerprint: "c".repeat(64),
        notBefore: "2026-10-15T00:00:00Z",
        notAfter: "2026-12-10T00:00:00Z",
        autoRenewEnabled: true,
        failedRenewalAttempts: 0,
        allowInsecureFallback: true,
      },
    ],
    now,
  );
  assert.equal(badSummary.valid, false);
});

test("backup providers, AES-256-GCM DEK/KEK envelope encryption, S3 TLS enforcement and PITR + KEK recovery drill", async () => {
  const {
    validateBackupProviderConfig,
    encryptBackupArtifact,
    decryptBackupArtifact,
    verifyPitrAndKekRecoveryDrill,
  } = await import("../../src/lib/backup-providers");

  // S3 provider with tlsInsecureSkipVerify=true or http:// is rejected (1Panel audit fix)
  assert.throws(() =>
    validateBackupProviderConfig({
      kind: "s3_compatible",
      providerId: "s3-bad-tls",
      endpointUrl: "https://s3.eu-central-1.amazonaws.com",
      bucket: "omni-dr-vault",
      region: "eu-central-1",
      tlsVerifyPeer: false,
      tlsInsecureSkipVerify: true,
    }),
  );

  assert.throws(() =>
    validateBackupProviderConfig({
      kind: "s3_compatible",
      providerId: "s3-bad-http",
      endpointUrl: "http://s3.eu-central-1.amazonaws.com",
      bucket: "omni-dr-vault",
      region: "eu-central-1",
      tlsVerifyPeer: true,
      tlsInsecureSkipVerify: false,
    }),
  );

  const validProvider = {
    kind: "s3_compatible" as const,
    providerId: "s3-eu-vault",
    endpointUrl: "https://s3.eu-central-1.amazonaws.com",
    bucket: "omni-dr-vault",
    region: "eu-central-1",
    tlsVerifyPeer: true,
    tlsInsecureSkipVerify: false,
  };

  const kek = crypto.randomBytes(32);
  const wrongKek = crypto.randomBytes(32);
  const payload = Buffer.from('{"controlPlaneEpoch":3,"secretRefs":["sec-1","sec-2"]}', "utf8");

  const sealed = encryptBackupArtifact({
    artifactId: "snap-epoch-3",
    providerConfig: validProvider,
    kekId: "kek-2026-11",
    kekBytes: kek,
    controlPlaneEpoch: 3,
    walTargetLsn: "0/16B3748",
    plaintext: payload,
    now: new Date("2026-11-05T12:00:00Z"),
  });
  const unsealed = decryptBackupArtifact(sealed, kek);
  assert.deepEqual(unsealed, payload);

  // Wrong KEK fails closed
  assert.throws(() => decryptBackupArtifact(sealed, wrongKek));

  // Full PITR + KEK recovery drill requires declaredNextEpoch = previousEpoch + 1
  const drill = verifyPitrAndKekRecoveryDrill({
    envelope: sealed,
    independentKekBytes: kek,
    expectedPlaintextSha256: sealed.plaintextSha256,
    restoredAuditGenesisHash: "a".repeat(64),
    restoredAuditChainValid: true,
    previousEpoch: 3,
    declaredNextEpoch: 4,
    drillNow: new Date("2026-11-05T12:05:00Z"),
  });

  assert.equal(drill.verified, true);
  assert.equal(drill.previousEpoch, 3);
  assert.equal(drill.newAuthorizedEpoch, 4);
  assert.equal(drill.staleEpochEnvelopesRejected, true);
  assert.equal(drill.decryptedPayloadBytes, payload.length);
});

test("runtime-neutral live session registry distinguishes closed vs muted_unclosable QUIC sessions and blocks re-admission", async () => {
  const { LiveSessionRegistry } = await import("../../src/lib/session-registry");
  const reg = new LiveSessionRegistry();

  reg.authorizePrincipal("user-elena", 1);
  reg.registerSession({
    sessionId: "sess-tcp-1",
    principalId: "user-elena",
    credentialGeneration: 1,
    protocol: "vless-reality-vision",
    hasRuntimeCloser: true,
  });
  reg.registerSession({
    sessionId: "sess-quic-1",
    principalId: "user-elena",
    credentialGeneration: 1,
    protocol: "hysteria2",
    hasRuntimeCloser: false,
  });

  assert.equal(reg.canOpenNewFlow("sess-tcp-1"), true);
  assert.equal(reg.canOpenNewFlow("sess-quic-1"), true);

  const summary = reg.revokePrincipal("user-elena", "quota_suspended");
  assert.equal(summary.closedCount, 1);
  assert.equal(summary.mutedUnclosableCount, 1);
  // Because one session lacked a runtime closer, existingStreamsGuaranteedTerminated is false
  assert.equal(summary.existingStreamsGuaranteedTerminated, false);
  assert.equal(summary.newAuthenticationBlocked, true);
  assert.equal(summary.newRoutedFlowsBlocked, true);
  assert.equal(reg.canOpenNewFlow("sess-tcp-1"), false);
  assert.equal(reg.canOpenNewFlow("sess-quic-1"), false);

  // Re-authorizing user at generation 2 still refuses re-admission of revoked sessionId
  reg.authorizePrincipal("user-elena", 2);
  assert.throws(() =>
    reg.registerSession({
      sessionId: "sess-tcp-1",
      principalId: "user-elena",
      credentialGeneration: 2,
      protocol: "vless-reality-vision",
      hasRuntimeCloser: true,
    }),
  );
});

test("durable S-UI-inspired metering accumulator enforces persist-before-ack, WAL rollback, generation resets and at-least-once flush", async () => {
  const { DurableMeteringAccumulator } = await import("../../src/lib/durable-metering");
  let walBlob = "";

  const acc = new DurableMeteringAccumulator({ nodeId: "fra-edge-1", maxTrackedUsers: 10, maxDirtyWindow: 5 });

  // First sample in generation 1
  const r1 = acc.acceptDurable(
    {
      principalId: "u1-ib1",
      processGeneration: 1,
      sequence: 1,
      cumulativeUplinkBytes: 1000,
      cumulativeDownlinkBytes: 5000,
    },
    (json) => {
      walBlob = json;
    },
  );
  assert.equal(r1.replay, false);
  assert.equal(r1.deltaUplink, 1000);
  assert.equal(r1.deltaDownlink, 5000);

  // Exact replay is idempotent with zero delta
  const replay = acc.acceptDurable({
    principalId: "u1-ib1",
    processGeneration: 1,
    sequence: 1,
    cumulativeUplinkBytes: 1000,
    cumulativeDownlinkBytes: 5000,
  });
  assert.equal(replay.replay, true);
  assert.equal(replay.deltaUplink, 0);

  // Simulated WAL persistence failure rolls back in-memory state
  assert.throws(() =>
    acc.acceptDurable(
      {
        principalId: "u1-ib1",
        processGeneration: 1,
        sequence: 2,
        cumulativeUplinkBytes: 2500,
        cumulativeDownlinkBytes: 9000,
      },
      () => {
        throw new Error("ENOSPC: disk full");
      },
    ),
  );

  // Rehydrate from last committed WAL checkpoint and advance generation
  const rehydrated = DurableMeteringAccumulator.rehydrateFromWal(walBlob);
  const r2 = rehydrated.acceptDurable(
    {
      principalId: "u1-ib1",
      processGeneration: 2, // Runtime restarted; cumulative counters reset
      sequence: 1,
      cumulativeUplinkBytes: 400,
      cumulativeDownlinkBytes: 600,
    },
    (json) => {
      walBlob = json;
    },
  );
  assert.equal(r2.deltaUplink, 400);
  assert.equal(r2.checkpoint.trackedUsers[0].totalAccumulatedUplinkBytes, 1400);
  assert.equal(r2.checkpoint.trackedUsers[0].totalAccumulatedDownlinkBytes, 5600);

  // Failed remote flush keeps dirty flag set
  assert.throws(() =>
    rehydrated.flushDurable(() => {
      throw new Error("remote gateway 503");
    }),
  );
  assert.equal(rehydrated.exportCheckpoint().trackedUsers[0].dirty, true);

  // Successful remote flush clears dirty flag and emits absolute totals
  let delivered: unknown[] = [];
  const flushed = rehydrated.flushDurable((records) => {
    delivered = records;
  });
  assert.equal(flushed.length, 1);
  assert.equal(delivered.length, 1);
  assert.equal(rehydrated.exportCheckpoint().trackedUsers[0].dirty, false);
});

test("journaled agent reconciler & commit-confirm watchdog autonomously rolls back unconfirmed network changes", async () => {
  const { JournaledReconcileWatchdog } = await import("../../src/lib/reconcile-watchdog");
  const t0 = new Date("2026-11-05T12:00:00Z");

  const watchdog = new JournaledReconcileWatchdog({
    nodeId: "fra-edge-1",
    authorizedEpoch: 1,
    initialLastKnownGoodDigest: "a".repeat(64),
    initialAppliedSequence: 1,
    now: t0,
  });

  // Receiving manifest #2 does NOT advance appliedStructuralSequence
  let st = watchdog.recordReceivedManifest({
    epoch: 1,
    structuralSequence: 2,
    membershipSequence: 4,
    manifestDigest: "b".repeat(64),
    now: t0,
  });
  assert.equal(st.receivedStructuralSequence, 2);
  assert.equal(st.appliedStructuralSequence, 1);
  assert.equal(st.stage, "SIGNATURE_VERIFIED");

  watchdog.transitionStage("VALIDATED", { now: t0 });
  watchdog.transitionStage("STAGED", { now: t0 });
  watchdog.transitionStage("PREFLIGHTED", { now: t0 });
  watchdog.transitionStage("APPLYING", { now: t0 });
  st = watchdog.transitionStage("APPLIED_UNVERIFIED", { watchdogTimeoutSeconds: 30, now: t0 });
  assert.equal(st.watchdogArmed, true);
  assert.equal(st.appliedStructuralSequence, 1);

  // Before deadline (t0 + 15s), watchdog does not roll back
  const tickEarly = watchdog.evaluateIndependentWatchdogTick(new Date(t0.getTime() + 15_000));
  assert.equal(tickEarly.triggeredRollback, false);

  // After deadline (t0 + 35s), watchdog autonomously rolls back to lastKnownGoodDigest
  const tickExpired = watchdog.evaluateIndependentWatchdogTick(new Date(t0.getTime() + 35_000));
  assert.equal(tickExpired.triggeredRollback, true);
  assert.equal(tickExpired.state.stage, "ROLLED_BACK");
  assert.equal(tickExpired.state.appliedStructuralSequence, 1);
  assert.equal(tickExpired.state.lastKnownGoodDigest, "a".repeat(64));
});

test("enrollment grant service enforces trusted TOTP step-up, 2h idle session check, logout revocation and shared HMAC limiter", async () => {
  const { EnrollmentGrantService, SharedEnrollmentLimiter } = await import("../../src/lib/enrollment-grants");
  const { generateTotpSecret, generateTotp } = await import("../../src/lib/totp");

  const t0 = new Date("2026-11-05T12:00:00Z");
  const limiter = new SharedEnrollmentLimiter({
    hmacKey: Buffer.alloc(32, 7),
    maxPerPeerPerWindow: 2,
    maxGlobalPerWindow: 5,
  });

  assert.equal(limiter.checkAndAdmit("203.0.113.10", t0).allowed, true);
  assert.equal(limiter.checkAndAdmit("203.0.113.10", t0).allowed, true);
  const deniedPeer = limiter.checkAndAdmit("203.0.113.10", t0);
  assert.equal(deniedPeer.allowed, false);
  assert.equal(deniedPeer.reason, "peer_rate_limit_exceeded");

  const svc = new EnrollmentGrantService();
  const secret = generateTotpSecret();
  const nodeUuid = "11111111-2222-4333-8444-555555555555";

  svc.registerSession({
    sessionId: 101,
    adminId: 1,
    adminEmail: "owner1@omnipanel.internal",
    role: "owner",
    sessionTokenHash: "hash-session-101-first",
    createdAt: t0,
    lastSeenAt: t0,
    expiresAt: new Date(t0.getTime() + 8 * 3600_000),
    canIssueGrant: true,
    canApproveGrant: true,
    totpEnabled: true,
    totpSecretBase32: secret,
  });

  svc.setNodeAndOrgState({
    nodeId: 1,
    nodeUuid,
    organizationId: "org-main",
    nodeStatus: "pending_enrollment",
    organizationActive: true,
    bindingApproved: true,
  });

  // Legacy step-up source is refused
  svc.recordLegacyStepUp(101, 1, t0);
  assert.throws(() =>
    svc.issueEnrollmentGrant({
      issuerSessionId: 101,
      approverAdminId: 2,
      approverCanApprove: true,
      organizationId: "org-main",
      nodeId: 1,
      nodeUuid,
      now: t0,
    }),
  );

  // Trusted RFC 6238 TOTP step-up succeeds and blocks counter replay
  const code = generateTotp(secret, t0.getTime());
  svc.verifyTrustedStepUp({ sessionId: 101, totpCode: code, now: t0 });
  assert.throws(() => svc.verifyTrustedStepUp({ sessionId: 101, totpCode: code, now: t0 }));

  const issued = svc.issueEnrollmentGrant({
    issuerSessionId: 101,
    approverAdminId: 2,
    approverCanApprove: true,
    organizationId: "org-main",
    nodeId: 1,
    nodeUuid,
    now: t0,
  });

  // If issuer logs out before node redeems token, redemption fails closed
  svc.logoutSession(101);
  assert.throws(() =>
    svc.redeemGrantAndIssueCertificate({
      bearerToken: issued.bearerToken,
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
      now: new Date(t0.getTime() + 10_000),
    }),
  );

  // Even if session ID 101 is recycled with a different credential hash, old grant cannot be redeemed
  svc.registerSession({
    sessionId: 101,
    adminId: 1,
    adminEmail: "owner1@omnipanel.internal",
    role: "owner",
    sessionTokenHash: "hash-session-101-recycled",
    createdAt: new Date(t0.getTime() + 30_000),
    lastSeenAt: new Date(t0.getTime() + 30_000),
    expiresAt: new Date(t0.getTime() + 8 * 3600_000),
    canIssueGrant: true,
    canApproveGrant: true,
    totpEnabled: true,
    totpSecretBase32: secret,
  });
  assert.throws(() =>
    svc.redeemGrantAndIssueCertificate({
      bearerToken: issued.bearerToken,
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
      now: new Date(t0.getTime() + 35_000),
    }),
  );
});

test("dry-run S-UI / 3X-UI importer marks imported counters historical_non_billable and client balancer compiles deterministic groups", async () => {
  const { evaluatePanelImportDryRun } = await import("../../src/lib/panel-importer");
  const { compileClientBalancerDocument } = await import("../../src/lib/subscription-balancer");

  const report = evaluatePanelImportDryRun(
    {
      sourcePanel: "s-ui",
      sourceVersion: "1.3.2",
      exportedAt: "2026-11-05T12:00:00Z",
      inbounds: [
        {
          tag: "sui-vless-8444",
          protocol: "vless-reality-vision",
          transport: "tcp",
          runtime: "sing-box",
          listenPort: 8444,
          serverName: "www.microsoft.com",
          realityPublicKey: "m4f8kLp2qR9vW1xY3zA5bC7dE9fG1hI3jK5lM7nO9pQ",
          realityShortId: "01a2b3c4",
          clients: [
            {
              id: "u1",
              emailOrName: "alice@example.com",
              enable: true,
              upBytes: 1024,
              downBytes: 2048,
              totalQuotaBytes: 107_374_182_400,
              expiryEpochMs: Date.parse("2026-12-31T00:00:00Z"),
            },
          ],
        },
        {
          tag: "sui-vless-443-conflict",
          protocol: "vless-reality-vision",
          transport: "tcp",
          runtime: "sing-box",
          listenPort: 443,
          serverName: "www.microsoft.com",
          realityPublicKey: "m4f8kLp2qR9vW1xY3zA5bC7dE9fG1hI3jK5lM7nO9pQ",
          realityShortId: "01a2b3c4",
          clients: [],
        },
      ],
    },
    [443],
    [],
  );

  assert.equal(report.mode, "dry_run");
  assert.equal(report.admittedInbounds.length, 1);
  assert.equal(report.rejectedInbounds.length, 1);
  assert.equal(report.logicalUsers.length, 1);
  assert.equal(report.historicalUsage[0].accountingClassification, "historical_non_billable");

  const b1 = compileClientBalancerDocument({
    groupTag: "omni-auto",
    strategy: "url-test",
    probeUrl: "https://cp.cloudflare.com/generate_204",
    intervalSeconds: 180,
    toleranceMs: 50,
    endpoints: [
      { tag: "z-node", protocol: "vless-reality-vision" },
      { tag: "a-node", protocol: "vless-reality-vision" },
    ],
  });
  const b2 = compileClientBalancerDocument({
    groupTag: "omni-auto",
    strategy: "url-test",
    probeUrl: "https://cp.cloudflare.com/generate_204",
    intervalSeconds: 180,
    toleranceMs: 50,
    endpoints: [
      { tag: "a-node", protocol: "vless-reality-vision" },
      { tag: "z-node", protocol: "vless-reality-vision" },
    ],
  });

  assert.equal(b1.digest, b2.digest);
  assert.deepEqual(b1.memberTags, ["a-node", "z-node"]);
  assert.equal(b1.guaranteesServerSideFailover, false);
  assert.equal(b1.guaranteesExistingSessionMigration, false);
  assert.equal(b1.singboxOutboundsFragment.length, 1);
});

test("multi-driver config fragment renderers (singbox, hysteria2, xray), gate qualification matrix, and interactive governance store workflows preserve fail-closed invariants", async () => {
  const { renderRuntimeConfigFragment, GATE_QUALIFICATION_MATRIX } = await import(
    "../../src/lib/runtime-renderers"
  );
  const {
    mutateNodeReconcileWatchdogStage,
    mutateNodeSessionAndMetering,
    runEnrollmentAuthorityDrill,
    executePanelImportDryRun,
    commitPanelImportDryRun,
  } = await import("../../src/lib/governance-store");
  const { bulkSubscriberOperation } = await import("../../src/lib/users");

  assert.equal(GATE_QUALIFICATION_MATRIX.length, 7);
  assert.equal(
    GATE_QUALIFICATION_MATRIX.find((g) => g.gateTarget === "gate-lab")?.externalLabGateStatus,
    "BLOCKED",
  );

  for (const driver of ["singbox", "hysteria2", "xray"] as const) {
    const frag = renderRuntimeConfigFragment({
      nodeName: "fra-edge-1",
      driver,
      listenPort: 8443,
      serverName: "www.microsoft.com",
      principals: [
        { attributionKey: "u2-marcus", credentialUuidOrToken: "22222222-3333-4444-8555-666666666666" },
        { attributionKey: "u1-elena", credentialUuidOrToken: "11111111-2222-4333-8444-555555555555" },
      ],
    });
    assert.equal(frag.driver, driver);
    assert.equal(frag.privateEgressBlockedCidrs.length, 7);
    assert.ok(frag.configJson.includes("secretref://"));
  }

  // Interactive watchdog simulator: stage -> arm -> timeout rollback
  const staged = await mutateNodeReconcileWatchdogStage("admin:test", 1, "stage_candidate");
  assert.equal(staged.stage, "PREFLIGHTED");
  const rolledBack = await mutateNodeReconcileWatchdogStage("admin:test", 1, "trigger_watchdog_timeout");
  assert.equal(rolledBack.stage, "ROLLED_BACK");

  // Interactive live sessions & durable metering: sample -> revoke -> flush
  const sampled = await mutateNodeSessionAndMetering("admin:test", 1, "accept_sample");
  assert.ok(sampled.checkpoint.checkpointSequence >= 3);
  const revoked = await mutateNodeSessionAndMetering("admin:test", 1, "revoke_u1_sessions");
  assert.equal(revoked.lastRevocationSummary?.closedCount, 1);
  assert.equal(revoked.lastRevocationSummary?.mutedUnclosableCount, 1);
  assert.equal(revoked.lastRevocationSummary?.existingStreamsGuaranteedTerminated, false);

  // Enrollment authority drill: mint -> redeem -> logout
  const redeemed = await runEnrollmentAuthorityDrill("admin:test", "redeem_csr_mtls", "203.0.113.99");
  assert.equal(redeemed.grantStatus, "redeemed");
  assert.ok(redeemed.issuedCertificate?.spiffeUri.startsWith("spiffe://omnipanel/node/"));

  // Dry-run evaluation followed by atomic commit of non-conflicting dry-run users + bulk subscriber lifecycle
  await executePanelImportDryRun(
    "admin:test",
    "3x-ui",
    JSON.stringify({
      sourcePanel: "3x-ui",
      sourceVersion: "2.4.1",
      exportedAt: "2026-11-05T12:00:00Z",
      inbounds: [
        {
          tag: "legacy-vless-reality-8444",
          protocol: "vless-reality-vision",
          transport: "tcp",
          runtime: "xray",
          listenPort: 8444,
          serverName: "www.cloudflare.com",
          realityPublicKey: "m4f8kLp2qR9vW1xY3zA5bC7dE9fG1hI3jK5lM7nO9pQ",
          realityShortId: "a1b2c3d4",
          clients: [
            {
              id: "c1-uuid",
              emailOrName: "migrated.operator@omnipanel.internal",
              enable: true,
              upBytes: 1_048_576,
              downBytes: 2_097_152,
              totalQuotaBytes: 0,
              expiryEpochMs: null,
            },
          ],
        },
      ],
    }),
  );
  const committed = await commitPanelImportDryRun("admin:test");
  assert.equal(committed.importedUsers.length, 1);

  const bulkRes = await bulkSubscriberOperation(
    { label: "admin:test" },
    { operation: "extend_expiry_30d" },
  );
  assert.ok(bulkRes.affectedCount >= 3);
});




