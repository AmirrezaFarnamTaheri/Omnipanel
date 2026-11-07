import test from "node:test";
import assert from "node:assert/strict";
import { eq } from "drizzle-orm";
import { db } from "../../src/db";
import { admins, inbounds, nodes, settings, users } from "../../src/db/schema";
import { resolveAuthenticatedAdminFromToken } from "../../src/lib/auth";
import * as systemActions from "../../src/app/actions/system";
import { verifyAuditChain, recordAudit } from "../../src/lib/audit";
import {
  approveDesiredStateProposal,
  commitPanelImportDryRun,
  createDesiredStateProposal,
  executePanelImportDryRun,
  getNodeResourceTelemetry,
  listDesiredStateProposals,
  publishApprovedDesiredStateProposal,
} from "../../src/lib/governance-store";
import { createInbound } from "../../src/lib/nodes";
import { hotp, verifyTotpMatchedStep } from "../../src/lib/totp";
import { processAgentReportPayload } from "../../src/lib/agent-report";

test("P0-1: switchOperatorIdentityAction is removed and missing/invalid tokens return null", async () => {
  assert.equal(
    "switchOperatorIdentityAction" in systemActions,
    false,
    "switchOperatorIdentityAction must not be exported from system actions",
  );
  const unauthenticated = await resolveAuthenticatedAdminFromToken(undefined);
  assert.equal(unauthenticated, null);
  const invalidToken = await resolveAuthenticatedAdminFromToken("invalid-random-session-token");
  assert.equal(invalidToken, null);
});

test("P1-3: control-plane Ed25519 private key is encrypted at rest under KEK", async () => {
  const allAdmins = await db.select().from(admins).orderBy(admins.id);
  const owner = allAdmins[0]!;
  const [node] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  assert.ok(node, "seeded node must exist");

  await createDesiredStateProposal(owner, node.id, "Verify encrypted signing keypair at rest", 300);

  const [keyRow] = await db
    .select()
    .from(settings)
    .where(eq(settings.key, "desired.signing_keypair"));
  assert.ok(keyRow, "signing keypair row must exist");
  assert.equal(
    keyRow.value.includes("BEGIN PRIVATE KEY"),
    false,
    "plaintext PEM private key must never be stored in settings",
  );
  const parsed = JSON.parse(keyRow.value) as { publicKeyPem?: string; privateKeyEnc?: string };
  assert.ok(parsed.publicKeyPem?.includes("BEGIN PUBLIC KEY"));
  assert.ok(parsed.privateKeyEnc && parsed.privateKeyEnc.length > 32);
});

test("P1-4: publication detects candidate manifest drift, rolls back consumption on error, and supports 1-click personal self-approval", async () => {
  const allAdmins = await db.select().from(admins).orderBy(admins.id);
  const owner1 = allAdmins[0]!;
  const owner2 = allAdmins[1] ?? owner1;
  const [node] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  assert.ok(node);

  // 1. Create proposal and approve
  const propDrift = await createDesiredStateProposal(owner1, node.id, "Test drift detection", 300);
  await approveDesiredStateProposal(owner2, propDrift.proposalId, propDrift.envelopeSha256, {
    allowSelfApproval: true,
  });

  // Mutate an inbound port on the node before publishing to trigger CANDIDATE_MANIFEST_DRIFT
  const [ib] = await db.select().from(inbounds).where(eq(inbounds.nodeId, node.id)).limit(1);
  assert.ok(ib);
  const originalPort = ib.port;
  await db.update(inbounds).set({ port: originalPort + 10 }).where(eq(inbounds.id, ib.id));

  try {
    await assert.rejects(
      () => publishApprovedDesiredStateProposal(owner1, propDrift.proposalId, { allowSelfApproval: true }),
      /CANDIDATE_MANIFEST_DRIFT/,
    );
  } finally {
    await db.update(inbounds).set({ port: originalPort }).where(eq(inbounds.id, ib.id));
  }

  // Verify the failed publish did NOT mark the decision as consumed
  const afterDrift = (await listDesiredStateProposals()).find((p) => p.proposalId === propDrift.proposalId);
  assert.equal(afterDrift?.decision?.consumedAt, null, "failed publication must not leave decision consumed");

  // 2. Now that port is restored to originalPort, 1-click personal self-approved publish succeeds and consumes once
  const published = await publishApprovedDesiredStateProposal(owner1, propDrift.proposalId, {
    allowSelfApproval: true,
  });
  assert.ok(published.decision?.consumedAt, "successful publication must mark decision consumed");
  assert.ok(published.decision?.publishedRevisionSeq);

  // 3. Re-publishing an already consumed proposal must fail closed
  await assert.rejects(
    () => publishApprovedDesiredStateProposal(owner1, propDrift.proposalId, { allowSelfApproval: true }),
    /already been consumed/i,
  );
});

test("P0: unqualified inbound creation is denied even without a strictGate opt-in", async () => {
  const allAdmins = await db.select().from(admins).orderBy(admins.id);
  const owner = allAdmins[0]!;
  const [node] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  assert.ok(node);

  await assert.rejects(
    () => createInbound(
      { label: `admin:${owner.email}` },
      {
        nodeId: node.id,
        name: `unqualified-hy2-${Date.now()}`,
        runtime: "hysteria2",
        protocol: "hysteria2",
        port: 18443,
        sni: "www.cloudflare.com",
      },
    ),
    /unqualified|lab gate/i,
  );
});

test("P0: governance store must refuse single-owner approval even when old bypass flag is requested", async () => {
  const [owner] = await db.select().from(admins).where(eq(admins.role, "owner")).limit(1);
  const [node] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  assert.ok(owner && node);
  const proposal = await createDesiredStateProposal(owner, node.id, "self-approval must be denied", 300);
  await assert.rejects(
    () => approveDesiredStateProposal(owner, proposal.proposalId, proposal.envelopeSha256, { allowSelfApproval: true }),
    /Self-approval refused|distinct second owner/i,
  );
});

test("P1-5: transactional audit entries preserve unbroken hash-chain integrity", async () => {
  await db.transaction(async (tx) => {
    await recordAudit(tx, {
      actor: "admin:test@omnipanel.internal",
      action: "test.chain.1",
      objectType: "system",
      objectId: "1",
      detail: { step: 1 },
    });
    await recordAudit(tx, {
      actor: "admin:test@omnipanel.internal",
      action: "test.chain.2",
      objectType: "system",
      objectId: "2",
      detail: { step: 2 },
    });
  });
  const verification = await verifyAuditChain();
  assert.equal(verification.ok, true, "audit hash chain must remain valid");
});

test("P2-6: verifyTotpMatchedStep returns exact matched counter step across drift windows", () => {
  const secret = "JBSWY3DPEHPK3PXP";
  const fakeNowMs = 1_700_000_000_000;
  const currentStep = Math.floor(fakeNowMs / 30_000);
  const prevStepCode = hotp(secret, currentStep - 1);

  const matched = verifyTotpMatchedStep(secret, prevStepCode, fakeNowMs);
  assert.equal(matched, currentStep - 1, "must return exact matched step (currentStep - 1)");
  assert.equal(verifyTotpMatchedStep(secret, "000000", fakeNowMs), null);
});

test("P2-7: commitPanelImportDryRun enforces digest binding and atomic rollback on failure", async () => {
  await executePanelImportDryRun("admin:owner@omnipanel.internal", "3x-ui");
  await assert.rejects(
    () =>
      commitPanelImportDryRun("admin:owner@omnipanel.internal", {
        expectedDryRunDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      }),
    /digest mismatch/i,
  );

  // Inject a multi-user export and simulate failure after first user to prove atomic rollback
  const customExport = JSON.stringify({
    sourcePanel: "3x-ui",
    sourceVersion: "2.4.1",
    inbounds: [
      {
        tag: "atomic-test-ib",
        protocol: "vless-reality-vision",
        transport: "tcp",
        runtime: "singbox",
        listenPort: 29443,
        serverName: "www.cloudflare.com",
        realityPublicKey: "A".repeat(43),
        realityShortId: "01020304",
        clients: [
          {
            id: "atomic-rollback-user-1",
            emailOrName: "atomic-rollback-user-1",
            enable: true,
            upBytes: 1024,
            downBytes: 2048,
            totalQuotaBytes: 0,
            expiryEpochMs: null,
          },
          {
            id: "atomic-rollback-user-2",
            emailOrName: "atomic-rollback-user-2",
            enable: true,
            upBytes: 1024,
            downBytes: 2048,
            totalQuotaBytes: 0,
            expiryEpochMs: null,
          },
        ],
      },
    ],
  });
  const customReport = await executePanelImportDryRun("admin:owner@omnipanel.internal", "3x-ui", customExport);

  await assert.rejects(
    () =>
      commitPanelImportDryRun("admin:owner@omnipanel.internal", {
        expectedDryRunDigest: customReport.migrationJournalDigest,
        injectAfterCountCrash: 1,
      }),
    /Injected mid-batch migration commit failure/,
  );

  const leakedUsers = await db
    .select()
    .from(users)
    .where(eq(users.name, "atomic-rollback-user-1"));
  assert.equal(leakedUsers.length, 0, "first user must be rolled back when transaction fails on second user");
});

test("P2-8: processAgentReportPayload validates resourceSnapshot before mutating node state", async () => {
  const [node] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  assert.ok(node);
  const beforeSeq = node.appliedStructuralSeq;

  // Invalid resourceSnapshot (memoryUsedBytes > memoryTotalBytes) must reject before updating node
  await assert.rejects(
    () =>
      processAgentReportPayload(node, {
        epoch: 1,
        structuralSeq: beforeSeq + 99,
        membershipSeq: 1,
        state: "VERIFIED",
        resourceSnapshot: {
          generation: 1,
          sampledAt: new Date().toISOString(),
          cpuPercent: 20,
          memoryTotalBytes: 1000,
          memoryUsedBytes: 5000,
          filesystems: [{ id: "/", totalBytes: 1000, usedBytes: 500 }],
          network: [{ interface: "eth0", receivedBytes: 100, sentBytes: 100 }],
        },
      }),
    /Invalid resourceSnapshot/,
  );

  const [afterFailed] = await db.select().from(nodes).where(eq(nodes.id, node.id));
  assert.equal(
    afterFailed?.appliedStructuralSeq,
    beforeSeq,
    "node appliedStructuralSeq must not advance when resourceSnapshot validation fails",
  );

  // Valid payload updates node and persists agent_reported telemetry atomically
  await processAgentReportPayload(node, {
    epoch: 1,
    structuralSeq: beforeSeq,
    membershipSeq: node.appliedMembershipSeq,
    state: "VERIFIED",
    resourceSnapshot: {
      generation: 777,
      sampledAt: new Date().toISOString(),
      cpuPercent: 12.5,
      memoryTotalBytes: 8_589_934_592,
      memoryUsedBytes: 2_147_483_648,
      filesystems: [{ id: "/", totalBytes: 68_719_476_736, usedBytes: 17_179_869_184 }],
      network: [{ interface: "eth0", receivedBytes: 102400, sentBytes: 204800 }],
    },
  });

  const telemetry = await getNodeResourceTelemetry(node.id);
  assert.equal(telemetry.source, "agent_reported");
  assert.equal(telemetry.snapshot?.generation, 777);
});
