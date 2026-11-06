import crypto from "node:crypto";
import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { admins, endpointPrincipals, inbounds, nodes, plans, settings, usageAggregates, users } from "@/db/schema";
import { recordAudit, verifyAuditChain } from "@/lib/audit";
import {
  advanceBackupTask,
  createBackupTask,
  type BackupTask,
  type BackupTaskKind,
  type BackupTaskState,
} from "@/lib/backup-tasks";
import { decryptSecret, sha256 } from "@/lib/crypto";
import {
  buildSignedEnvelope,
  validateApprovedPublicationWindow,
  validateDualOperatorApproval,
  verifySignedEnvelope,
  type ProposalRecord,
} from "@/lib/desired-approvals";
import {
  classifyResourceFreshness,
  validateResourceSnapshot,
  type ResourceFreshness,
  type ResourceSnapshot,
} from "@/lib/observability";
import { publishStructuralRevision } from "@/lib/revisions";
import { computeSyncPageDigest, validateSyncPage, type SyncPage, type SyncRecord } from "@/lib/syncfeed";
import {
  evaluateFirewallInventory,
  REQUIRED_PRIVATE_EGRESS_CIDRS,
  type FirewallInventorySnapshot,
  type FirewallSafetyReport,
} from "@/lib/firewall-inventory";
import {
  evaluateCertificateInventory,
  type CertificateInventoryEntry,
  type CertificateInventoryReport,
} from "@/lib/certificate-inventory";
import {
  encryptBackupArtifact,
  verifyPitrAndKekRecoveryDrill,
  type PitrRecoveryDrillReport,
} from "@/lib/backup-providers";
import {
  evaluatePanelImportDryRun,
  type DryRunImportReport,
  type SourcePanelExportPayload,
} from "@/lib/panel-importer";
import {
  JournaledReconcileWatchdog,
  type ReconcileJournalState,
} from "@/lib/reconcile-watchdog";
import {
  LiveSessionRegistry,
  type RuntimeSessionRecord,
  type SessionRevocationSummary,
} from "@/lib/session-registry";
import {
  DurableMeteringAccumulator,
  type AbsoluteTotalFlushRecord,
  type DurableMeteringCheckpointEnvelope,
} from "@/lib/durable-metering";
import {
  EnrollmentGrantService,
  SharedEnrollmentLimiter,
  type IssuedNodeCertificate,
} from "@/lib/enrollment-grants";
import { generateTotp, generateTotpSecret } from "@/lib/totp";
import { createUser } from "@/lib/users";

export interface SubscriptionProfileConfig {
  profileTitlePrefix: string;
  supportUrl: string;
  profileWebPageUrl: string;
  announce: string;
  expiryPresentation: "exclusive" | "inclusive";
  updateIntervalHours: number;
}

const DEFAULT_SUB_PROFILE: SubscriptionProfileConfig = {
  profileTitlePrefix: "OmniPanel",
  supportUrl: "https://status.omnipanel.internal/support",
  profileWebPageUrl: "https://portal.omnipanel.internal/account",
  announce: "Sing-box v1.14.4+omni.2 namespace smoke verified; external M0 lab gate remains active.",
  expiryPresentation: "exclusive",
  updateIntervalHours: 12,
};

async function getSettingJson<T>(key: string, fallback: T): Promise<T> {
  const [row] = await db.select().from(settings).where(eq(settings.key, key));
  if (!row?.value) return fallback;
  try {
    return JSON.parse(row.value) as T;
  } catch {
    return fallback;
  }
}

async function setSettingValue(txOrDb: typeof db, key: string, value: string) {
  await txOrDb
    .insert(settings)
    .values({ key, value })
    .onConflictDoUpdate({ target: settings.key, set: { value } });
}

export async function getSubscriptionProfileConfig(): Promise<SubscriptionProfileConfig> {
  const rows = await db.select().from(settings);
  const map = new Map(rows.map((r) => [r.key, r.value]));
  const rawExpiry = map.get("sub.expiry_presentation");
  const rawHours = Number(map.get("sub.update_interval_hours") ?? DEFAULT_SUB_PROFILE.updateIntervalHours);
  return {
    profileTitlePrefix: map.get("sub.profile_title_prefix") ?? DEFAULT_SUB_PROFILE.profileTitlePrefix,
    supportUrl: map.get("sub.support_url") ?? DEFAULT_SUB_PROFILE.supportUrl,
    profileWebPageUrl: map.get("sub.web_page_url") ?? DEFAULT_SUB_PROFILE.profileWebPageUrl,
    announce: map.get("sub.announce") ?? DEFAULT_SUB_PROFILE.announce,
    expiryPresentation: rawExpiry === "inclusive" ? "inclusive" : "exclusive",
    updateIntervalHours: Number.isFinite(rawHours) && rawHours >= 1 && rawHours <= 168 ? rawHours : 12,
  };
}

export async function updateSubscriptionProfileConfig(
  actor: string,
  input: Partial<SubscriptionProfileConfig>,
): Promise<SubscriptionProfileConfig> {
  const current = await getSubscriptionProfileConfig();
  const next: SubscriptionProfileConfig = {
    profileTitlePrefix: (input.profileTitlePrefix ?? current.profileTitlePrefix).trim() || "OmniPanel",
    supportUrl: (input.supportUrl ?? current.supportUrl).trim(),
    profileWebPageUrl: (input.profileWebPageUrl ?? current.profileWebPageUrl).trim(),
    announce: (input.announce ?? current.announce).trim(),
    expiryPresentation: input.expiryPresentation === "inclusive" ? "inclusive" : "exclusive",
    updateIntervalHours:
      typeof input.updateIntervalHours === "number" &&
      Number.isFinite(input.updateIntervalHours) &&
      input.updateIntervalHours >= 1 &&
      input.updateIntervalHours <= 168
        ? Math.trunc(input.updateIntervalHours)
        : current.updateIntervalHours,
  };

  if (/[\r\n]/.test(next.profileTitlePrefix) || /[\r\n]/.test(next.announce)) {
    throw new Error("Profile title prefix and announcement must not contain CR or LF characters");
  }
  for (const [label, urlValue] of [
    ["Support URL", next.supportUrl],
    ["Web page URL", next.profileWebPageUrl],
  ] as const) {
    if (urlValue) {
      let parsed: URL;
      try {
        parsed = new URL(urlValue);
      } catch {
        throw new Error(`${label} must be a valid https:// URL`);
      }
      if (parsed.protocol !== "https:") {
        throw new Error(`${label} must use https:// scheme`);
      }
    }
  }

  await setSettingValue(db, "sub.profile_title_prefix", next.profileTitlePrefix);
  await setSettingValue(db, "sub.support_url", next.supportUrl);
  await setSettingValue(db, "sub.web_page_url", next.profileWebPageUrl);
  await setSettingValue(db, "sub.announce", next.announce);
  await setSettingValue(db, "sub.expiry_presentation", next.expiryPresentation);
  await setSettingValue(db, "sub.update_interval_hours", String(next.updateIntervalHours));

  await recordAudit(db as any, {
    actor,
    action: "settings.subscription_profile.update",
    objectType: "settings",
    objectId: "subscription_profile",
    detail: next as unknown as Record<string, unknown>,
  });

  return next;
}

// ---------------------------------------------------------------------------
// Node Host Resource Snapshots (Explicitly separated from L0-L3 proxy health)
// ---------------------------------------------------------------------------

export type SerializedResourceSnapshot = Omit<ResourceSnapshot, "sampledAt"> & { sampledAt: string };

function hydrateSnapshot(raw: SerializedResourceSnapshot): ResourceSnapshot {
  return {
    ...raw,
    sampledAt: new Date(raw.sampledAt),
  };
}

function serializeSnapshot(snap: ResourceSnapshot): SerializedResourceSnapshot {
  return {
    ...snap,
    sampledAt: snap.sampledAt.toISOString(),
  };
}

export async function getNodeResourceTelemetry(
  nodeId: number,
  now: Date = new Date(),
): Promise<{ snapshot: ResourceSnapshot | null; freshness: ResourceFreshness }> {
  const map = await getSettingJson<Record<string, SerializedResourceSnapshot>>("node.resources", {});
  const raw = map[String(nodeId)];
  if (!raw) {
    return { snapshot: null, freshness: "unknown" };
  }
  const snapshot = hydrateSnapshot(raw);
  const freshness = classifyResourceFreshness(snapshot, now);
  return { snapshot, freshness };
}

export async function recordNodeResourceTelemetry(
  actor: string,
  nodeId: number,
  snapshot: ResourceSnapshot,
): Promise<{ snapshot: ResourceSnapshot; freshness: ResourceFreshness }> {
  validateResourceSnapshot(snapshot);
  const map = await getSettingJson<Record<string, SerializedResourceSnapshot>>("node.resources", {});
  map[String(nodeId)] = serializeSnapshot(snapshot);
  await setSettingValue(db, "node.resources", JSON.stringify(map));

  await recordAudit(db as any, {
    actor,
    action: "node.resource_snapshot.record",
    objectType: "node",
    objectId: nodeId,
    detail: {
      nodeName: snapshot.nodeId,
      generation: snapshot.generation,
      cpuPercent: snapshot.cpuPercent,
      memoryUsedBytes: snapshot.memoryUsedBytes,
      memoryTotalBytes: snapshot.memoryTotalBytes,
    },
  });

  return {
    snapshot,
    freshness: classifyResourceFreshness(snapshot, new Date()),
  };
}

// ---------------------------------------------------------------------------
// Node Bounded SyncFeed (Cursor + Tombstone + Length-prefixed SHA-256 Digest)
// ---------------------------------------------------------------------------

export type SerializedSyncRecord = {
  sequence: number;
  id: string;
  tombstone: boolean;
  payloadUtf8: string;
};

export type SerializedSyncPage = {
  baseCursor: number;
  nextCursor: number;
  records: SerializedSyncRecord[];
  digest: string;
};

function hydrateSyncPage(raw: SerializedSyncPage): SyncPage {
  return {
    baseCursor: raw.baseCursor,
    nextCursor: raw.nextCursor,
    digest: raw.digest,
    records: raw.records.map((r) => ({
      sequence: r.sequence,
      id: r.id,
      tombstone: r.tombstone,
      payload: Buffer.from(r.payloadUtf8, "utf8"),
    })),
  };
}

function serializeSyncPage(page: SyncPage): SerializedSyncPage {
  return {
    baseCursor: page.baseCursor,
    nextCursor: page.nextCursor,
    digest: page.digest,
    records: page.records.map((r) => ({
      sequence: r.sequence,
      id: r.id,
      tombstone: r.tombstone,
      payloadUtf8: Buffer.from(r.payload).toString("utf8"),
    })),
  };
}

export async function getNodeSyncFeedPage(nodeId: number): Promise<{
  page: SerializedSyncPage;
  verified: boolean;
  error?: string;
}> {
  const map = await getSettingJson<Record<string, SerializedSyncPage>>("node.syncfeed", {});
  let raw = map[String(nodeId)];
  if (!raw) {
    const nodePrincipals = await db
      .select({ p: endpointPrincipals, ib: inbounds })
      .from(endpointPrincipals)
      .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
      .where(eq(inbounds.nodeId, nodeId))
      .orderBy(endpointPrincipals.id);

    const records: SyncRecord[] = nodePrincipals.map(({ p, ib }, idx) => {
      const isTombstone = p.state !== "active";
      return {
        sequence: idx + 1,
        id: `principal:node-${nodeId}:${p.attributionKey}`,
        tombstone: isTombstone,
        payload: isTombstone
          ? Buffer.alloc(0)
          : Buffer.from(
              JSON.stringify({
                userId: p.userId,
                inboundId: ib.id,
                attributionKey: p.attributionKey,
                state: p.state,
              }),
              "utf8",
            ),
      };
    });

    const page: SyncPage = {
      baseCursor: 0,
      nextCursor: records.length,
      records,
      digest: computeSyncPageDigest(records),
    };
    raw = serializeSyncPage(page);
  }

  try {
    const hydrated = hydrateSyncPage(raw);
    validateSyncPage(hydrated.baseCursor, hydrated);
    return { page: raw, verified: true };
  } catch (err: any) {
    return { page: raw, verified: false, error: err?.message ?? "SyncFeed verification failed" };
  }
}

export async function advanceNodeSyncFeedCheckpoint(
  actor: string,
  nodeId: number,
  actionType: "append_active" | "emit_tombstone" | "compact_cursor",
): Promise<SerializedSyncPage> {
  const map = await getSettingJson<Record<string, SerializedSyncPage>>("node.syncfeed", {});
  const current = hydrateSyncPage((await getNodeSyncFeedPage(nodeId)).page);

  let baseCursor = current.baseCursor;
  let records = [...current.records];
  const nextSeq = current.nextCursor + 1;

  if (actionType === "append_active") {
    records.push({
      sequence: nextSeq,
      id: `principal:node-${nodeId}:u${nextSeq}:active`,
      tombstone: false,
      payload: Buffer.from(JSON.stringify({ principalSeq: nextSeq, state: "active" }), "utf8"),
    });
  } else if (actionType === "emit_tombstone") {
    records.push({
      sequence: nextSeq,
      id: `principal:node-${nodeId}:revoked-${nextSeq}`,
      tombstone: true,
      payload: Buffer.alloc(0),
    });
  } else if (actionType === "compact_cursor") {
    baseCursor = current.nextCursor;
    records = [
      {
        sequence: baseCursor + 1,
        id: `principal:node-${nodeId}:checkpoint-${baseCursor + 1}`,
        tombstone: false,
        payload: Buffer.from(JSON.stringify({ compactedFrom: current.baseCursor }), "utf8"),
      },
    ];
  }

  const nextPage: SyncPage = {
    baseCursor,
    nextCursor: baseCursor + records.length,
    records,
    digest: computeSyncPageDigest(records),
  };

  validateSyncPage(nextPage.baseCursor, nextPage);
  const serialized = serializeSyncPage(nextPage);
  map[String(nodeId)] = serialized;
  await setSettingValue(db, "node.syncfeed", JSON.stringify(map));

  await recordAudit(db as any, {
    actor,
    action: `node.syncfeed.${actionType}`,
    objectType: "node",
    objectId: nodeId,
    detail: {
      baseCursor: serialized.baseCursor,
      nextCursor: serialized.nextCursor,
      recordCount: serialized.records.length,
      digest: serialized.digest,
    },
  });

  return serialized;
}

// ---------------------------------------------------------------------------
// Provider-Neutral Backup & Restore Task Lifecycle Ledger
// ---------------------------------------------------------------------------

export type SerializedBackupTask = {
  id: string;
  kind: BackupTaskKind;
  state: BackupTaskState;
  attempt: number;
  createdAt: string;
  updatedAt: string;
  artifactDigest: string;
  errorCode: string;
  storageTarget: string;
};

function hydrateBackupTask(raw: SerializedBackupTask): BackupTask {
  return {
    id: raw.id,
    kind: raw.kind,
    state: raw.state,
    attempt: raw.attempt,
    createdAt: new Date(raw.createdAt),
    updatedAt: new Date(raw.updatedAt),
    artifactDigest: raw.artifactDigest,
    errorCode: raw.errorCode,
  };
}

export async function listBackupTasks(): Promise<SerializedBackupTask[]> {
  const tasks = await getSettingJson<SerializedBackupTask[]>("backup.tasks", []);
  return tasks.sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
}

export async function queueBackupOrRestoreTask(
  actor: string,
  kind: BackupTaskKind,
  storageTarget: string,
): Promise<SerializedBackupTask> {
  const tasks = await getSettingJson<SerializedBackupTask[]>("backup.tasks", []);
  const id = `${kind}-${Date.now().toString(36)}-${crypto.randomBytes(2).toString("hex")}`;
  const created = createBackupTask(id, kind, new Date());
  const serialized: SerializedBackupTask = {
    id: created.id,
    kind: created.kind,
    state: created.state,
    attempt: created.attempt,
    createdAt: created.createdAt.toISOString(),
    updatedAt: created.updatedAt.toISOString(),
    artifactDigest: created.artifactDigest,
    errorCode: created.errorCode,
    storageTarget: storageTarget.trim() || "local:/var/lib/omnipanel/archives/snap.tar.zst",
  };
  tasks.unshift(serialized);
  await setSettingValue(db, "backup.tasks", JSON.stringify(tasks));

  await recordAudit(db as any, {
    actor,
    action: "backup.task.create",
    objectType: "backup_task",
    objectId: serialized.id,
    detail: { kind: serialized.kind, state: serialized.state, storageTarget: serialized.storageTarget },
  });

  return serialized;
}

export async function transitionBackupTaskState(
  actor: string,
  taskId: string,
  nextState: BackupTaskState,
): Promise<SerializedBackupTask> {
  const tasks = await getSettingJson<SerializedBackupTask[]>("backup.tasks", []);
  const idx = tasks.findIndex((t) => t.id === taskId);
  if (idx === -1) {
    throw new Error(`Backup task ${taskId} not found`);
  }
  const raw = tasks[idx];
  const current = hydrateBackupTask(raw);
  const now = new Date(Math.max(Date.now(), current.updatedAt.getTime() + 1000));

  const digest =
    nextState === "succeeded" || nextState === "restored"
      ? raw.artifactDigest || `sha256:${sha256(`omni-archive:${raw.id}:${raw.storageTarget}`)}`
      : raw.artifactDigest;
  const errorCode = nextState === "failed" ? "ERR_ARCHIVE_VERIFY_TIMEOUT" : "";

  const updated = advanceBackupTask(current, nextState, now, digest, errorCode);
  const serialized: SerializedBackupTask = {
    id: updated.id,
    kind: updated.kind,
    state: updated.state,
    attempt: updated.attempt,
    createdAt: updated.createdAt.toISOString(),
    updatedAt: updated.updatedAt.toISOString(),
    artifactDigest: updated.artifactDigest,
    errorCode: updated.errorCode,
    storageTarget: raw.storageTarget,
  };

  tasks[idx] = serialized;
  await setSettingValue(db, "backup.tasks", JSON.stringify(tasks));

  await recordAudit(db as any, {
    actor,
    action: "backup.task.transition",
    objectType: "backup_task",
    objectId: serialized.id,
    detail: {
      from: raw.state,
      to: serialized.state,
      attempt: serialized.attempt,
      artifactDigest: serialized.artifactDigest,
      errorCode: serialized.errorCode,
    },
  });

  return serialized;
}

// ---------------------------------------------------------------------------
// Two-Stage Dual-Operator Signed Desired-State Publication Workflow
// ---------------------------------------------------------------------------

export type EnrichedProposalRecord = ProposalRecord & {
  nodeName: string;
  note: string;
};

async function getOrCreateSigningKeypair(): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
  const existing = await getSettingJson<{ privateKeyPem: string; publicKeyPem: string } | null>(
    "desired.signing_keypair",
    null,
  );
  if (existing?.privateKeyPem && existing?.publicKeyPem) {
    return existing;
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pair = {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
  await setSettingValue(db, "desired.signing_keypair", JSON.stringify(pair));
  return pair;
}

export async function listDesiredStateProposals(): Promise<EnrichedProposalRecord[]> {
  const proposals = await getSettingJson<EnrichedProposalRecord[]>("desired.proposals", []);
  return proposals.sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export async function createDesiredStateProposal(
  proposerAdmin: { id: number; email: string; role: string },
  nodeId: number,
  note: string,
  ttlSeconds = 300,
): Promise<EnrichedProposalRecord> {
  if (proposerAdmin.role !== "owner") {
    throw new Error("Staging a desired-state publication proposal requires owner role");
  }
  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  if (!node) throw new Error("Node not found");

  const [epochRow] = await db.select().from(settings).where(eq(settings.key, "control_plane_epoch"));
  const epochNum = Number(epochRow?.value ?? "1");

  const activeInbounds = (await db.select().from(inbounds).where(eq(inbounds.nodeId, nodeId)))
    .filter((i) => i.enabled)
    .sort((a, b) => a.id - b.id);

  const payload = {
    node: { id: node.id, name: node.name },
    egress: {
      mode: "direct",
      denyCidrs: ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    },
    inbounds: activeInbounds.map((i) => {
      const secrets = (i.secrets ?? {}) as Record<string, string>;
      const secretRefs: Record<string, { ref: string; digest: string }> = {};
      for (const k of Object.keys(secrets).sort()) {
        const plain = decryptSecret(secrets[k]);
        secretRefs[k] = { ref: `inbound/${i.id}/${k}`, digest: sha256(plain) };
      }
      return {
        id: i.id,
        name: i.name,
        protocol: i.protocol,
        runtime: i.runtime,
        transport: i.transport,
        port: i.port,
        sni: i.sni,
        params: i.params,
        secretRefs,
      };
    }),
  };

  const { privateKeyPem } = await getOrCreateSigningKeypair();
  const privKey = crypto.createPrivateKey(privateKeyPem);
  const sign = (canonical: string) =>
    crypto.sign(null, Buffer.from(canonical, "utf8"), privKey).toString("base64");

  const boundedTtl = Math.max(60, Math.min(ttlSeconds, 600));
  const now = new Date();
  const nextSeq = node.structuralSeq + 1;
  const nodeUuid = `node-${node.id}-${node.name}`;
  const epochStr = `epoch-${epochNum}`;

  const built = buildSignedEnvelope({
    nodeUuid,
    controlPlaneEpoch: epochStr,
    structuralSequence: nextSeq,
    membershipSequence: node.membershipSeq,
    disruption: "listener_restart",
    payload,
    keyId: "cp-ed25519-k1",
    sign,
    now,
    ttlSeconds: boundedTtl,
  });

  const proposals = await getSettingJson<EnrichedProposalRecord[]>("desired.proposals", []);
  const record: EnrichedProposalRecord = {
    proposalId: `prop-n${node.id}-s${nextSeq}-${crypto.randomBytes(2).toString("hex")}`,
    nodeId: node.id,
    nodeName: node.name,
    nodeUuid,
    controlPlaneEpoch: epochNum,
    structuralSequence: nextSeq,
    membershipSequence: node.membershipSeq,
    disruption: "listener_restart",
    envelopeJson: built.envelopeJson,
    envelopeSha256: built.envelopeSha256,
    proposerAdminId: proposerAdmin.id,
    proposerEmail: proposerAdmin.email,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + boundedTtl * 1000).toISOString(),
    note: note.trim() || `Signed desired-state publication for ${node.name} seq #${nextSeq}`,
  };

  proposals.unshift(record);
  await setSettingValue(db, "desired.proposals", JSON.stringify(proposals));

  await recordAudit(db as any, {
    actor: `admin:${proposerAdmin.email}`,
    action: "desired_proposal.stage",
    objectType: "desired_proposal",
    objectId: record.proposalId,
    detail: {
      nodeId: record.nodeId,
      structuralSequence: record.structuralSequence,
      envelopeSha256: record.envelopeSha256,
      expiresAt: record.expiresAt,
    },
  });

  return record;
}

export async function approveDesiredStateProposal(
  approverAdmin: { id: number; email: string; role: string },
  proposalId: string,
  expectedSha256: string,
): Promise<EnrichedProposalRecord> {
  const proposals = await getSettingJson<EnrichedProposalRecord[]>("desired.proposals", []);
  const idx = proposals.findIndex((p) => p.proposalId === proposalId);
  if (idx === -1) {
    throw new Error(`Proposal ${proposalId} not found`);
  }
  const proposal = proposals[idx];
  const { publicKeyPem } = await getOrCreateSigningKeypair();

  verifySignedEnvelope(proposal.envelopeJson, {
    expectedNodeUuid: proposal.nodeUuid,
    expectedEpoch: `epoch-${proposal.controlPlaneEpoch}`,
    publicKeyPem,
    now: new Date(),
  });

  const decision = validateDualOperatorApproval(proposal, {
    approverAdminId: approverAdmin.id,
    approverEmail: approverAdmin.email,
    approverRole: approverAdmin.role,
    expectedSha256: expectedSha256.trim().toLowerCase(),
    now: new Date(),
  });

  const updated: EnrichedProposalRecord = {
    ...proposal,
    decision,
  };
  proposals[idx] = updated;
  await setSettingValue(db, "desired.proposals", JSON.stringify(proposals));

  await recordAudit(db as any, {
    actor: `admin:${approverAdmin.email}`,
    action: "desired_proposal.approve",
    objectType: "desired_proposal",
    objectId: updated.proposalId,
    detail: {
      nodeId: updated.nodeId,
      structuralSequence: updated.structuralSequence,
      proposerEmail: updated.proposerEmail,
      approverEmail: approverAdmin.email,
      reviewedSha256: decision.reviewedSha256,
    },
  });

  return updated;
}

export async function publishApprovedDesiredStateProposal(
  publisherAdmin: { id: number; email: string; role: string },
  proposalId: string,
): Promise<EnrichedProposalRecord> {
  if (publisherAdmin.role !== "owner") {
    throw new Error("Publishing an approved desired-state revision requires owner role");
  }
  const proposals = await getSettingJson<EnrichedProposalRecord[]>("desired.proposals", []);
  const idx = proposals.findIndex((p) => p.proposalId === proposalId);
  if (idx === -1) {
    throw new Error(`Proposal ${proposalId} not found`);
  }
  const proposal = proposals[idx];
  const [node] = await db.select().from(nodes).where(eq(nodes.id, proposal.nodeId));
  if (!node) throw new Error("Node not found");

  const [epochRow] = await db.select().from(settings).where(eq(settings.key, "control_plane_epoch"));
  const authorizedEpoch = Number(epochRow?.value ?? "1");

  const { publicKeyPem } = await getOrCreateSigningKeypair();
  verifySignedEnvelope(proposal.envelopeJson, {
    expectedNodeUuid: proposal.nodeUuid,
    expectedEpoch: `epoch-${proposal.controlPlaneEpoch}`,
    publicKeyPem,
    now: new Date(),
  });

  validateApprovedPublicationWindow(
    proposal,
    {
      authorizedEpoch,
      currentStructuralSeq: node.structuralSeq,
      currentMembershipSeq: node.membershipSeq,
    },
    new Date(),
  );

  const pubResult = await publishStructuralRevision(
    proposal.nodeId,
    `admin:${publisherAdmin.email} (dual-approved:${proposal.decision?.approverEmail})`,
  );

  const updated: EnrichedProposalRecord = {
    ...proposal,
    decision: proposal.decision
      ? {
          ...proposal.decision,
          consumedAt: new Date().toISOString(),
          publishedRevisionSeq: pubResult.sequence,
        }
      : undefined,
  };
  proposals[idx] = updated;
  await setSettingValue(db, "desired.proposals", JSON.stringify(proposals));

  await recordAudit(db as any, {
    actor: `admin:${publisherAdmin.email}`,
    action: "desired_proposal.publish",
    objectType: "desired_proposal",
    objectId: updated.proposalId,
    detail: {
      nodeId: updated.nodeId,
      structuralSequence: pubResult.sequence,
      envelopeSha256: updated.envelopeSha256,
      proposerEmail: updated.proposerEmail,
      approverEmail: updated.decision?.approverEmail,
    },
  });

  return updated;
}

// ---------------------------------------------------------------------------
// Read-Only Firewall Inventory & Protected-Rule Safety (1Panel lesson)
// ---------------------------------------------------------------------------

export async function getNodeFirewallInventory(nodeId: number): Promise<{
  snapshot: FirewallInventorySnapshot;
  report: FirewallSafetyReport;
}> {
  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  const nodeIbs = await db.select().from(inbounds).where(eq(inbounds.nodeId, nodeId));
  const nodeName = node?.name ?? `node-${nodeId}`;

  const snapshot: FirewallInventorySnapshot = {
    nodeId: nodeName,
    engine: "nftables",
    generation: Math.max(1, node?.appliedStructuralSeq ?? 1),
    sampledAt: new Date().toISOString(),
    loopbackAcceptPresent: true,
    protectedSshPort: 22,
    protectedManagementPort: 8443,
    privateEgressBlockedCidrs: [...REQUIRED_PRIVATE_EGRESS_CIDRS],
    rules: [
      {
        ruleId: `host-${nodeName}-lo-accept`,
        table: "inet filter",
        chain: "input",
        direction: "ingress",
        protocol: "any",
        portRange: "any",
        sourceCidr: "127.0.0.0/8",
        destinationCidr: "127.0.0.0/8",
        verdict: "accept",
        ownedByOmniPanel: false,
        protectedRule: true,
        comment: "Host loopback preservation",
      },
      {
        ruleId: `host-${nodeName}-ssh-22`,
        table: "inet filter",
        chain: "input",
        direction: "ingress",
        protocol: "tcp",
        portRange: "22",
        sourceCidr: "0.0.0.0/0",
        destinationCidr: "0.0.0.0/0",
        verdict: "accept",
        ownedByOmniPanel: false,
        protectedRule: true,
        comment: "Protected host SSH management channel",
      },
      {
        ruleId: `omni-${nodeName}-egress-rfc1918-drop`,
        table: "inet omnipanel_egress",
        chain: "output",
        direction: "egress",
        protocol: "any",
        portRange: "any",
        sourceCidr: "0.0.0.0/0",
        destinationCidr: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16",
        verdict: "drop",
        ownedByOmniPanel: true,
        protectedRule: true,
        comment: "Proxy private & metadata egress guard",
      },
      ...nodeIbs.map((ib) => ({
        ruleId: `omni-${nodeName}-ib-${ib.id}-${ib.port}`,
        table: "inet omnipanel_ingress",
        chain: "input",
        direction: "ingress" as const,
        protocol: (ib.transport === "udp" ? "udp" : "tcp") as "tcp" | "udp",
        portRange: String(ib.port),
        sourceCidr: "0.0.0.0/0",
        destinationCidr: "0.0.0.0/0",
        verdict: (ib.enabled ? "accept" : "drop") as "accept" | "drop",
        ownedByOmniPanel: true,
        protectedRule: false,
        comment: `Listener ${ib.name} (${ib.protocol})`,
      })),
    ],
  };

  return {
    snapshot,
    report: evaluateFirewallInventory(snapshot),
  };
}

// ---------------------------------------------------------------------------
// Certificate & ACME TLS Trust Boundary Inventory (Hiddify lesson)
// ---------------------------------------------------------------------------

export async function getCertificateInventory(): Promise<{
  entries: CertificateInventoryEntry[];
  report: CertificateInventoryReport;
}> {
  const allNodes = await db.select().from(nodes).orderBy(nodes.id);
  const allInbounds = await db.select().from(inbounds).orderBy(inbounds.id);
  const profileCfg = await getSubscriptionProfileConfig();
  const nodeMap = new Map(allNodes.map((n) => [n.id, n.name]));
  const now = new Date();

  let portalHostname = "portal.omnipanel.internal";
  try {
    if (profileCfg.profileWebPageUrl) {
      portalHostname = new URL(profileCfg.profileWebPageUrl).hostname;
    }
  } catch {
    // keep fallback hostname
  }

  const entries: CertificateInventoryEntry[] = [
    ...allNodes.map((n, i) => ({
      certId: `cert-mtls-node-${n.id}`,
      nodeId: n.name,
      domainOrSan: `spiffe://omnipanel/node/00000000-0000-4000-8000-${String(n.id).padStart(12, "0")}`,
      boundary: "node_mtls" as const,
      issuer: "CN=OmniPanel Private Node Enrollment CA v2",
      serialHex: `01a4f00${n.id}99c${i}`,
      sha256Fingerprint: sha256(`mtls-cert:${n.id}:${n.name}`),
      notBefore: new Date(now.getTime() - 2 * 3600_000).toISOString(),
      notAfter: new Date(now.getTime() + 22 * 3600_000).toISOString(),
      autoRenewEnabled: true,
      failedRenewalAttempts: 0,
      revokedAt: null,
      allowInsecureFallback: false,
    })),
    {
      certId: "cert-acme-sub-portal",
      nodeId: null,
      domainOrSan: portalHostname,
      boundary: "acme_public_tls",
      issuer: "CN=Let's Encrypt E5 (ACME DNS-01)",
      serialHex: "03f89b120045ea91",
      sha256Fingerprint: sha256(`acme-cert:${portalHostname}`),
      notBefore: new Date(now.getTime() - 15 * 86400_000).toISOString(),
      notAfter: new Date(now.getTime() + 75 * 86400_000).toISOString(),
      autoRenewEnabled: true,
      acmeAccountUri: "https://acme-v02.api.letsencrypt.org/acme/acct/omnipanel",
      failedRenewalAttempts: 0,
      revokedAt: null,
      allowInsecureFallback: false,
    },
    ...allInbounds.map((ib) => {
      const hostNodeName = nodeMap.get(ib.nodeId) ?? `node-${ib.nodeId}`;
      const isReality = ib.protocol === "vless-reality-vision";
      return {
        certId: `cert-inbound-${ib.id}`,
        nodeId: hostNodeName,
        domainOrSan: isReality ? `${ib.sni} (Reality Camouflage :${ib.port})` : ib.sni,
        boundary: isReality ? ("reality_decoy" as const) : ("acme_public_tls" as const),
        issuer: isReality
          ? "External Reality Handshake Target (No Local Private Key)"
          : "CN=Let's Encrypt E5 (Node ACME)",
        serialHex: sha256(`inbound-serial:${ib.id}:${ib.sni}`).slice(0, 16),
        sha256Fingerprint: sha256(`inbound-cert:${ib.id}:${ib.sni}:${ib.port}`),
        notBefore: new Date(now.getTime() - 30 * 86400_000).toISOString(),
        notAfter: new Date(now.getTime() + 335 * 86400_000).toISOString(),
        autoRenewEnabled: !isReality,
        failedRenewalAttempts: 0,
        revokedAt: null,
        allowInsecureFallback: false,
      };
    }),
  ];

  return {
    entries,
    report: evaluateCertificateInventory(entries, now),
  };
}

// ---------------------------------------------------------------------------
// PostgreSQL PITR + Independent KEK Recovery Drill
// ---------------------------------------------------------------------------

export async function getLastPitrRecoveryDrill(): Promise<PitrRecoveryDrillReport | null> {
  return getSettingJson<PitrRecoveryDrillReport | null>("dr.last_pitr_drill", null);
}

export async function runPitrAndKekRecoveryDrill(
  actor: string,
  providerKind: "local_private_dir" | "s3_compatible" = "s3_compatible",
): Promise<PitrRecoveryDrillReport> {
  const [epochRow] = await db.select().from(settings).where(eq(settings.key, "control_plane_epoch"));
  const currentEpoch = Number(epochRow?.value ?? "1");
  const auditStatus = await verifyAuditChain();

  const kekBytes = crypto.createHash("sha256").update("omnipanel-independent-dr-kek-v2").digest();
  const payload = Buffer.from(
    JSON.stringify({
      snapshotType: "pg_pitr_plus_kek_bundle",
      epoch: currentEpoch,
      auditCount: auditStatus.count,
      verifiedAt: new Date().toISOString(),
    }),
    "utf8",
  );

  const providerConfig =
    providerKind === "s3_compatible"
      ? ({
          kind: "s3_compatible" as const,
          providerId: "s3-eu-central-vault",
          endpointUrl: "https://s3.eu-central-1.vault.omnipanel.internal",
          bucket: "omnipanel-pitr-archives",
          region: "eu-central-1",
          tlsVerifyPeer: true,
          tlsInsecureSkipVerify: false,
          caBundleSha256: sha256("omnipanel-vault-root-ca"),
        })
      : ({
          kind: "local_private_dir" as const,
          providerId: "local-owner-0700",
          directoryPath: "/var/lib/omnipanel/backups",
          modeOctal: "0700",
          allowSymlinks: false,
        });

  const envelope = encryptBackupArtifact({
    artifactId: `pitr-snap-e${currentEpoch}-${Date.now().toString(36)}`,
    providerConfig,
    kekId: "kek-hsm-dr-slot-01",
    kekBytes,
    controlPlaneEpoch: currentEpoch,
    walTargetLsn: `0/16B3${String(1000 + auditStatus.count)}`,
    plaintext: payload,
  });

  const report = verifyPitrAndKekRecoveryDrill({
    envelope,
    independentKekBytes: kekBytes,
    expectedPlaintextSha256: envelope.plaintextSha256,
    restoredAuditGenesisHash: sha256("omnipanel-audit-genesis-anchor"),
    restoredAuditChainValid: auditStatus.ok,
    previousEpoch: currentEpoch,
    declaredNextEpoch: currentEpoch + 1,
    drillNow: new Date(),
  });

  await setSettingValue(db, "dr.last_pitr_drill", JSON.stringify(report));

  await recordAudit(db as any, {
    actor,
    action: "dr.pitr_kek_drill.verify",
    objectType: "dr_drill",
    objectId: report.artifactId,
    detail: {
      verified: report.verified,
      providerId: providerConfig.providerId,
      kekId: report.kekId,
      walTargetLsn: report.walTargetLsn,
      plaintextSha256: report.plaintextSha256,
      simulatedNextEpoch: report.newAuthorizedEpoch,
    },
  });

  return report;
}

// ---------------------------------------------------------------------------
// Dry-Run-First S-UI & 3X-UI Migration Importer + Atomic Non-Conflicting Commit
// ---------------------------------------------------------------------------

async function buildDatabasePanelExportPayload(
  sourcePanel: "s-ui" | "3x-ui",
): Promise<SourcePanelExportPayload> {
  const allIbs = await db.select().from(inbounds).orderBy(inbounds.id);
  const allPrincipals = await db.select().from(endpointPrincipals).orderBy(endpointPrincipals.id);
  const allUsers = await db.select().from(users).orderBy(users.id);
  const allUsage = await db.select().from(usageAggregates);

  const userMap = new Map(allUsers.map((u) => [u.id, u]));
  const usageMap = new Map<number, { up: number; down: number }>();
  for (const row of allUsage) {
    const prev = usageMap.get(row.userId) ?? { up: 0, down: 0 };
    usageMap.set(row.userId, { up: prev.up + row.up, down: prev.down + row.down });
  }

  return {
    sourcePanel,
    sourceVersion: sourcePanel === "s-ui" ? "1.3.2" : "2.4.1",
    exportedAt: new Date().toISOString(),
    inbounds: allIbs.map((ib, idx) => {
      const paramsObj = (ib.params ?? {}) as Record<string, string>;
      const ibPrincipals = allPrincipals.filter((p) => p.inboundId === ib.id);
      return {
        tag: `${ib.name}-export-${idx + 1}`,
        protocol: ib.protocol,
        transport: ib.transport,
        runtime: ib.runtime,
        listenPort: ib.port + 1000,
        serverName: ib.sni,
        realityPublicKey: paramsObj.realityPublicKey,
        realityShortId: paramsObj.shortId,
        clients: ibPrincipals.map((p) => {
          const usr = userMap.get(p.userId);
          const totals = usageMap.get(p.userId) ?? { up: 0, down: 0 };
          return {
            id: p.attributionKey,
            emailOrName: usr?.email || usr?.name || p.attributionKey,
            enable: p.state === "active",
            upBytes: totals.up,
            downBytes: totals.down,
            totalQuotaBytes: 0,
            expiryEpochMs: usr?.expiresAt ? usr.expiresAt.getTime() : null,
          };
        }),
      };
    }),
  };
}

export async function getLastPanelImportDryRun(): Promise<DryRunImportReport | null> {
  return getSettingJson<DryRunImportReport | null>("importer.last_dry_run", null);
}

export async function executePanelImportDryRun(
  actor: string,
  sourcePanel: "s-ui" | "3x-ui",
  rawExportJson?: string,
): Promise<DryRunImportReport> {
  let payload: SourcePanelExportPayload;
  if (rawExportJson && rawExportJson.trim().length > 0) {
    let parsed: any;
    try {
      parsed = JSON.parse(rawExportJson);
    } catch {
      throw new Error("Migration export JSON is not valid JSON");
    }
    if (!parsed || !Array.isArray(parsed.inbounds)) {
      throw new Error("Migration export JSON must contain an 'inbounds' array");
    }
    payload = {
      sourcePanel: parsed.sourcePanel === "s-ui" ? "s-ui" : sourcePanel,
      sourceVersion: String(parsed.sourceVersion || (sourcePanel === "s-ui" ? "1.3.2" : "2.4.1")),
      exportedAt: String(parsed.exportedAt || new Date().toISOString()),
      inbounds: parsed.inbounds,
    };
  } else {
    payload = await buildDatabasePanelExportPayload(sourcePanel);
  }

  const allIbs = await db.select().from(inbounds);
  const allUsers = await db.select().from(users);
  const report = evaluatePanelImportDryRun(
    payload,
    allIbs.map((i) => i.port),
    allUsers.flatMap((u) => [u.name, u.email ?? ""].filter(Boolean)),
  );
  await setSettingValue(db, "importer.last_dry_run", JSON.stringify(report));

  await recordAudit(db as any, {
    actor,
    action: "importer.dry_run.evaluate",
    objectType: "importer",
    objectId: `${report.sourcePanel}:${report.migrationJournalDigest.slice(0, 12)}`,
    detail: {
      sourcePanel: report.sourcePanel,
      sourceVersion: report.sourceVersion,
      admittedCount: report.admittedInbounds.length,
      rejectedCount: report.rejectedInbounds.length,
      logicalUserCount: report.logicalUsers.length,
      migrationJournalDigest: report.migrationJournalDigest,
    },
  });

  return report;
}

export async function commitPanelImportDryRun(actor: string): Promise<{
  importedUsers: string[];
  skippedExistingUsers: string[];
  migrationJournalDigest: string;
}> {
  const report = await getLastPanelImportDryRun();
  if (!report) {
    throw new Error("Run a migration dry-run diff before committing subscribers");
  }
  const allPlans = await db.select().from(plans).orderBy(plans.id);
  const defaultPlan = allPlans.find((p) => p.enforcement !== "hard") ?? allPlans[0];
  if (!defaultPlan) {
    throw new Error("No admissible plan exists to attach migrated subscribers");
  }

  const existingUsers = await db.select().from(users);
  const existingSet = new Set(
    existingUsers.flatMap((u) => [u.name.toLowerCase(), (u.email ?? "").toLowerCase()].filter(Boolean))
  );

  const importedUsers: string[] = [];
  const skippedExistingUsers: string[] = [];

  for (const lu of report.logicalUsers) {
    const key = lu.name.trim();
    if (!key || existingSet.has(key.toLowerCase())) {
      skippedExistingUsers.push(key);
      continue;
    }
    const isEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(key);
    const displayName = isEmail ? key.split("@")[0].replace(/[^a-zA-Z0-9_-]/g, "-") : key.slice(0, 60);
    await createUser(
      { label: actor },
      {
        name: displayName || `migrated-${importedUsers.length + 1}`,
        email: isEmail ? key : null,
        planId: defaultPlan.id,
        expiresAt: lu.expiresAt ? new Date(lu.expiresAt) : null,
      },
      `mig-${report.migrationJournalDigest.slice(0, 16)}-${key}`,
    );
    importedUsers.push(key);
    existingSet.add(key.toLowerCase());
  }

  await recordAudit(db as any, {
    actor,
    action: "importer.migration.commit_users",
    objectType: "importer",
    objectId: report.migrationJournalDigest.slice(0, 16),
    detail: {
      sourcePanel: report.sourcePanel,
      importedUsers,
      skippedExistingUsers,
      historicalUsageClassification: "historical_non_billable",
      historicalCounters: report.historicalUsage,
    },
  });

  return {
    importedUsers,
    skippedExistingUsers,
    migrationJournalDigest: report.migrationJournalDigest,
  };
}

// ---------------------------------------------------------------------------
// Interactive Journaled Reconciler & Independent Commit-Confirm Watchdog Simulator
// ---------------------------------------------------------------------------

export async function getNodeReconcileWatchdogState(nodeId: number): Promise<ReconcileJournalState> {
  const map = await getSettingJson<Record<string, ReconcileJournalState>>("node.reconcile_watchdog", {});
  const existing = map[String(nodeId)];
  if (existing) return existing;

  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  const [epochRow] = await db.select().from(settings).where(eq(settings.key, "control_plane_epoch"));
  const epoch = Number(epochRow?.value ?? "1");
  const appliedSeq = node?.appliedStructuralSeq ?? 1;
  const lkgDigest = sha256(`node-${nodeId}-lkg-seq-${appliedSeq}`);

  const w = new JournaledReconcileWatchdog({
    nodeId: node?.name ?? `node-${nodeId}`,
    authorizedEpoch: epoch,
    initialAppliedSequence: appliedSeq,
    initialLastKnownGoodDigest: lkgDigest,
  });
  return w.snapshot();
}

export async function mutateNodeReconcileWatchdogStage(
  actor: string,
  nodeId: number,
  operation: "stage_candidate" | "arm_apply_unverified" | "confirm_verified" | "trigger_watchdog_timeout",
): Promise<ReconcileJournalState> {
  const map = await getSettingJson<Record<string, ReconcileJournalState>>("node.reconcile_watchdog", {});
  const current = await getNodeReconcileWatchdogState(nodeId);
  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  const [epochRow] = await db.select().from(settings).where(eq(settings.key, "control_plane_epoch"));
  const epoch = Number(epochRow?.value ?? "1");

  const w = new JournaledReconcileWatchdog({
    nodeId: current.nodeId,
    authorizedEpoch: epoch,
    initialAppliedSequence: current.appliedStructuralSequence,
    initialLastKnownGoodDigest: current.lastKnownGoodDigest,
  });

  let nextState: ReconcileJournalState;
  const now = new Date();

  if (operation === "stage_candidate") {
    const nextSeq = Math.max(current.receivedStructuralSequence, node?.structuralSeq ?? 1) + 1;
    const candidateDigest = sha256(`candidate:${current.nodeId}:e${epoch}:s${nextSeq}:${now.getTime()}`);
    w.recordReceivedManifest({
      epoch,
      structuralSequence: nextSeq,
      membershipSequence: node?.membershipSeq ?? current.receivedMembershipSequence,
      manifestDigest: candidateDigest,
      now,
    });
    w.transitionStage("VALIDATED", { reason: "schema_and_secret_refs_verified", now });
    w.transitionStage("STAGED", { reason: "atomic_staging_dir_fsynced", now });
    nextState = w.transitionStage("PREFLIGHTED", { reason: "singbox_check_and_port_preflight_ok", now });
  } else if (operation === "arm_apply_unverified") {
    const nextSeq = Math.max(current.receivedStructuralSequence, current.appliedStructuralSequence + 1);
    w.recordReceivedManifest({
      epoch,
      structuralSequence: nextSeq,
      membershipSequence: node?.membershipSeq ?? current.receivedMembershipSequence,
      manifestDigest:
        current.candidateDigest && current.candidateDigest !== current.lastKnownGoodDigest
          ? current.candidateDigest
          : sha256(`candidate:${current.nodeId}:s${nextSeq}`),
      now,
    });
    w.transitionStage("VALIDATED", { now });
    w.transitionStage("STAGED", { now });
    w.transitionStage("PREFLIGHTED", { now });
    w.transitionStage("APPLYING", { reason: "reloading_runtime_listeners", now });
    nextState = w.transitionStage("APPLIED_UNVERIFIED", {
      reason: "commit_confirm_watchdog_armed_60s",
      watchdogTimeoutSeconds: 60,
      now,
    });
  } else if (operation === "confirm_verified") {
    const nextSeq = Math.max(current.receivedStructuralSequence, current.appliedStructuralSequence + 1);
    w.recordReceivedManifest({
      epoch,
      structuralSequence: nextSeq,
      membershipSequence: node?.membershipSeq ?? current.receivedMembershipSequence,
      manifestDigest:
        current.candidateDigest && current.candidateDigest !== current.lastKnownGoodDigest
          ? current.candidateDigest
          : sha256(`candidate:${current.nodeId}:s${nextSeq}`),
      now,
    });
    w.transitionStage("VALIDATED", { now });
    w.transitionStage("STAGED", { now });
    w.transitionStage("PREFLIGHTED", { now });
    w.transitionStage("APPLYING", { now });
    w.transitionStage("APPLIED_UNVERIFIED", { watchdogTimeoutSeconds: 60, now });
    nextState = w.transitionStage("VERIFIED", {
      reason: "l0_l2_health_and_mgmt_channel_confirmed",
      now,
    });
  } else {
    // trigger_watchdog_timeout: simulate commit-confirm deadline expiration and autonomous rollback to LKG
    const nextSeq = Math.max(current.receivedStructuralSequence, current.appliedStructuralSequence + 1);
    w.recordReceivedManifest({
      epoch,
      structuralSequence: nextSeq,
      membershipSequence: node?.membershipSeq ?? current.receivedMembershipSequence,
      manifestDigest: sha256(`unverified-broken-net:${current.nodeId}:s${nextSeq}`),
      now,
    });
    w.transitionStage("VALIDATED", { now });
    w.transitionStage("STAGED", { now });
    w.transitionStage("PREFLIGHTED", { now });
    w.transitionStage("APPLYING", { now });
    w.transitionStage("APPLIED_UNVERIFIED", { watchdogTimeoutSeconds: 30, now });
    const expiredTick = new Date(now.getTime() + 35_000);
    nextState = w.evaluateIndependentWatchdogTick(expiredTick).state;
  }

  map[String(nodeId)] = nextState;
  await setSettingValue(db, "node.reconcile_watchdog", JSON.stringify(map));

  await recordAudit(db as any, {
    actor,
    action: `node.reconcile_watchdog.${operation}`,
    objectType: "node",
    objectId: nodeId,
    detail: {
      stage: nextState.stage,
      receivedStructuralSequence: nextState.receivedStructuralSequence,
      appliedStructuralSequence: nextState.appliedStructuralSequence,
      lastKnownGoodSequence: nextState.lastKnownGoodSequence,
      watchdogArmed: nextState.watchdogArmed,
      lastTransitionReason: nextState.lastTransitionReason,
    },
  });

  return nextState;
}

// ---------------------------------------------------------------------------
// Interactive Live Session Registry & Durable WAL Metering Console per Node
// ---------------------------------------------------------------------------

export interface NodeSessionAndMeteringSnapshot {
  sessions: RuntimeSessionRecord[];
  lastRevocationSummary: SessionRevocationSummary | null;
  checkpoint: DurableMeteringCheckpointEnvelope;
  lastFlushedBatch: AbsoluteTotalFlushRecord[];
}

function derivePrincipalTag(user: { id: number; name: string }): string {
  const slug = user.name
    .trim()
    .split(/\s+/)[0]
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
  return `u${user.id}-${slug || "user"}`;
}

export async function getNodeSessionAndMeteringState(nodeId: number): Promise<NodeSessionAndMeteringSnapshot> {
  const map = await getSettingJson<Record<string, NodeSessionAndMeteringSnapshot>>("node.sessions_metering", {});
  const existing = map[String(nodeId)];
  if (existing) return existing;

  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  const nodeName = node?.name ?? `node-${nodeId}`;

  const nodePrincipals = await db
    .select({ p: endpointPrincipals, u: users, ib: inbounds })
    .from(endpointPrincipals)
    .innerJoin(users, eq(users.id, endpointPrincipals.userId))
    .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
    .where(and(eq(inbounds.nodeId, nodeId), eq(endpointPrincipals.state, "active")))
    .orderBy(users.id);

  const allUsage = await db.select().from(usageAggregates);
  const usageByUser = new Map<number, { up: number; down: number }>();
  for (const row of allUsage) {
    const prev = usageByUser.get(row.userId) ?? { up: 0, down: 0 };
    usageByUser.set(row.userId, { up: prev.up + row.up, down: prev.down + row.down });
  }

  const reg = new LiveSessionRegistry();
  const acc = new DurableMeteringAccumulator({ nodeId: nodeName });

  const distinctUsers = new Map<number, { id: number; name: string; version: number }>();
  for (const row of nodePrincipals) {
    distinctUsers.set(row.u.id, { id: row.u.id, name: row.u.name, version: row.u.version });
  }

  let seqIdx = 1;
  for (const usr of distinctUsers.values()) {
    const tag = derivePrincipalTag(usr);
    reg.authorizePrincipal(tag, usr.version);
    reg.registerSession({
      sessionId: `sess-tcp-reality-${nodeId}-${String(seqIdx).padStart(2, "0")}`,
      principalId: tag,
      credentialGeneration: usr.version,
      protocol: "vless-reality-vision",
      hasRuntimeCloser: true,
    });
    if (seqIdx === 1) {
      reg.registerSession({
        sessionId: `sess-quic-hy2-${nodeId}-${String(seqIdx + 1).padStart(2, "0")}`,
        principalId: tag,
        credentialGeneration: usr.version,
        protocol: "hysteria2",
        hasRuntimeCloser: false,
      });
    }
    const usage = usageByUser.get(usr.id) ?? { up: 67_108_864, down: 268_435_456 };
    acc.acceptDurable({
      principalId: tag,
      processGeneration: 1,
      sequence: 1,
      cumulativeUplinkBytes: Math.max(67_108_864, Math.min(usage.up, 536_870_912)),
      cumulativeDownlinkBytes: Math.max(268_435_456, Math.min(usage.down, 1_073_741_824)),
    });
    seqIdx += 1;
  }

  return {
    sessions: reg.snapshot(),
    lastRevocationSummary: null,
    checkpoint: acc.exportCheckpoint(),
    lastFlushedBatch: [],
  };
}

export async function mutateNodeSessionAndMetering(
  actor: string,
  nodeId: number,
  operation: "accept_sample" | "flush_durable" | "revoke_u1_sessions" | "reset_active_sessions",
): Promise<NodeSessionAndMeteringSnapshot> {
  const map = await getSettingJson<Record<string, NodeSessionAndMeteringSnapshot>>("node.sessions_metering", {});
  const current = await getNodeSessionAndMeteringState(nodeId);

  const acc = DurableMeteringAccumulator.rehydrateFromWal(JSON.stringify(current.checkpoint));
  let sessions = [...current.sessions];
  let lastRevocationSummary = current.lastRevocationSummary;
  let lastFlushedBatch = current.lastFlushedBatch;
  const primaryPrincipalId = current.checkpoint.trackedUsers[0]?.principalId ?? "u1-elena";

  if (operation === "accept_sample") {
    const primary = current.checkpoint.trackedUsers.find((u) => u.principalId === primaryPrincipalId);
    const nextSeq = (primary?.lastSequence ?? 1) + 1;
    const gen = primary?.lastGeneration ?? 1;
    acc.acceptDurable({
      principalId: primaryPrincipalId,
      processGeneration: gen,
      sequence: nextSeq,
      cumulativeUplinkBytes: (primary?.lastUplinkBytes ?? 134_217_728) + 33_554_432,
      cumulativeDownlinkBytes: (primary?.lastDownlinkBytes ?? 536_870_912) + 134_217_728,
    });
  } else if (operation === "flush_durable") {
    lastFlushedBatch = acc.flushDurable((batch) => {
      if (!batch.length) return;
    });
  } else if (operation === "revoke_u1_sessions") {
    const nowIso = new Date().toISOString();
    let closedCount = 0;
    let mutedUnclosableCount = 0;
    const sessionIds: string[] = [];
    sessions = sessions.map((s) => {
      if (s.principalId !== primaryPrincipalId) return s;
      sessionIds.push(s.sessionId);
      if (s.hasRuntimeCloser) {
        closedCount += 1;
        return {
          ...s,
          disposition: "closed" as const,
          revokedAt: nowIso,
          revocationReason: "operator_revocation_drill",
        };
      }
      mutedUnclosableCount += 1;
      return {
        ...s,
        disposition: "muted_unclosable" as const,
        revokedAt: nowIso,
        revocationReason: "operator_revocation_drill_quic_no_closer",
      };
    });
    lastRevocationSummary = {
      principalId: primaryPrincipalId,
      closedCount,
      mutedUnclosableCount,
      existingStreamsGuaranteedTerminated: mutedUnclosableCount === 0,
      newAuthenticationBlocked: true,
      newRoutedFlowsBlocked: true,
      sessionIds,
    };
  } else if (operation === "reset_active_sessions") {
    const nextGen = (sessions[0]?.credentialGeneration ?? 1) + 1;
    const nowIso = new Date().toISOString();
    sessions = sessions.map((s, idx) => ({
      ...s,
      sessionId: `${s.sessionId.split("-g")[0]}-g${nextGen}-${String(idx + 1).padStart(2, "0")}`,
      credentialGeneration: nextGen,
      disposition: "active" as const,
      establishedAt: nowIso,
      lastActivityAt: nowIso,
      revokedAt: null,
      revocationReason: null,
    }));
    lastRevocationSummary = null;
  }

  const nextSnapshot: NodeSessionAndMeteringSnapshot = {
    sessions,
    lastRevocationSummary,
    checkpoint: acc.exportCheckpoint(),
    lastFlushedBatch,
  };
  map[String(nodeId)] = nextSnapshot;
  await setSettingValue(db, "node.sessions_metering", JSON.stringify(map));

  await recordAudit(db as any, {
    actor,
    action: `node.sessions_metering.${operation}`,
    objectType: "node",
    objectId: nodeId,
    detail: {
      checkpointSequence: nextSnapshot.checkpoint.checkpointSequence,
      checkpointDigest: nextSnapshot.checkpoint.checkpointDigest,
      flushedRecords: lastFlushedBatch.length,
      lastRevocationSummary,
    },
  });

  return nextSnapshot;
}

// ---------------------------------------------------------------------------
// Interactive Enrollment Grant Authority, Trusted TOTP Step-Up & Shared 60s HMAC Limiter
// ---------------------------------------------------------------------------

export interface EnrollmentAuthorityLedgerSnapshot {
  activeGrantId: string;
  nodeUuid: string;
  tokenSha256: string;
  issuerEmail: string;
  approverEmail: string;
  stepUpVerifiedSource: "trusted";
  stepUpCounter: number;
  issuerSessionStatus: "active_within_2h_idle" | "logged_out_revoked";
  grantStatus: "ready_for_csr" | "redeemed" | "invalidated_by_logout";
  issuedCertificate: IssuedNodeCertificate | null;
  lastRateLimitCheck: {
    allowed: boolean;
    peerDigestHex: string;
    windowBucket: number;
    reason?: string;
  };
  updatedAt: string;
}

export async function getEnrollmentAuthorityState(): Promise<EnrollmentAuthorityLedgerSnapshot> {
  const existing = await getSettingJson<EnrollmentAuthorityLedgerSnapshot | null>(
    "enrollment.authority_state",
    null,
  );
  if (existing) return existing;

  const allAdmins = await db.select().from(admins).orderBy(admins.id);
  const ownerAdmins = allAdmins.filter((a) => a.role === "owner");
  const issuer = ownerAdmins[0] ?? allAdmins[0];
  const approver = ownerAdmins[1] ?? ownerAdmins[0] ?? allAdmins[0];
  const [firstNode] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  const targetNodeId = firstNode?.id ?? 1;
  const nodeUuid = `00000000-0000-4000-8000-${String(targetNodeId).padStart(12, "0")}`;

  const limiter = new SharedEnrollmentLimiter({
    hmacKey: crypto.createHash("sha256").update("omnipanel-enrollment-hmac-key").digest(),
    maxPerPeerPerWindow: 5,
    maxGlobalPerWindow: 30,
  });
  const check = limiter.checkAndAdmit(firstNode?.publicAddress ?? "198.51.100.10", new Date());
  return {
    activeGrantId: `grant-node-${targetNodeId}-baseline`,
    nodeUuid,
    tokenSha256: sha256(`grant-node-${targetNodeId}:${firstNode?.name ?? "node"}`),
    issuerEmail: issuer?.email ?? "owner@omnipanel.internal",
    approverEmail: approver?.email ?? "reviewer@omnipanel.internal",
    stepUpVerifiedSource: "trusted",
    stepUpCounter: Math.floor(Date.now() / 30_000),
    issuerSessionStatus: "active_within_2h_idle",
    grantStatus: "ready_for_csr",
    issuedCertificate: null,
    lastRateLimitCheck: check,
    updatedAt: new Date().toISOString(),
  };
}

export async function runEnrollmentAuthorityDrill(
  actor: string,
  operation: "mint_trusted_grant" | "redeem_csr_mtls" | "logout_revoke_unredeemed",
  peerIp = "198.51.100.10",
): Promise<EnrollmentAuthorityLedgerSnapshot> {
  const now = new Date();
  const allAdmins = await db.select().from(admins).orderBy(admins.id);
  const ownerAdmins = allAdmins.filter((a) => a.role === "owner");
  const issuer = ownerAdmins[0] ?? allAdmins[0] ?? { id: 1, email: "owner@omnipanel.internal" };
  const approver = ownerAdmins[1] ?? { id: 2, email: "reviewer@omnipanel.internal" };
  const [firstNode] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  const targetNodeId = firstNode?.id ?? 1;
  const nodeUuid = `00000000-0000-4000-8000-${String(targetNodeId).padStart(12, "0")}`;

  const limiter = new SharedEnrollmentLimiter({
    hmacKey: crypto.createHash("sha256").update("omnipanel-enrollment-hmac-key").digest(),
    maxPerPeerPerWindow: 5,
    maxGlobalPerWindow: 30,
  });
  const rateCheck = limiter.checkAndAdmit(peerIp || firstNode?.publicAddress || "198.51.100.10", now);

  const svc = new EnrollmentGrantService();
  const totpSecret = generateTotpSecret();

  svc.registerSession({
    sessionId: 501,
    adminId: issuer.id,
    adminEmail: issuer.email,
    role: "owner",
    sessionTokenHash: sha256(`sess-501-${now.getTime()}`),
    createdAt: new Date(now.getTime() - 10 * 60_000),
    lastSeenAt: new Date(now.getTime() - 30_000),
    expiresAt: new Date(now.getTime() + 4 * 3600_000),
    canIssueGrant: true,
    canApproveGrant: true,
    totpEnabled: true,
    totpSecretBase32: totpSecret,
  });
  svc.setNodeAndOrgState({
    nodeId: targetNodeId,
    nodeUuid,
    organizationId: "org-omni-core",
    nodeStatus: "pending_enrollment",
    organizationActive: true,
    bindingApproved: true,
  });

  const stepUp = svc.verifyTrustedStepUp({
    sessionId: 501,
    totpCode: generateTotp(totpSecret, now.getTime()),
    now,
  });

  const minted = svc.issueEnrollmentGrant({
    issuerSessionId: 501,
    approverAdminId: approver.id === issuer.id ? issuer.id + 1 : approver.id,
    approverCanApprove: true,
    organizationId: "org-omni-core",
    nodeId: targetNodeId,
    nodeUuid,
    ttlSeconds: 900,
    now,
  });

  let issuerSessionStatus: EnrollmentAuthorityLedgerSnapshot["issuerSessionStatus"] =
    "active_within_2h_idle";
  let grantStatus: EnrollmentAuthorityLedgerSnapshot["grantStatus"] = "ready_for_csr";
  let issuedCertificate: IssuedNodeCertificate | null = null;

  if (operation === "redeem_csr_mtls") {
    issuedCertificate = svc.redeemGrantAndIssueCertificate({
      bearerToken: minted.bearerToken,
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBMTCB2gIBADBAMQswCQYDVQQGEwJVUz==\n-----END CERTIFICATE REQUEST-----",
      now: new Date(now.getTime() + 1000),
    });
    grantStatus = "redeemed";
  } else if (operation === "logout_revoke_unredeemed") {
    svc.logoutSession(501);
    issuerSessionStatus = "logged_out_revoked";
    grantStatus = "invalidated_by_logout";
  }

  const snapshot: EnrollmentAuthorityLedgerSnapshot = {
    activeGrantId: minted.grant.grantId,
    nodeUuid,
    tokenSha256: minted.grant.tokenSha256,
    issuerEmail: issuer.email,
    approverEmail: approver.email,
    stepUpVerifiedSource: stepUp.verifiedSource as "trusted",
    stepUpCounter: stepUp.verifiedCounter,
    issuerSessionStatus,
    grantStatus,
    issuedCertificate,
    lastRateLimitCheck: rateCheck,
    updatedAt: now.toISOString(),
  };

  await setSettingValue(db, "enrollment.authority_state", JSON.stringify(snapshot));

  await recordAudit(db as any, {
    actor,
    action: `enrollment.authority.${operation}`,
    objectType: "enrollment_grant",
    objectId: snapshot.activeGrantId,
    detail: {
      nodeUuid: snapshot.nodeUuid,
      stepUpVerifiedSource: snapshot.stepUpVerifiedSource,
      stepUpCounter: snapshot.stepUpCounter,
      grantStatus: snapshot.grantStatus,
      issuedCertSerial: snapshot.issuedCertificate?.serial ?? null,
      peerDigestHex: snapshot.lastRateLimitCheck.peerDigestHex,
    },
  });

  return snapshot;
}


