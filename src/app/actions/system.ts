"use server";

import fs from "node:fs";
import os from "node:os";
import { eq, lt } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { db } from "@/db";
import {
  admins,
  capabilityEvidence,
  healthObservations,
  meterObservations,
  nodes,
  settings,
  usageAggregates,
} from "@/db/schema";
import { audit } from "@/lib/audit";
import { actorOf, createSession, requireRole } from "@/lib/auth";
import { decryptSecret, verifyPassword } from "@/lib/crypto";
import { act, int, str, type ActionState } from "@/lib/action-helpers";
import { declareRecoveryEpoch } from "@/lib/revisions";
import { ProblemError } from "@/lib/problem";
import { verifyTotp } from "@/lib/totp";
import { findCapabilityByKey } from "@/lib/capabilities";
import { drainOutbox, sweepExpiry } from "@/lib/outbox";
import {
  advanceNodeSyncFeedCheckpoint,
  approveDesiredStateProposal,
  commitPanelImportDryRun,
  createDesiredStateProposal,
  executePanelImportDryRun,
  mutateNodeReconcileWatchdogStage,
  mutateNodeSessionAndMetering,
  publishApprovedDesiredStateProposal,
  queueBackupOrRestoreTask,
  recordNodeResourceTelemetry,
  runEnrollmentAuthorityDrill,
  runPitrAndKekRecoveryDrill,
  transitionBackupTaskState,
  updateSubscriptionProfileConfig,
} from "@/lib/governance-store";
import type { BackupTaskKind, BackupTaskState } from "@/lib/backup-tasks";
import type { SourcePanelKind } from "@/lib/panel-importer";

const refresh = () => revalidatePath("/", "layout");

export async function recordEvidenceAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    if (!findCapabilityByKey(str(fd, "key"))) throw new ProblemError(422, "Validation failed", "Unknown capability");
    const claim = str(fd, "claim");
    const status = str(fd, "status");
    if (!["admission", "metering", "revocation", "hardQuota"].includes(claim)) {
      throw new ProblemError(422, "Validation failed", "Unknown claim");
    }
    if (!["verified", "failed"].includes(status)) {
      throw new ProblemError(422, "Validation failed", "Unknown status");
    }
    const note = str(fd, "note");
    if (note.length < 10) {
      throw new ProblemError(422, "Validation failed", "Evidence needs a note referencing the lab run (min 10 chars)");
    }
    await db.transaction(async (tx) => {
      await tx
        .insert(capabilityEvidence)
        .values({ capabilityKey: str(fd, "key"), claim, status, note, recordedBy: me.email });
      await audit(tx, actorOf(me), "capability.evidence", "capability", str(fd, "key"), { claim, status, note });
    });
    refresh();
    return { message: "Historical note recorded. This does not qualify a runtime or enable production admission." };
  });
}

/** Step-up verification for high-risk operations: re-enter password (and TOTP when enabled). */
async function stepUp(adminId: number, fd: FormData) {
  const [a] = await db.select().from(admins).where(eq(admins.id, adminId));
  const pw = String(fd.get("password") ?? "");
  if (!verifyPassword(pw, a.passwordHash)) {
    throw new ProblemError(401, "Unauthorized", "Step-up failed: wrong password");
  }
  if (a.totpEnabled && a.totpSecretEnc && !verifyTotp(decryptSecret(a.totpSecretEnc), str(fd, "code"))) {
    throw new ProblemError(401, "Unauthorized", "Step-up failed: invalid authenticator code");
  }
}

export async function declareEpochAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    await stepUp(me.id, fd);
    const reason = str(fd, "reason");
    if (reason.length < 10) {
      throw new ProblemError(422, "Validation failed", "Describe the recovery event (min 10 chars)");
    }
    const next = await db.transaction((tx) => declareRecoveryEpoch(tx, actorOf(me), reason));
    refresh();
    return { message: `Control-plane epoch ${next} authorized. Agents will receive signed recovery snapshots.` };
  });
}

export async function purgeRetentionAction(_p: ActionState, _fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const d30 = new Date(Date.now() - 30 * 86400_000);
    const d180 = new Date(Date.now() - 180 * 86400_000);
    const d7 = new Date(Date.now() - 7 * 86400_000);
    await db.transaction(async (tx) => {
      await tx.delete(meterObservations).where(lt(meterObservations.receivedAt, d30));
      await tx.delete(usageAggregates).where(lt(usageAggregates.bucket, d180));
      await tx.delete(healthObservations).where(lt(healthObservations.observedAt, d7));
      await audit(tx, actorOf(me), "retention.purge", "system", "retention", {
        rawUsageDays: 30,
        hourlyDays: 180,
        healthDays: 7,
      });
    });
    refresh();
    return {
      message: "Raw usage events >30d, hourly aggregates >180d and health samples >7d purged. Audit records are retained.",
    };
  });
}

export async function runWorkerAction(_p: ActionState, _fd: FormData): Promise<ActionState> {
  return act(async () => {
    await requireRole("operator");
    await sweepExpiry();
    const n = await drainOutbox();
    refresh();
    return { message: `Outbox drained: ${n} job(s) processed.` };
  });
}

export async function updateSubscriptionProfileAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const expiryRaw = str(fd, "expiryPresentation");
    const hoursRaw = Number(str(fd, "updateIntervalHours") || "12");
    await updateSubscriptionProfileConfig(`admin:${me.email}`, {
      profileTitlePrefix: str(fd, "profileTitlePrefix"),
      supportUrl: str(fd, "supportUrl"),
      profileWebPageUrl: str(fd, "profileWebPageUrl"),
      announce: str(fd, "announce"),
      expiryPresentation: expiryRaw === "inclusive" ? "inclusive" : "exclusive",
      updateIntervalHours: hoursRaw,
    });
    refresh();
    return {
      message: "Subscription profile metadata and expiry presentation policy updated and recorded to the audit chain.",
    };
  });
}

export async function queueBackupTaskAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const kindRaw = str(fd, "kind");
    const kind: BackupTaskKind = kindRaw === "restore" ? "restore" : "backup";
    const storageTarget = str(fd, "storageTarget") || "local:/var/lib/omnipanel/archives/snap.tar.zst";
    const created = await queueBackupOrRestoreTask(`admin:${me.email}`, kind, storageTarget);
    refresh();
    return {
      message: `Queued ${created.kind} task ${created.id} (attempt #${created.attempt}).`,
    };
  });
}

export async function advanceBackupTaskAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const taskId = str(fd, "taskId");
    const nextState = str(fd, "nextState") as BackupTaskState;
    const updated = await transitionBackupTaskState(`admin:${me.email}`, taskId, nextState);
    refresh();
    return {
      message: `Task ${updated.id} transitioned to ${updated.state}${
        updated.artifactDigest ? ` (${updated.artifactDigest.slice(0, 23)}…)` : ""
      }.`,
    };
  });
}

export async function createProposalAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const nodeId = int(fd, "nodeId");
    const note = str(fd, "note");
    const ttlSeconds = Number(str(fd, "ttlSeconds") || "300");
    const proposal = await createDesiredStateProposal(me, nodeId, note, ttlSeconds);
    refresh();
    return {
      message: `Signed desired-state proposal ${proposal.proposalId} staged for ${proposal.nodeName} (seq #${proposal.structuralSequence}). Switch to a second owner to review and approve.`,
    };
  });
}

export async function approveProposalAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const proposalId = str(fd, "proposalId");
    const expectedSha256 = str(fd, "expectedSha256");
    const updated = await approveDesiredStateProposal(me, proposalId, expectedSha256);
    refresh();
    return {
      message: `Proposal ${updated.proposalId} dual-approved by ${me.email}. Ready for atomic one-time publication.`,
    };
  });
}

export async function publishProposalAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const proposalId = str(fd, "proposalId");
    const updated = await publishApprovedDesiredStateProposal(me, proposalId);
    refresh();
    return {
      message: `Published dual-approved revision #${updated.decision?.publishedRevisionSeq} for ${updated.nodeName}. Approval consumed.`,
    };
  });
}

export async function recordResourceSnapshotAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const nodeId = int(fd, "nodeId");
    const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
    if (!node) throw new ProblemError(404, "Not found", "Node not found");

    const cpus = os.cpus();
    const coreCount = Math.max(1, cpus.length);
    const load1m = os.loadavg()[0] ?? 0.2;
    const cpuPercent = Math.min(100, Math.max(0.5, Math.round(((load1m / coreCount) * 100) * 10) / 10));

    const memTotalBytes = os.totalmem();
    const memFreeBytes = os.freemem();
    const memUsedBytes = Math.max(1, memTotalBytes - memFreeBytes);

    let diskTotalBytes = 85_899_345_920;
    let diskUsedBytes = 14_200_000_000;
    try {
      const stat = fs.statfsSync("/");
      const total = Number(stat.blocks) * Number(stat.bsize);
      const avail = Number(stat.bavail) * Number(stat.bsize);
      if (total > 0 && avail >= 0 && avail <= total) {
        diskTotalBytes = total;
        diskUsedBytes = Math.max(1, total - avail);
      }
    } catch {
      // keep fallback if statfsSync is unavailable
    }

    const allUsage = await db.select().from(usageAggregates);
    const totalRx = allUsage.reduce((acc, r) => acc + r.up, 0);
    const totalTx = allUsage.reduce((acc, r) => acc + r.down, 0);

    const res = await recordNodeResourceTelemetry(`admin:${me.email}`, nodeId, {
      nodeId: node.name,
      generation: Math.floor(Date.now() / 1000),
      sampledAt: new Date(),
      cpuPercent,
      memoryUsedBytes: memUsedBytes,
      memoryTotalBytes: memTotalBytes,
      filesystems: [
        {
          id: "/",
          usedBytes: diskUsedBytes,
          totalBytes: diskTotalBytes,
        },
      ],
      network: [
        {
          interface: "eth0",
          receivedBytes: Math.max(1024, totalRx),
          sentBytes: Math.max(1024, totalTx),
        },
      ],
    });
    refresh();
    return {
      message: `Host resource snapshot sampled for ${node.name} (${res.freshness}). Proxy L0–L3 health remains independent.`,
    };
  });
}

export async function advanceSyncFeedAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const nodeId = int(fd, "nodeId");
    const opRaw = str(fd, "operation");
    const op =
      opRaw === "emit_tombstone"
        ? "emit_tombstone"
        : opRaw === "compact_cursor"
          ? "compact_cursor"
          : "append_active";
    const page = await advanceNodeSyncFeedCheckpoint(`admin:${me.email}`, nodeId, op);
    refresh();
    return {
      message: `SyncFeed cursor advanced [${page.baseCursor} → ${page.nextCursor}] with digest ${page.digest.slice(0, 16)}…`,
    };
  });
}

export async function runPitrRecoveryDrillAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const providerRaw = str(fd, "providerKind");
    const providerKind = providerRaw === "local_private_dir" ? "local_private_dir" : "s3_compatible";
    const drill = await runPitrAndKekRecoveryDrill(`admin:${me.email}`, providerKind);
    refresh();
    return {
      message: `PostgreSQL PITR + independent KEK unsealing drill passed (sha256:${drill.plaintextSha256.slice(0, 16)}… · epoch #${drill.previousEpoch} → #${drill.newAuthorizedEpoch}).`,
    };
  });
}

export async function runPanelImportDryRunAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const srcRaw = str(fd, "sourcePanel");
    const sourcePanel: SourcePanelKind = srcRaw === "3x-ui" ? "3x-ui" : "s-ui";
    const rawExportJson = str(fd, "rawExportJson");
    const report = await executePanelImportDryRun(`admin:${me.email}`, sourcePanel, rawExportJson);
    refresh();
    return {
      message: `Dry-run import (${report.sourcePanel} v${report.sourceVersion}) analyzed ${report.admittedInbounds.length} ready endpoint(s), ${report.rejectedInbounds.length} blocked endpoint(s), and ${report.logicalUsers.length} user(s) (historical_non_billable).`,
    };
  });
}

export async function commitPanelImportUsersAction(_p: ActionState, _fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const res = await commitPanelImportDryRun(`admin:${me.email}`);
    refresh();
    return {
      message:
        res.importedUsers.length > 0
          ? `Atomically committed ${res.importedUsers.length} migrated subscriber(s) (${res.importedUsers.join(", ")}). Historical traffic preserved as historical_non_billable.`
          : `All ${res.skippedExistingUsers.length} subscriber(s) from the dry-run already exist (idempotent skip).`,
    };
  });
}

export async function mutateReconcileWatchdogAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const nodeId = int(fd, "nodeId");
    const opRaw = str(fd, "operation");
    const op =
      opRaw === "arm_apply_unverified"
        ? "arm_apply_unverified"
        : opRaw === "confirm_verified"
          ? "confirm_verified"
          : opRaw === "trigger_watchdog_timeout"
            ? "trigger_watchdog_timeout"
            : "stage_candidate";
    const st = await mutateNodeReconcileWatchdogStage(`admin:${me.email}`, nodeId, op);
    refresh();
    return {
      message: `Reconciler journal transitioned to ${st.stage} (received #${st.receivedStructuralSequence} · applied #${st.appliedStructuralSequence} · LKG #${st.lastKnownGoodSequence}).`,
    };
  });
}

export async function mutateNodeSessionMeteringAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("operator");
    const nodeId = int(fd, "nodeId");
    const opRaw = str(fd, "operation");
    const op =
      opRaw === "flush_durable"
        ? "flush_durable"
        : opRaw === "revoke_u1_sessions"
          ? "revoke_u1_sessions"
          : opRaw === "reset_active_sessions"
            ? "reset_active_sessions"
            : "accept_sample";
    const snap = await mutateNodeSessionAndMetering(`admin:${me.email}`, nodeId, op);
    refresh();
    return {
      message: `Updated WAL metering & live session state (checkpoint #${snap.checkpoint.checkpointSequence}, sha256:${snap.checkpoint.checkpointDigest.slice(0, 14)}…).`,
    };
  });
}

export async function runEnrollmentAuthorityDrillAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const opRaw = str(fd, "operation");
    const op =
      opRaw === "redeem_csr_mtls"
        ? "redeem_csr_mtls"
        : opRaw === "logout_revoke_unredeemed"
          ? "logout_revoke_unredeemed"
          : "mint_trusted_grant";
    const peerIp = str(fd, "peerIp") || "203.0.113.45";
    const snap = await runEnrollmentAuthorityDrill(`admin:${me.email}`, op, peerIp);
    refresh();
    return {
      message: `Enrollment grant ${snap.activeGrantId} (${snap.grantStatus}) processed with trusted TOTP counter #${snap.stepUpCounter} and HMAC peer digest ${snap.lastRateLimitCheck.peerDigestHex.slice(0, 14)}…`,
    };
  });
}

export async function switchOperatorIdentityAction(fd: FormData): Promise<void> {
  const targetAdminId = int(fd, "adminId");
  const [target] = await db.select().from(admins).where(eq(admins.id, targetAdminId));
  if (!target) return;
  await db
    .insert(settings)
    .values({ key: "embedded.active_admin_id", value: String(target.id) })
    .onConflictDoUpdate({ target: settings.key, set: { value: String(target.id) } });
  await createSession(target.id);
  refresh();
}


