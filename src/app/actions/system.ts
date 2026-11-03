"use server";

import { eq } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { db } from "@/db";
import { admins, capabilityEvidence, healthObservations, meterObservations, usageAggregates } from "@/db/schema";
import { audit } from "@/lib/audit";
import { actorOf, requireRole } from "@/lib/auth";
import { decryptSecret, verifyPassword } from "@/lib/crypto";
import { act, str, type ActionState } from "@/lib/action-helpers";
import { declareRecoveryEpoch } from "@/lib/revisions";
import { ProblemError } from "@/lib/problem";
import { verifyTotp } from "@/lib/totp";
import { seedDemo } from "@/lib/demo";
import { drainOutbox, sweepExpiry } from "@/lib/outbox";
import { lt } from "drizzle-orm";

const refresh = () => revalidatePath("/", "layout");

export async function recordEvidenceAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const claim = str(fd, "claim");
    const status = str(fd, "status");
    if (!["admission", "metering", "revocation", "hardQuota"].includes(claim)) throw new ProblemError(422, "Validation failed", "Unknown claim");
    if (!["verified", "failed"].includes(status)) throw new ProblemError(422, "Validation failed", "Unknown status");
    const note = str(fd, "note");
    if (note.length < 10) throw new ProblemError(422, "Validation failed", "Evidence needs a note referencing the lab run (min 10 chars)");
    await db.transaction(async (tx) => {
      await tx.insert(capabilityEvidence).values({ capabilityKey: str(fd, "key"), claim, status, note, recordedBy: me.email });
      await audit(tx, actorOf(me), "capability.evidence", "capability", str(fd, "key"), { claim, status, note });
    });
    refresh();
    return { message: "Evidence recorded." };
  });
}

/** Step-up verification for high-risk operations: re-enter password (and TOTP when enabled). */
async function stepUp(adminId: number, fd: FormData) {
  const [a] = await db.select().from(admins).where(eq(admins.id, adminId));
  if (!verifyPassword(String(fd.get("password") ?? ""), a.passwordHash)) throw new ProblemError(401, "Unauthorized", "Step-up failed: wrong password");
  if (a.totpEnabled && a.totpSecretEnc && !verifyTotp(decryptSecret(a.totpSecretEnc), str(fd, "code"))) {
    throw new ProblemError(401, "Unauthorized", "Step-up failed: invalid authenticator code");
  }
}

export async function declareEpochAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    await stepUp(me.id, fd);
    const reason = str(fd, "reason");
    if (reason.length < 10) throw new ProblemError(422, "Validation failed", "Describe the recovery event (min 10 chars)");
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
      await audit(tx, actorOf(me), "retention.purge", "system", "retention", { rawUsageDays: 30, hourlyDays: 180, healthDays: 7 });
    });
    return { message: "Raw usage events >30d, hourly aggregates >180d and health samples >7d purged. Audit records are retained." };
  });
}

export async function seedDemoAction(_p: ActionState, _fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("owner");
    const r = await seedDemo(actorOf(me));
    refresh();
    return { message: r.message, secret: r.secret };
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

