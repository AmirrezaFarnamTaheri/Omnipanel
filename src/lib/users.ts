import { and, desc, eq, gte, inArray, ne, sql } from "drizzle-orm";
import { randomBytes } from "node:crypto";
import { db } from "@/db";
import {
  endpointPrincipals,
  inbounds,
  nodes,
  outboxJobs,
  plans,
  subscriptionTokens,
  usageAggregates,
  usageQualityIntervals,
  users,
} from "@/db/schema";
import { audit } from "@/lib/audit";
import { loadEvidence, findCapability, isHardQuotaCapable, type EvidenceMap } from "@/lib/capabilities";
import { encryptSecret, newUuid, randomToken, sha256 } from "@/lib/crypto";
import { idempotent } from "@/lib/idempotency";
import { conflict, invalid, notFound } from "@/lib/problem";
import { emitMembership } from "@/lib/revisions";
import type { Actor, Tx } from "@/lib/tx";

type Executor = Tx | typeof db;

export function periodStart(now = new Date()) {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

/* ---------- Plans ---------- */

export async function createPlan(
  actor: Actor,
  input: { name: string; quotaGb: number | null; enforcement: string; idemKey?: string },
) {
  const name = input.name.trim();
  if (name.length < 2 || name.length > 60) throw invalid("Plan name must be 2-60 characters");
  if (!["hard", "metered", "unmetered"].includes(input.enforcement)) throw invalid("Unknown enforcement class");
  if (input.enforcement !== "unmetered" && (!input.quotaGb || input.quotaGb <= 0)) {
    throw invalid("Metered and hard plans need a positive quota");
  }
  const quotaBytes = input.enforcement === "unmetered" ? null : Math.round((input.quotaGb as number) * 1024 ** 3);
  return db.transaction((tx) =>
    idempotent(tx, "plan.create", input.idemKey, { name, quotaBytes, e: input.enforcement }, async () => {
      const dup = await tx.select({ id: plans.id }).from(plans).where(eq(plans.name, name));
      if (dup.length) throw conflict(`A plan named "${name}" already exists`);
      const [p] = await tx.insert(plans).values({ name, quotaBytes, enforcement: input.enforcement }).returning();
      await audit(tx, actor, "plan.create", "plan", p.id, { name, quotaBytes, enforcement: input.enforcement });
      return { planId: p.id };
    }),
  );
}

/** Hard-quota plans may only be attached to users whose endpoints are all verified hard-enforceable. */
export async function assertPlanAdmissible(ex: Executor, planId: number, ev?: EvidenceMap) {
  const [plan] = await ex.select().from(plans).where(eq(plans.id, planId));
  if (!plan) throw invalid("Plan does not exist");
  if (plan.enforcement !== "hard") return plan;
  const evidence = ev ?? (await loadEvidence());
  const rows = await ex.select().from(inbounds).where(eq(inbounds.enabled, true));
  const bad = rows.filter((r) => {
    const cap = findCapability(r.runtime, r.protocol);
    return !cap || !isHardQuotaCapable(cap, evidence);
  });
  if (bad.length) {
    throw invalid(
      `Plan "${plan.name}" promises hard quota enforcement, but these endpoints have no verified hard-quota evidence: ${bad
        .map((b) => b.name)
        .join(", ")}. Use a metered plan or record lab evidence first.`,
    );
  }
  return plan;
}

/* ---------- Principals ---------- */

export async function provisionPrincipal(
  tx: Tx,
  user: { id: number; status: string },
  inbound: { id: number; runtime: string; protocol: string },
) {
  const cap = findCapability(inbound.runtime, inbound.protocol);
  if (!cap) throw invalid("Inbound uses an unsupported runtime/protocol");
  const credential = cap.credential === "uuid" ? newUuid() : randomToken(24);
  const attributionKey = `u${user.id}-i${inbound.id}-${randomBytes(3).toString("hex")}`;
  const [p] = await tx
    .insert(endpointPrincipals)
    .values({ userId: user.id, inboundId: inbound.id, attributionKey, credentialEnc: encryptSecret(credential) })
    .returning();
  if (user.status === "active") await emitMembership(tx, "add", p);
  return p;
}

export async function rotateEndpoint(actor: Actor, principalId: number) {
  return db.transaction(async (tx) => {
    const [p] = await tx.select().from(endpointPrincipals).where(eq(endpointPrincipals.id, principalId));
    if (!p || p.state !== "active") throw notFound("Active endpoint credential");
    const [user] = await tx.select().from(users).where(eq(users.id, p.userId));
    const [ib] = await tx.select().from(inbounds).where(eq(inbounds.id, p.inboundId));
    await tx
      .update(endpointPrincipals)
      .set({ state: "revoked", revokedAt: new Date() })
      .where(eq(endpointPrincipals.id, p.id));
    await emitMembership(tx, "remove", p);
    const np = await provisionPrincipal(tx, user, ib);
    await audit(tx, actor, "endpoint.rotate", "user", user.id, { inboundId: ib.id, old: p.attributionKey, new: np.attributionKey });
    return np.id;
  });
}

/* ---------- Users ---------- */

export type UserInput = { name: string; email?: string | null; planId: number; expiresAt?: Date | null };

function validateUser(i: UserInput) {
  const name = i.name.trim();
  if (name.length < 1 || name.length > 80) throw invalid("Name must be 1-80 characters");
  if (i.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(i.email)) throw invalid("Email address is not valid");
  if (i.expiresAt && Number.isNaN(i.expiresAt.getTime())) throw invalid("Expiry date is not valid");
  return { name, email: i.email?.trim() || null, planId: i.planId, expiresAt: i.expiresAt ?? null };
}

export async function createUser(actor: Actor, input: UserInput, idemKey?: string | null) {
  const v = validateUser(input);
  let token: string | undefined;
  const result = await db.transaction((tx) =>
    idempotent(tx, "user.create", idemKey, { ...v, expiresAt: v.expiresAt?.toISOString() ?? null }, async () => {
      await assertPlanAdmissible(tx, v.planId);
      const [user] = await tx.insert(users).values(v).returning();
      token = `omni_${randomToken(32)}`;
      await tx.insert(subscriptionTokens).values({ userId: user.id, tokenHash: sha256(token), prefix: token.slice(0, 9) });
      const ibs = await db
        .select({ ib: inbounds })
        .from(inbounds)
        .innerJoin(nodes, eq(nodes.id, inbounds.nodeId))
        .where(and(eq(inbounds.enabled, true), ne(nodes.status, "quarantined")));
      for (const { ib } of ibs) await provisionPrincipal(tx, user, ib);
      await audit(tx, actor, "user.create", "user", user.id, { name: v.name, planId: v.planId, endpoints: ibs.length });
      return { userId: user.id, version: user.version };
    }),
  );
  return { ...result, token };
}

export async function updateUser(actor: Actor, id: number, input: UserInput, expectedVersion: number) {
  const v = validateUser(input);
  return db.transaction(async (tx) => {
    await assertPlanAdmissible(tx, v.planId);
    const updated = await tx
      .update(users)
      .set({ ...v, version: sql`${users.version} + 1`, updatedAt: new Date() })
      .where(and(eq(users.id, id), eq(users.version, expectedVersion)))
      .returning();
    if (!updated.length) {
      const [exists] = await tx.select({ id: users.id }).from(users).where(eq(users.id, id));
      if (!exists) throw notFound("User");
      throw conflict("This user was modified by someone else. Reload and re-apply your edit.", { currentVersionChanged: true });
    }
    await audit(tx, actor, "user.update", "user", id, { ...v, expiresAt: v.expiresAt?.toISOString() ?? null, version: updated[0].version });
    await tx.insert(outboxJobs).values({ kind: "quota.evaluate", payload: { userId: id } });
    return updated[0];
  });
}

export async function setUserStatus(
  tx: Tx,
  actor: Actor,
  userId: number,
  status: "active" | "suspended" | "expired",
  reason: string | null,
) {
  const [user] = await tx.select().from(users).where(eq(users.id, userId)).for("update");
  if (!user) throw notFound("User");
  if (user.status === status) return user;
  const wasActive = user.status === "active";
  const [u] = await tx
    .update(users)
    .set({ status, suspendReason: status === "active" ? null : reason, version: sql`${users.version} + 1`, updatedAt: new Date() })
    .where(eq(users.id, userId))
    .returning();
  const principals = await tx
    .select()
    .from(endpointPrincipals)
    .where(and(eq(endpointPrincipals.userId, userId), eq(endpointPrincipals.state, "active")));
  if (wasActive && status !== "active") for (const p of principals) await emitMembership(tx, "suspend", p);
  if (!wasActive && status === "active") for (const p of principals) await emitMembership(tx, "resume", p);
  await audit(tx, actor, `user.${status === "active" ? "resume" : status === "suspended" ? "suspend" : "expire"}`, "user", userId, {
    reason,
  });
  return u;
}

export async function mutateUserStatus(actor: Actor, userId: number, status: "active" | "suspended", reason: string) {
  return db.transaction((tx) => setUserStatus(tx, actor, userId, status, status === "active" ? null : reason));
}

export async function rotateSubscriptionToken(actor: Actor, userId: number) {
  const token = `omni_${randomToken(32)}`;
  await db.transaction(async (tx) => {
    const [u] = await tx.select({ id: users.id }).from(users).where(eq(users.id, userId));
    if (!u) throw notFound("User");
    await tx
      .update(subscriptionTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(subscriptionTokens.userId, userId), sql`revoked_at is null`));
    await tx.insert(subscriptionTokens).values({ userId, tokenHash: sha256(token), prefix: token.slice(0, 9) });
    await audit(tx, actor, "subscription_token.rotate", "user", userId, {});
  });
  return token;
}

/* ---------- Usage & quota ---------- */

export type UsageQuality = "complete" | "partial" | "estimated" | "unknown" | "unmetered";

export async function usageForUser(ex: Executor, userId: number) {
  const start = periodStart();
  const [agg] = await ex
    .select({
      up: sql<number>`coalesce(sum(${usageAggregates.up}), 0)::float8`,
      down: sql<number>`coalesce(sum(${usageAggregates.down}), 0)::float8`,
      n: sql<number>`count(*)::int`,
    })
    .from(usageAggregates)
    .where(and(eq(usageAggregates.userId, userId), gte(usageAggregates.bucket, start)));
  const gaps = await ex
    .select()
    .from(usageQualityIntervals)
    .where(and(eq(usageQualityIntervals.userId, userId), gte(usageQualityIntervals.detectedAt, start)))
    .orderBy(desc(usageQualityIntervals.id))
    .limit(20);
  const [row] = await ex
    .select({ enforcement: plans.enforcement })
    .from(users)
    .innerJoin(plans, eq(plans.id, users.planId))
    .where(eq(users.id, userId));
  let quality: UsageQuality = "complete";
  if (agg.n === 0) quality = row?.enforcement === "unmetered" ? "unmetered" : "unknown";
  else if (gaps.length) quality = "partial";
  return { up: agg.up, down: agg.down, total: agg.up + agg.down, quality, gaps, periodStart: start };
}

/** Applies quota/expiry policy. Only exact measured usage is used; estimates never suspend. */
export async function evaluateUserPolicy(tx: Tx, userId: number) {
  const [row] = await tx
    .select({ u: users, p: plans })
    .from(users)
    .innerJoin(plans, eq(plans.id, users.planId))
    .where(eq(users.id, userId));
  if (!row) return;
  const { u, p } = row;
  const sys: Actor = { label: "system:policy" };
  if (u.expiresAt && u.expiresAt.getTime() < Date.now() && u.status !== "expired") {
    await setUserStatus(tx, sys, u.id, "expired", "expired");
    return;
  }
  if (p.enforcement === "unmetered" || !p.quotaBytes) return;
  const usage = await usageForUser(tx, userId);
  if (usage.total >= p.quotaBytes && u.status === "active") {
    await setUserStatus(tx, sys, u.id, "suspended", "quota");
  } else if (usage.total < p.quotaBytes && u.status === "suspended" && u.suspendReason === "quota") {
    await setUserStatus(tx, sys, u.id, "active", null);
  }
}

export async function listUsers(ids?: number[]) {
  const q = db
    .select({ u: users, planName: plans.name })
    .from(users)
    .innerJoin(plans, eq(plans.id, users.planId))
    .orderBy(users.id);
  return ids ? q.where(inArray(users.id, ids)) : q;
}

export type BulkUserOperationKind =
  | "extend_expiry_30d"
  | "resume_suspended"
  | "assign_plan"
  | "rotate_all_tokens";

export async function bulkSubscriberOperation(
  actor: Actor,
  input: {
    operation: BulkUserOperationKind;
    planId?: number;
  },
): Promise<{ affectedCount: number; operation: BulkUserOperationKind }> {
  return db.transaction(async (tx) => {
    const allUsers = await tx.select().from(users).orderBy(users.id);
    if (allUsers.length === 0) {
      return { affectedCount: 0, operation: input.operation };
    }

    let affectedCount = 0;
    const now = new Date();

    if (input.operation === "extend_expiry_30d") {
      for (const u of allUsers) {
        const baseMs = u.expiresAt && u.expiresAt.getTime() > now.getTime() ? u.expiresAt.getTime() : now.getTime();
        const nextExpires = new Date(baseMs + 30 * 86400_000);
        await tx
          .update(users)
          .set({
            expiresAt: nextExpires,
            version: sql`${users.version} + 1`,
            updatedAt: now,
          })
          .where(eq(users.id, u.id));
        if (u.status === "expired") {
          await setUserStatus(tx, actor, u.id, "active", null);
        }
        affectedCount += 1;
      }
    } else if (input.operation === "resume_suspended") {
      for (const u of allUsers) {
        if (u.status !== "active") {
          await setUserStatus(tx, actor, u.id, "active", null);
          affectedCount += 1;
        }
      }
    } else if (input.operation === "assign_plan") {
      if (!input.planId) throw invalid("Plan ID is required for bulk plan assignment");
      await assertPlanAdmissible(tx, input.planId);
      for (const u of allUsers) {
        if (u.planId !== input.planId) {
          await tx
            .update(users)
            .set({
              planId: input.planId,
              version: sql`${users.version} + 1`,
              updatedAt: now,
            })
            .where(eq(users.id, u.id));
          await tx.insert(outboxJobs).values({ kind: "quota.evaluate", payload: { userId: u.id } });
          affectedCount += 1;
        }
      }
    } else if (input.operation === "rotate_all_tokens") {
      for (const u of allUsers) {
        const token = `omni_${randomToken(32)}`;
        await tx
          .update(subscriptionTokens)
          .set({ revokedAt: now })
          .where(and(eq(subscriptionTokens.userId, u.id), sql`revoked_at is null`));
        await tx
          .insert(subscriptionTokens)
          .values({ userId: u.id, tokenHash: sha256(token), prefix: token.slice(0, 9) });
        affectedCount += 1;
      }
    }

    await audit(tx, actor, "user.bulk_lifecycle", "user", "batch", {
      operation: input.operation,
      affectedCount,
      planId: input.planId ?? null,
    });

    return { affectedCount, operation: input.operation };
  });
}

