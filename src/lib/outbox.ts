import { eq, lte, and, asc } from "drizzle-orm";
import { db } from "@/db";
import { outboxJobs, users } from "@/db/schema";
import { evaluateUserPolicy } from "@/lib/users";

/** Durable worker: claims pending jobs in transaction order so drainers process deterministically. */
export async function drainOutbox(limit = 100) {
  let processed = 0;
  for (let i = 0; i < limit; i++) {
    const done = await db.transaction(async (tx) => {
      const [job] = await tx
        .select({
          id: outboxJobs.id,
          kind: outboxJobs.kind,
          payload: outboxJobs.payload,
          attempts: outboxJobs.attempts,
        })
        .from(outboxJobs)
        .where(and(eq(outboxJobs.status, "pending"), lte(outboxJobs.runAfter, new Date())))
        .orderBy(asc(outboxJobs.id))
        .limit(1);
      if (!job) return false;
      const { id: jobId, kind: jobKind, payload: jobPayload, attempts: jobAttempts } = job;
      try {
        if (jobKind === "quota.evaluate") {
          await evaluateUserPolicy(tx, Number(jobPayload.userId));
        }
        await tx
          .update(outboxJobs)
          .set({ status: "done", doneAt: new Date(), attempts: jobAttempts + 1 })
          .where(eq(outboxJobs.id, jobId));
      } catch (e) {
        await tx
          .update(outboxJobs)
          .set({
            attempts: jobAttempts + 1,
            status: jobAttempts + 1 >= 5 ? "failed" : "pending",
            runAfter: new Date(Date.now() + 30_000 * (jobAttempts + 1)),
            lastError: e instanceof Error ? e.message.slice(0, 300) : "error",
          })
          .where(eq(outboxJobs.id, jobId));
      }
      return true;
    });
    if (!done) break;
    processed++;
  }
  return processed;
}

/** Expiry sweep: queue a policy evaluation for users whose expiry has passed. */
export async function sweepExpiry() {
  const due = await db
    .select({ id: users.id })
    .from(users)
    .where(and(lte(users.expiresAt, new Date()), eq(users.status, "active")));
  for (const u of due) await db.insert(outboxJobs).values({ kind: "quota.evaluate", payload: { userId: u.id } });
  return due.length;
}
