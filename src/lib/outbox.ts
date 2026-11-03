import { eq, lte, and, sql } from "drizzle-orm";
import { db } from "@/db";
import { outboxJobs, users } from "@/db/schema";
import { evaluateUserPolicy } from "@/lib/users";

/** Durable worker: claims jobs with SKIP LOCKED so concurrent drainers never double-process. */
export async function drainOutbox(limit = 100) {
  let processed = 0;
  for (let i = 0; i < limit; i++) {
    const done = await db.transaction(async (tx) => {
      const rows = await tx.execute<{ id: number; kind: string; payload: Record<string, unknown>; attempts: number }>(
        sql`select id, kind, payload, attempts from outbox_jobs
            where status = 'pending' and run_after <= now()
            order by id limit 1 for update skip locked`,
      );
      const job = rows.rows[0];
      if (!job) return false;
      try {
        if (job.kind === "quota.evaluate") {
          await evaluateUserPolicy(tx, Number(job.payload.userId));
        }
        await tx.update(outboxJobs).set({ status: "done", doneAt: new Date(), attempts: job.attempts + 1 }).where(eq(outboxJobs.id, job.id));
      } catch (e) {
        await tx
          .update(outboxJobs)
          .set({
            attempts: job.attempts + 1,
            status: job.attempts + 1 >= 5 ? "failed" : "pending",
            runAfter: new Date(Date.now() + 30_000 * (job.attempts + 1)),
            lastError: e instanceof Error ? e.message.slice(0, 300) : "error",
          })
          .where(eq(outboxJobs.id, job.id));
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
