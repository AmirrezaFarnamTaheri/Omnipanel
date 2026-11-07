import { and, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { settings } from "@/db/schema";
import { ProblemError } from "@/lib/problem";

/**
 * Claims one TOTP counter using the database primary key and conditional writes.
 *
 * First use is a unique INSERT .. ON CONFLICT DO NOTHING. Reuse at a higher
 * step is UPDATE .. WHERE current_step < proposed_step .. RETURNING.
 * PostgreSQL holds the unique-index/row lock and rechecks the UPDATE predicate
 * after competing commits, so simultaneous equal-step callers cannot win twice.
 * No SELECT + unconditional UPSERT race is permitted.
 */
export async function consumeTotpCounter(adminId: number, matchedStep: number): Promise<void> {
  if (!Number.isSafeInteger(adminId) || adminId <= 0 || !Number.isSafeInteger(matchedStep) || matchedStep < 0) {
    throw new ProblemError(422, "Validation failed", "Invalid authenticator counter or administrator");
  }
  const key = `totp.last_counter.${adminId}`;
  const inserted = await db
    .insert(settings)
    .values({ key, value: String(matchedStep) })
    .onConflictDoNothing()
    .returning({ value: settings.value });
  if (inserted.length === 1) return;

  const updated = await db
    .update(settings)
    .set({ value: String(matchedStep) })
    .where(and(eq(settings.key, key), sql`CAST(${settings.value} AS BIGINT) < ${matchedStep}`))
    .returning({ value: settings.value });
  if (updated.length !== 1) {
    throw new ProblemError(401, "Unauthorized", "Step-up failed: authenticator code was already used (replay refused)");
  }
}
