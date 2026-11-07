import { sql } from "drizzle-orm";
import { db } from "@/db";
import { settings } from "@/db/schema";
import { ProblemError } from "@/lib/problem";

/**
 * Consume a matched TOTP window in ONE PostgreSQL statement.
 *
 * ON CONFLICT ... DO UPDATE WHERE serializes competing writers on the same
 * unique key. Only a strictly newer counter may be written; RETURNING is
 * empty on replay. A separate SELECT followed by unconditional UPSERT would
 * allow two concurrent high-risk actions with the same authenticator code.
 */
export async function consumeTotpCounter(adminId: number, matchedStep: number): Promise<void> {
  if (!Number.isSafeInteger(adminId) || adminId <= 0 || !Number.isSafeInteger(matchedStep) || matchedStep < 0) {
    throw new ProblemError(422, "Validation failed", "Invalid authenticator counter or administrator");
  }
  const key = `totp.last_counter.${adminId}`;
  const result = await db
    .insert(settings)
    .values({ key, value: String(matchedStep) })
    .onConflictDoUpdate({
      target: settings.key,
      set: { value: String(matchedStep) },
      setWhere: sql`CAST(${settings.value} AS BIGINT) < ${matchedStep}`,
    })
    .returning({ value: settings.value });

  if (result.length !== 1) {
    throw new ProblemError(401, "Unauthorized", "Step-up failed: authenticator code was already used (replay refused)");
  }
}
