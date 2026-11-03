import { and, eq } from "drizzle-orm";
import { idempotencyRecords } from "@/db/schema";
import { digestOf } from "@/lib/crypto";
import { ProblemError } from "@/lib/problem";
import type { Tx } from "@/lib/tx";

/**
 * Runs `fn` exactly once per (scope, key). The idempotency row is written in the same
 * transaction as the mutation, so intent and de-duplication record commit together.
 * Replays return the original result; reusing a key with different content is rejected.
 */
export async function idempotent<T>(
  tx: Tx,
  scope: string,
  key: string | null | undefined,
  request: unknown,
  fn: () => Promise<T>,
): Promise<T> {
  if (!key) return fn();
  if (key.length > 200) throw new ProblemError(422, "Validation failed", "Idempotency key too long");
  const requestHash = digestOf(request);
  const inserted = await tx
    .insert(idempotencyRecords)
    .values({ scope, key, requestHash })
    .onConflictDoNothing()
    .returning({ key: idempotencyRecords.key });
  if (inserted.length === 0) {
    const [existing] = await tx
      .select()
      .from(idempotencyRecords)
      .where(and(eq(idempotencyRecords.scope, scope), eq(idempotencyRecords.key, key)));
    if (!existing) throw new ProblemError(409, "Conflict", "Idempotency record in flux, retry");
    if (existing.requestHash !== requestHash) {
      throw new ProblemError(422, "Idempotency key reuse", "This idempotency key was already used with different content");
    }
    return existing.response as T;
  }
  const result = await fn();
  await tx
    .update(idempotencyRecords)
    .set({ response: (result ?? null) as never })
    .where(and(eq(idempotencyRecords.scope, scope), eq(idempotencyRecords.key, key)));
  return result;
}
