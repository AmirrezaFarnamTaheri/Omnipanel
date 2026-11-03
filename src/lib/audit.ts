import { asc, desc, sql } from "drizzle-orm";
import { db } from "@/db";
import { auditLog } from "@/db/schema";
import { sha256, canonicalJson } from "@/lib/crypto";
import type { Actor, Tx } from "@/lib/tx";

/** Append a hash-chained audit record inside the caller's transaction. */
export async function audit(
  tx: Tx,
  actor: Actor,
  action: string,
  objectType: string,
  objectId: string | number,
  detail: Record<string, unknown> = {},
) {
  await tx.execute(sql`select pg_advisory_xact_lock(7001)`);
  const [last] = await tx.select({ hash: auditLog.hash }).from(auditLog).orderBy(desc(auditLog.id)).limit(1);
  const prevHash = last?.hash ?? "genesis";
  const ts = new Date();
  const hash = sha256(
    prevHash + canonicalJson({ ts: ts.toISOString(), actor: actor.label, action, objectType, objectId: String(objectId), detail }),
  );
  await tx.insert(auditLog).values({
    ts,
    actor: actor.label,
    action,
    objectType,
    objectId: String(objectId),
    detail,
    correlationId: actor.correlationId,
    prevHash,
    hash,
  });
}

export async function verifyAuditChain() {
  const rows = await db.select().from(auditLog).orderBy(asc(auditLog.id));
  let prev = "genesis";
  for (const r of rows) {
    const expected = sha256(
      prev +
        canonicalJson({
          ts: r.ts.toISOString(),
          actor: r.actor,
          action: r.action,
          objectType: r.objectType,
          objectId: r.objectId,
          detail: r.detail,
        }),
    );
    if (r.prevHash !== prev || r.hash !== expected) return { ok: false, brokenAt: r.id, count: rows.length };
    prev = r.hash;
  }
  return { ok: true, brokenAt: null, count: rows.length };
}
