import { gt } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { actorOf, assertSameOrigin, requireRole } from "@/lib/auth";
import { handle, invalid, json } from "@/lib/problem";
import { createUser } from "@/lib/users";

export const dynamic = "force-dynamic";

export const GET = handle(async (req) => {
  await requireRole("viewer");
  const url = new URL(req.url);
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 100);
  const after = Number(url.searchParams.get("after") ?? 0) || 0;
  const rows = await db
    .select({ id: users.id, name: users.name, email: users.email, planId: users.planId, status: users.status, version: users.version })
    .from(users)
    .where(gt(users.id, after))
    .orderBy(users.id)
    .limit(limit + 1);
  const page = rows.slice(0, limit);
  return json({ items: page, nextAfter: rows.length > limit ? page[page.length - 1].id : null });
});

export const POST = handle(async (req, cid) => {
  assertSameOrigin(req);
  const admin = await requireRole("operator");
  const key = req.headers.get("idempotency-key");
  if (!key) throw invalid("Idempotency-Key header is required");
  const b = (await req.json().catch(() => null)) as { name?: string; email?: string; planId?: number; expiresAt?: string } | null;
  if (!b || typeof b.name !== "string" || !Number.isInteger(b.planId)) throw invalid("name and planId are required");
  const r = await createUser(
    actorOf(admin, cid),
    { name: b.name, email: b.email, planId: b.planId as number, expiresAt: b.expiresAt ? new Date(b.expiresAt) : null },
    key,
  );
  // The subscription token is shown once at creation; replays never re-disclose it.
  return json({ userId: r.userId, version: r.version, subscriptionToken: r.token ?? null }, r.token ? 201 : 200);
});
