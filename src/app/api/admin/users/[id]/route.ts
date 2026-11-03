import { eq } from "drizzle-orm";
import { db } from "@/db";
import { users } from "@/db/schema";
import { actorOf, assertSameOrigin, requireRole } from "@/lib/auth";
import { handle, invalid, json, notFound, ProblemError } from "@/lib/problem";
import { updateUser } from "@/lib/users";

export const dynamic = "force-dynamic";

export const GET = handle(async (_req, _cid, ctx: { params: Promise<{ id: string }> }) => {
  await requireRole("viewer");
  const id = Number((await ctx.params).id);
  const [u] = await db.select().from(users).where(eq(users.id, id));
  if (!u) throw notFound("User");
  return json(u, 200, { etag: `"${u.version}"` });
});

export const PATCH = handle(async (req, cid, ctx: { params: Promise<{ id: string }> }) => {
  assertSameOrigin(req);
  const admin = await requireRole("operator");
  const id = Number((await ctx.params).id);
  const m = /^"?(\d+)"?$/.exec(req.headers.get("if-match") ?? "");
  if (!m) throw new ProblemError(428, "Precondition required", "If-Match with the current version is required");
  const [cur] = await db.select().from(users).where(eq(users.id, id));
  if (!cur) throw notFound("User");
  const b = (await req.json().catch(() => null)) as { name?: string; email?: string | null; planId?: number; expiresAt?: string | null } | null;
  if (!b) throw invalid("JSON body required");
  const u = await updateUser(
    actorOf(admin, cid),
    id,
    {
      name: b.name ?? cur.name,
      email: b.email === undefined ? cur.email : b.email,
      planId: b.planId ?? cur.planId,
      expiresAt: b.expiresAt === undefined ? cur.expiresAt : b.expiresAt ? new Date(b.expiresAt) : null,
    },
    Number(m[1]),
  );
  return json(u, 200, { etag: `"${u.version}"` });
});
