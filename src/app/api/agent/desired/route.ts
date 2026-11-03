import { authenticateAgent } from "@/lib/nodes";
import { buildDesiredResponse } from "@/lib/revisions";
import { handle, json, ProblemError } from "@/lib/problem";
import { rateLimit } from "@/lib/ratelimit";
import { db } from "@/db";
import { nodes } from "@/db/schema";
import { eq } from "drizzle-orm";

export const dynamic = "force-dynamic";

const num = (v: string | null) => (v !== null && /^\d+$/.test(v) ? Number(v) : null);

export const GET = handle(async (req) => {
  const node = await authenticateAgent(req);
  if (!rateLimit(`agent:${node.id}`, 60, 5)) throw new ProblemError(429, "Too many requests", "Agent rate limit");
  const url = new URL(req.url);
  const res = await buildDesiredResponse(node.id, {
    epoch: num(url.searchParams.get("epoch")),
    structural: num(url.searchParams.get("structural")) ?? 0,
    membership: num(url.searchParams.get("membership")) ?? 0,
  });
  await db.update(nodes).set({ lastSeenAt: new Date() }).where(eq(nodes.id, node.id));
  return json(res);
});
