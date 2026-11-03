import { authenticateAgent } from "@/lib/nodes";
import { handle, invalid, json, ProblemError } from "@/lib/problem";
import { ingestMetering, type Gap } from "@/lib/metering";
import { drainOutbox } from "@/lib/outbox";
import { rateLimit } from "@/lib/ratelimit";
import { db } from "@/db";
import { nodes } from "@/db/schema";
import { eq } from "drizzle-orm";

export const dynamic = "force-dynamic";

export const POST = handle(async (req) => {
  const node = await authenticateAgent(req);
  if (!rateLimit(`agent:${node.id}`, 60, 5)) throw new ProblemError(429, "Too many requests", "Agent rate limit");
  if (Number(req.headers.get("content-length") ?? 0) > 2_000_000) throw new ProblemError(413, "Payload too large");
  const b = (await req.json().catch(() => null)) as { observations?: unknown[]; gaps?: Gap[] } | null;
  if (!b || !Array.isArray(b.observations ?? [])) throw invalid("observations array required");
  const summary = await ingestMetering(node.id, b.observations ?? [], Array.isArray(b.gaps) ? b.gaps : []);
  await db.update(nodes).set({ lastSeenAt: new Date() }).where(eq(nodes.id, node.id));
  await drainOutbox();
  return json({ ok: true, summary });
});
