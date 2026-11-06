import { authenticateAgent } from "@/lib/nodes";
import { handle, json, ProblemError } from "@/lib/problem";
import { rateLimit } from "@/lib/ratelimit";
import { processAgentReportPayload, type AgentReportBody } from "@/lib/agent-report";

export const dynamic = "force-dynamic";

export const POST = handle(async (req) => {
  const node = await authenticateAgent(req);
  if (!rateLimit(`agent:${node.id}`, 60, 5)) throw new ProblemError(429, "Too many requests", "Agent rate limit");
  if (Number(req.headers.get("content-length") ?? 0) > 1_000_000) throw new ProblemError(413, "Payload too large");
  const b = (await req.json().catch(() => null)) as AgentReportBody | null;
  await processAgentReportPayload(node, b);
  return json({ ok: true });
});
