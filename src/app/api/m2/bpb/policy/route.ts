import { assertSameOrigin, requireRole } from "@/lib/auth";
import { handle, invalid, json } from "@/lib/problem";
import { getBpbPolicy, updateBpbPolicy } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const GET = handle(async (req) => {
  await requireRole("viewer");
  const url = new URL(req.url);
  const nodeIdStr = url.searchParams.get("nodeId");
  const nodeId = nodeIdStr ? Number(nodeIdStr) : undefined;
  const policy = await getBpbPolicy(nodeId);
  return json(policy ? { policy } : { policy: null });
});

export const POST = handle(async (req, cid) => {
  await requireRole("operator");
  assertSameOrigin(req);
  const b = (await req.json().catch(() => null)) as {
    nodeId?: number;
    bandwidthLimit?: number;
    priority?: number;
  } | null;
  if (!b || !Number.isInteger(b.nodeId) || !Number.isInteger(b.bandwidthLimit) || !Number.isInteger(b.priority)) {
    throw invalid("nodeId, bandwidthLimit, and priority are required");
  }
  const nodeId = b.nodeId!;
  const bandwidthLimit = b.bandwidthLimit!;
  const priority = b.priority!;
  const policy = await updateBpbPolicy({ nodeId, bandwidthLimit, priority });
  return json({ policy }, 200);
});
