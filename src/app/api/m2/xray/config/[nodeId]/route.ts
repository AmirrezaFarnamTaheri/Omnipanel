import { requireRole } from "@/lib/auth";
import { handle, json, notFound } from "@/lib/problem";
import { getXrayNodeConfig } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const GET = handle(async (_req, _cid, ctx: { params: Promise<{ nodeId: string }> }) => {
  await requireRole("viewer");
  const { nodeId } = await ctx.params;
  const id = Number(nodeId);
  if (!Number.isInteger(id)) throw notFound("Node");
  const config = await getXrayNodeConfig(id);
  return json({ config });
});
