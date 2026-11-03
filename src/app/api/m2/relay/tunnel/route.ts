import { assertSameOrigin, requireRole } from "@/lib/auth";
import { handle, invalid, json } from "@/lib/problem";
import { createRelayTunnel, listRelayTunnels } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const GET = handle(async () => {
  await requireRole("viewer");
  const tunnels = await listRelayTunnels();
  return json({ tunnels });
});

export const POST = handle(async (req, cid) => {
  await requireRole("operator");
  assertSameOrigin(req);
  const b = (await req.json().catch(() => null)) as {
    sourceNode?: string;
    destination?: string;
    protocol?: string;
  } | null;
  if (!b || !b.sourceNode || !b.destination || !b.protocol) {
    throw invalid("sourceNode, destination, and protocol are required");
  }
  const tunnel = await createRelayTunnel({
    sourceNode: b.sourceNode,
    destination: b.destination,
    protocol: b.protocol,
  });
  return json(tunnel, 201);
});
