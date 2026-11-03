import { assertSameOrigin, requireRole } from "@/lib/auth";
import { handle, invalid, json } from "@/lib/problem";
import { configureWarp } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const POST = handle(async (req, cid) => {
  await requireRole("operator");
  assertSameOrigin(req);
  const b = (await req.json().catch(() => null)) as {
    interfaceName?: string;
    privateKey?: string;
    peers?: Array<{ publicKey: string; endpoint: string }>;
  } | null;
  if (!b || !b.interfaceName || !b.privateKey || !Array.isArray(b.peers)) {
    throw invalid("interfaceName, privateKey, and peers are required");
  }
  const iface = await configureWarp({
    interfaceName: b.interfaceName,
    privateKey: b.privateKey,
    peers: b.peers,
  });
  return json(iface, 201);
});
