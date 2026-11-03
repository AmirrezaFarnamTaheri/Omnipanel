import { handle, json } from "@/lib/problem";
import { listWarpPeers } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const GET = handle(async () => {
  const peers = await listWarpPeers();
  return json({ peers });
});
