import { handle, json } from "@/lib/problem";
import { listRelayNodes } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const GET = handle(async () => {
  const nodes = await listRelayNodes();
  return json({ nodes });
});
