import { handle, json } from "@/lib/problem";
import { listCdnProviders } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const GET = handle(async () => {
  const providers = await listCdnProviders();
  return json({ providers });
});
