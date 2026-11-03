import { assertSameOrigin, requireRole } from "@/lib/auth";
import { handle, invalid, json } from "@/lib/problem";
import { createCdnMapping, listCdnMappings } from "@/lib/m2";

export const dynamic = "force-dynamic";

export const GET = handle(async () => {
  await requireRole("viewer");
  const mappings = await listCdnMappings();
  return json({ mappings });
});

export const POST = handle(async (req, cid) => {
  await requireRole("operator");
  assertSameOrigin(req);
  const b = (await req.json().catch(() => null)) as {
    domain?: string;
    origin?: string;
    provider?: string;
    ttl?: number;
  } | null;
  if (!b || !b.domain || !b.origin || !b.provider) {
    throw invalid("domain, origin, and provider are required");
  }
  const mapping = await createCdnMapping({
    domain: b.domain,
    origin: b.origin,
    provider: b.provider,
    ttl: b.ttl,
  });
  return json(mapping, 201);
});
