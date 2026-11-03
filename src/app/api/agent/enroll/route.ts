import { enrollNode } from "@/lib/nodes";
import { getSigner } from "@/lib/crypto";
import { getEpoch } from "@/lib/revisions";
import { rateLimit } from "@/lib/ratelimit";
import { handle, invalid, json, ProblemError } from "@/lib/problem";

export const dynamic = "force-dynamic";

// Enrollment is rate-limited globally (not per forwarded IP, which clients could spoof).
export const POST = handle(async (req) => {
  if (!rateLimit("agent:enroll", 20, 0.5)) throw new ProblemError(429, "Too many requests", "Enrollment rate limit");
  const body = (await req.json().catch(() => null)) as { token?: string; agentVersion?: string } | null;
  if (!body?.token || typeof body.token !== "string") throw invalid("token is required");
  const { nodeId, nodeKey } = await enrollNode(body.token, body.agentVersion?.slice(0, 40) ?? null);
  const signer = await getSigner();
  return json({
    nodeId,
    credential: `${nodeId}.${nodeKey}`,
    signingKeyId: signer.keyId,
    signingPublicKey: signer.publicKeyPem,
    epoch: await getEpoch(),
  });
});
