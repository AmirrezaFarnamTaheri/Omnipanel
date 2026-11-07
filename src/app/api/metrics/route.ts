import crypto from "node:crypto";
import { count, eq } from "drizzle-orm";
import { db } from "@/db";
import { inboundHealth, nodes, users } from "@/db/schema";
import { verifyAuditChain } from "@/lib/audit";
import { resolveAuthenticatedAdminFromToken } from "@/lib/auth";
import { listDesiredStateProposals } from "@/lib/governance-store";
import { getEpoch } from "@/lib/revisions";
import { renderOpenTelemetryPrometheusMetrics } from "@/lib/enterprise-hardening";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  // This endpoint exposes administrative health and subscriber counts. Fail closed
  // before issuing any database queries when the session cookie is absent or invalid.
  const sessionCookie = req.headers.get("cookie")
    ?.split(";")
    .map((pair) => pair.trim())
    .find((pair) => pair.startsWith("omni_session="));
  const sessionToken = sessionCookie?.slice("omni_session=".length);
  if (!(await resolveAuthenticatedAdminFromToken(sessionToken))) {
    return new Response("Unauthorized", {
      status: 401,
      headers: { "cache-control": "no-store" },
    });
  }
  const epoch = await getEpoch();
  const auditChain = await verifyAuditChain();
  const [{ nn }] = await db.select({ nn: count() }).from(nodes);
  const [{ nh }] = await db
    .select({ nh: count() })
    .from(inboundHealth)
    .where(eq(inboundHealth.state, "healthy"));
  const [{ nu }] = await db
    .select({ nu: count() })
    .from(users)
    .where(eq(users.status, "active"));
  const proposals = await listDesiredStateProposals();
  const pendingProposals = proposals.filter((p) => !p.decision || p.decision.consumedAt === null).length;

  const incomingTrace = req.headers.get("traceparent");
  const traceparent =
    incomingTrace && /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/.test(incomingTrace)
      ? incomingTrace
      : `00-${crypto.randomBytes(16).toString("hex")}-${crypto.randomBytes(8).toString("hex")}-01`;

  const body = renderOpenTelemetryPrometheusMetrics({
    epoch,
    auditChainHeight: auditChain.count,
    auditChainIntact: auditChain.ok,
    enrolledNodes: nn,
    healthyInbounds: nh,
    activeSubscribers: nu,
    pendingProposals,
  });

  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/plain; version=0.0.4; charset=utf-8",
      "cache-control": "no-store",
      traceparent,
    },
  });
}
