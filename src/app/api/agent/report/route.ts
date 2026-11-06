import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { deploymentAttempts, inbounds, nodes } from "@/db/schema";
import { authenticateAgent } from "@/lib/nodes";
import { handle, invalid, json, ProblemError } from "@/lib/problem";
import { rateLimit } from "@/lib/ratelimit";
import { recordObservation } from "@/lib/health";
import { recordNodeResourceTelemetry } from "@/lib/governance-store";

export const dynamic = "force-dynamic";

const STATES = [
  "RECEIVED", "SIGNATURE_VERIFIED", "VALIDATED", "STAGED", "PREFLIGHTED", "APPLYING",
  "APPLIED_UNVERIFIED", "VERIFIED", "FAILED", "ROLLING_BACK", "ROLLED_BACK", "DEGRADED_REQUIRES_OPERATOR",
];

type Body = {
  epoch?: number;
  structuralSeq?: number;
  membershipSeq?: number;
  state?: string;
  agentVersion?: string;
  components?: Array<{ name: string; state: string; detail?: string }>;
  probes?: Array<{ inboundId: number; vantage?: string; level: "L0" | "L1" | "L2" | "L3"; ok: boolean; latencyMs?: number; detail?: string }>;
  resourceSnapshot?: {
    generation: number;
    sampledAt: string;
    cpuPercent: number;
    memoryTotalBytes: number;
    memoryUsedBytes: number;
    filesystems: Array<{ id: string; totalBytes: number; usedBytes: number }>;
    network: Array<{ interface: string; receivedBytes: number; sentBytes: number }>;
  };
};

export const POST = handle(async (req) => {
  const node = await authenticateAgent(req);
  if (!rateLimit(`agent:${node.id}`, 60, 5)) throw new ProblemError(429, "Too many requests", "Agent rate limit");
  if (Number(req.headers.get("content-length") ?? 0) > 1_000_000) throw new ProblemError(413, "Payload too large");
  const b = (await req.json().catch(() => null)) as Body | null;
  if (!b) throw invalid("JSON body required");
  const isInt = (v: unknown) => typeof v === "number" && Number.isInteger(v) && v >= 0;
  if (!isInt(b.structuralSeq) || !isInt(b.membershipSeq) || !isInt(b.epoch)) throw invalid("epoch, structuralSeq, membershipSeq must be non-negative integers");
  if (!b.state || !STATES.includes(b.state)) throw invalid(`state must be one of ${STATES.join(", ")}`);
  const components = (b.components ?? []).slice(0, 20).map((c) => ({
    name: String(c.name).slice(0, 40),
    state: String(c.state).slice(0, 40),
    detail: c.detail ? String(c.detail).slice(0, 200) : undefined,
  }));
  await db.transaction(async (tx) => {
    const changed = node.appliedState !== b.state || node.appliedStructuralSeq !== b.structuralSeq;
    await tx
      .update(nodes)
      .set({
        lastSeenAt: new Date(),
        appliedEpoch: b.epoch,
        appliedStructuralSeq: b.structuralSeq!,
        appliedMembershipSeq: b.membershipSeq!,
        appliedState: b.state!,
        components,
        agentVersion: b.agentVersion?.slice(0, 40) ?? node.agentVersion,
      })
      .where(eq(nodes.id, node.id));
    if (changed) {
      await tx.insert(deploymentAttempts).values({
        nodeId: node.id,
        epoch: b.epoch,
        structuralSeq: b.structuralSeq!,
        state: b.state!,
        components,
      });
    }
    for (const p of (b.probes ?? []).slice(0, 50)) {
      const [ib] = await tx.select({ id: inbounds.id }).from(inbounds).where(and(eq(inbounds.id, Number(p.inboundId)), eq(inbounds.nodeId, node.id)));
      if (!ib || !["L0", "L1", "L2", "L3"].includes(p.level)) continue;
      await recordObservation(tx, {
        nodeId: node.id,
        inboundId: ib.id,
        vantage: p.vantage ? `agent:${p.vantage}` : `agent:${node.name}`,
        level: p.level,
        ok: !!p.ok,
        latencyMs: p.latencyMs,
        detail: p.detail,
      });
    }
  });
  if (b.resourceSnapshot) {
    await recordNodeResourceTelemetry(`agent:${node.name}`, node.id, {
      nodeId: node.name,
      generation: b.resourceSnapshot.generation,
      sampledAt: new Date(b.resourceSnapshot.sampledAt),
      cpuPercent: b.resourceSnapshot.cpuPercent,
      memoryTotalBytes: b.resourceSnapshot.memoryTotalBytes,
      memoryUsedBytes: b.resourceSnapshot.memoryUsedBytes,
      filesystems: b.resourceSnapshot.filesystems ?? [],
      network: b.resourceSnapshot.network ?? [],
    });
  }
  return json({ ok: true });
});
