import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { deploymentAttempts, inbounds, nodes } from "@/db/schema";
import { invalid } from "@/lib/problem";
import { recordObservation } from "@/lib/health";
import { validateResourceSnapshot, type ResourceSnapshot } from "@/lib/observability";
import { persistNodeResourceTelemetryInTx } from "@/lib/governance-store";

export const AGENT_REPORT_STATES = [
  "RECEIVED",
  "SIGNATURE_VERIFIED",
  "VALIDATED",
  "STAGED",
  "PREFLIGHTED",
  "APPLYING",
  "APPLIED_UNVERIFIED",
  "VERIFIED",
  "FAILED",
  "ROLLING_BACK",
  "ROLLED_BACK",
  "DEGRADED_REQUIRES_OPERATOR",
];

export type AgentReportBody = {
  epoch?: number;
  structuralSeq?: number;
  membershipSeq?: number;
  state?: string;
  agentVersion?: string;
  components?: Array<{ name: string; state: string; detail?: string }>;
  probes?: Array<{
    inboundId: number;
    vantage?: string;
    level: "L0" | "L1" | "L2" | "L3";
    ok: boolean;
    latencyMs?: number;
    detail?: string;
  }>;
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

export async function processAgentReportPayload(
  node: { id: number; name: string; appliedState: string; appliedStructuralSeq: number; agentVersion: string | null },
  b: AgentReportBody | null,
) {
  if (!b) throw invalid("JSON body required");
  const isInt = (v: unknown) => typeof v === "number" && Number.isInteger(v) && v >= 0;
  if (!isInt(b.structuralSeq) || !isInt(b.membershipSeq) || !isInt(b.epoch)) {
    throw invalid("epoch, structuralSeq, membershipSeq must be non-negative integers");
  }
  if (!b.state || !AGENT_REPORT_STATES.includes(b.state)) {
    throw invalid(`state must be one of ${AGENT_REPORT_STATES.join(", ")}`);
  }

  let validatedResourceSnapshot: ResourceSnapshot | null = null;
  if (b.resourceSnapshot) {
    const candidateSnap: ResourceSnapshot = {
      nodeId: node.name,
      generation: b.resourceSnapshot.generation,
      sampledAt: new Date(b.resourceSnapshot.sampledAt),
      cpuPercent: b.resourceSnapshot.cpuPercent,
      memoryTotalBytes: b.resourceSnapshot.memoryTotalBytes,
      memoryUsedBytes: b.resourceSnapshot.memoryUsedBytes,
      filesystems: b.resourceSnapshot.filesystems ?? [],
      network: b.resourceSnapshot.network ?? [],
    };
    try {
      validateResourceSnapshot(candidateSnap);
      validatedResourceSnapshot = candidateSnap;
    } catch (err) {
      throw invalid(`Invalid resourceSnapshot: ${(err as Error).message}`);
    }
  }

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
      const [ib] = await tx
        .select({ id: inbounds.id })
        .from(inbounds)
        .where(and(eq(inbounds.id, Number(p.inboundId)), eq(inbounds.nodeId, node.id)));
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
    if (validatedResourceSnapshot) {
      await persistNodeResourceTelemetryInTx(
        tx,
        `agent:${node.name}`,
        node.id,
        validatedResourceSnapshot,
        "agent_reported",
      );
    }
  });
}
