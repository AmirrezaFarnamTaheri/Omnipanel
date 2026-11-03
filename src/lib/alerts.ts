import { and, eq, isNull } from "drizzle-orm";
import { db } from "@/db";
import { alerts, inboundHealth, inbounds, nodes } from "@/db/schema";

export const HEARTBEAT_ALERT_MS = 120_000;

type Want = { severity: string; kind: string; nodeId: number | null; message: string; dedupeKey: string };

/** Computes the set of conditions that currently warrant alerts; opens new ones and resolves cleared ones. */
export async function evaluateAlerts() {
  const want = new Map<string, Want>();
  const add = (w: Want) => want.set(w.dedupeKey, w);
  const allNodes = await db.select().from(nodes);
  const now = Date.now();

  for (const n of allNodes) {
    if (n.status === "pending_enrollment" || n.status === "quarantined") continue;
    if (!n.lastSeenAt || now - n.lastSeenAt.getTime() > HEARTBEAT_ALERT_MS) {
      add({
        severity: "critical",
        kind: "node_offline",
        nodeId: n.id,
        message: `${n.name} has not reported for over ${HEARTBEAT_ALERT_MS / 1000}s`,
        dedupeKey: `node_offline:${n.id}`,
      });
    }
    if (n.appliedState === "DEGRADED_REQUIRES_OPERATOR") {
      add({
        severity: "critical",
        kind: "operator_required",
        nodeId: n.id,
        message: `${n.name} could not restore a known-good configuration and needs an operator`,
        dedupeKey: `operator_required:${n.id}`,
      });
    }
    if (n.structuralSeq > n.appliedStructuralSeq && n.lastSeenAt && n.appliedState !== "UNKNOWN" && n.appliedState === "FAILED") {
      add({
        severity: "warning",
        kind: "deploy_failed",
        nodeId: n.id,
        message: `${n.name} failed to apply revision ${n.structuralSeq}`,
        dedupeKey: `deploy_failed:${n.id}`,
      });
    }
  }

  const bad = await db
    .select({ ib: inbounds, h: inboundHealth })
    .from(inboundHealth)
    .innerJoin(inbounds, eq(inbounds.id, inboundHealth.inboundId))
    .where(eq(inboundHealth.state, "confirmed_unreachable"));
  for (const { ib } of bad) {
    add({
      severity: "critical",
      kind: "endpoint_unreachable",
      nodeId: ib.nodeId,
      message: `Endpoint "${ib.name}" is confirmed unreachable from independent vantages`,
      dedupeKey: `endpoint_unreachable:${ib.id}`,
    });
  }

  const live = allNodes.filter((n) => n.status === "active");
  const providers = new Set(live.map((n) => n.provider.toLowerCase()));
  if (live.length > 0 && providers.size < 2) {
    add({
      severity: "warning",
      kind: "provider_diversity",
      nodeId: null,
      message: "Fewer than two independent providers are active; a provider-wide block would remove every path",
      dedupeKey: "provider_diversity",
    });
  }

  const open = await db.select().from(alerts).where(isNull(alerts.resolvedAt));
  for (const o of open) {
    if (!want.has(o.dedupeKey)) await db.update(alerts).set({ resolvedAt: new Date() }).where(eq(alerts.id, o.id));
  }
  const openKeys = new Set(open.map((o) => o.dedupeKey));
  for (const w of want.values()) {
    if (!openKeys.has(w.dedupeKey)) await db.insert(alerts).values(w).onConflictDoNothing();
  }
  return db.select().from(alerts).where(and(isNull(alerts.resolvedAt)));
}
