import net from "node:net";
import { desc, eq, gte, and } from "drizzle-orm";
import { db } from "@/db";
import { healthObservations, inboundHealth, inbounds, nodes } from "@/db/schema";
import { resolvePublicAddress } from "@/lib/netguard";
import type { Tx } from "@/lib/tx";

export type HealthState =
  | "healthy"
  | "degraded"
  | "suspected_unreachable"
  | "confirmed_unreachable"
  | "recovering";

const WINDOW_MS = 15 * 60_000;
const COOLDOWN_MS = 120_000;
const CONSEC = 3;

type Obs = { vantage: string; ok: boolean; observedAt: Date };

/**
 * Multi-vantage, hysteresis-based state machine.
 *  - a vantage "fails" only after 3 consecutive failures
 *  - one failing vantage => suspected; two independent vantages => confirmed
 *  - recovery requires 3 consecutive successes and a 120 s cooldown since the last failure
 */
export function deriveState(prev: HealthState | null, obs: Obs[], now = new Date()): HealthState {
  const fresh = obs.filter((o) => now.getTime() - o.observedAt.getTime() < WINDOW_MS);
  if (!fresh.length) return prev ?? "healthy";
  const byVantage = new Map<string, Obs[]>();
  for (const o of [...fresh].sort((a, b) => b.observedAt.getTime() - a.observedAt.getTime())) {
    const l = byVantage.get(o.vantage) ?? [];
    l.push(o);
    byVantage.set(o.vantage, l);
  }
  let failing = 0;
  for (const l of byVantage.values()) {
    if (l.length >= CONSEC && l.slice(0, CONSEC).every((o) => !o.ok)) failing++;
  }
  if (failing >= 2) return "confirmed_unreachable";
  if (failing === 1) return prev === "confirmed_unreachable" ? "confirmed_unreachable" : "suspected_unreachable";

  const recent = [...fresh].sort((a, b) => b.observedAt.getTime() - a.observedAt.getTime());
  const lastFail = recent.find((o) => !o.ok);
  const anyRecentFail = recent.slice(0, 5).some((o) => !o.ok);
  const wasBad = prev === "confirmed_unreachable" || prev === "suspected_unreachable" || prev === "recovering";
  if (wasBad) {
    const sustained = recent.slice(0, CONSEC).every((o) => o.ok);
    const cooled = !lastFail || now.getTime() - lastFail.observedAt.getTime() >= COOLDOWN_MS;
    return sustained && cooled ? "healthy" : "recovering";
  }
  return anyRecentFail ? "degraded" : "healthy";
}

export async function recordObservation(
  tx: Tx,
  o: { nodeId: number; inboundId: number; vantage: string; level: "L0" | "L1" | "L2" | "L3"; ok: boolean; latencyMs?: number | null; detail?: string },
) {
  await tx.insert(healthObservations).values({
    nodeId: o.nodeId,
    inboundId: o.inboundId,
    vantage: o.vantage.slice(0, 60),
    level: o.level,
    ok: o.ok,
    latencyMs: o.latencyMs ?? null,
    detail: (o.detail ?? "").slice(0, 200),
  });
  const rows = await tx
    .select()
    .from(healthObservations)
    .where(and(eq(healthObservations.inboundId, o.inboundId), gte(healthObservations.observedAt, new Date(Date.now() - WINDOW_MS))))
    .orderBy(desc(healthObservations.id))
    .limit(60);
  const [prevRow] = await tx.select().from(inboundHealth).where(eq(inboundHealth.inboundId, o.inboundId));
  const next = deriveState((prevRow?.state as HealthState) ?? null, rows);
  if (!prevRow) {
    await tx.insert(inboundHealth).values({ inboundId: o.inboundId, state: next });
  } else if (prevRow.state !== next) {
    await tx.update(inboundHealth).set({ state: next, since: new Date(), updatedAt: new Date() }).where(eq(inboundHealth.inboundId, o.inboundId));
  } else {
    await tx.update(inboundHealth).set({ updatedAt: new Date() }).where(eq(inboundHealth.inboundId, o.inboundId));
  }
  return next;
}

function tcpConnect(host: string, port: number, timeoutMs = 3000): Promise<{ ok: boolean; ms: number; detail: string }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const s = net.connect({ host, port });
    const done = (ok: boolean, detail: string) => {
      s.destroy();
      resolve({ ok, ms: Date.now() - start, detail });
    };
    s.setTimeout(timeoutMs, () => done(false, "timeout"));
    s.once("connect", () => done(true, "tcp connect ok"));
    s.once("error", (e) => done(false, (e as NodeJS.ErrnoException).code ?? "error"));
  });
}

/** L0 probe from the control-plane vantage. UDP listeners cannot be verified by a bare socket probe. */
export async function probeNodeNow(nodeId: number) {
  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  if (!node) return { probed: 0, skipped: 0, message: "Node not found" };
  const ibs = await db.select().from(inbounds).where(and(eq(inbounds.nodeId, nodeId), eq(inbounds.enabled, true)));
  let host: string;
  try {
    const ips = await resolvePublicAddress(node.publicAddress);
    if (!ips.length) return { probed: 0, skipped: ibs.length, message: "Address does not resolve" };
    host = ips[0];
  } catch (e) {
    return { probed: 0, skipped: ibs.length, message: (e as Error).message };
  }
  let probed = 0;
  let skipped = 0;
  for (const ib of ibs) {
    if (ib.transport !== "tcp") {
      skipped++;
      continue;
    }
    const r = await tcpConnect(host, ib.port);
    await db.transaction((tx) =>
      recordObservation(tx, { nodeId, inboundId: ib.id, vantage: "control-plane", level: "L0", ok: r.ok, latencyMs: r.ms, detail: r.detail }),
    );
    probed++;
  }
  return { probed, skipped, message: `${probed} TCP listener(s) probed, ${skipped} UDP listener(s) need an L1+ vantage` };
}
