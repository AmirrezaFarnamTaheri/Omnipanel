import { eq } from "drizzle-orm";
import { db } from "@/db";
import { endpointPrincipals, inbounds, nodes, plans, users } from "@/db/schema";
import { sha256, randomToken } from "@/lib/crypto";
import { ProblemError } from "@/lib/problem";
import { createInbound, createNode } from "@/lib/nodes";
import { recordObservation } from "@/lib/health";
import { ingestMetering } from "@/lib/metering";
import { drainOutbox } from "@/lib/outbox";
import { publishStructural } from "@/lib/revisions";
import type { Actor } from "@/lib/tx";
import { createPlan, createUser } from "@/lib/users";

const GB = 1024 ** 3;

/** Loads a simulated two-provider topology. Nodes are marked enrolled without a real agent. */
export async function seedDemo(actor: Actor) {
  const existing = await db.select({ id: nodes.id }).from(nodes).limit(1);
  if (existing.length) throw new ProblemError(409, "Conflict", "Demo data can only be loaded into an empty topology");

  await createPlan(actor, { name: "Standard 100 GB", quotaGb: 100, enforcement: "metered" });
  await createPlan(actor, { name: "Lite 20 GB", quotaGb: 20, enforcement: "metered" });
  await createPlan(actor, { name: "Staff (unmetered)", quotaGb: null, enforcement: "unmetered" });

  const fra = await createNode(actor, { name: "fra-1", address: "203.0.113.10", provider: "Hetzner", asn: "AS24940", region: "Falkenstein, DE" });
  const sgp = await createNode(actor, { name: "sgp-1", address: "198.51.100.20", provider: "Vultr", asn: "AS20473", region: "Singapore" });

  await createInbound(actor, { nodeId: fra.nodeId, name: "reality-443", runtime: "singbox", protocol: "vless-reality-vision", port: 443, sni: "www.microsoft.com" });
  await createInbound(actor, { nodeId: fra.nodeId, name: "hy2-443", runtime: "singbox", protocol: "hysteria2", port: 443, sni: "www.bing.com" });
  await createInbound(actor, { nodeId: sgp.nodeId, name: "reality-443", runtime: "singbox", protocol: "vless-reality-vision", port: 443, sni: "www.cloudflare.com" });

  const [std] = await db.select().from(plans).where(eq(plans.name, "Standard 100 GB"));
  const [lite] = await db.select().from(plans).where(eq(plans.name, "Lite 20 GB"));
  const [staff] = await db.select().from(plans).where(eq(plans.name, "Staff (unmetered)"));
  const alice = await createUser(actor, { name: "alice", email: "alice@example.com", planId: std.id });
  await createUser(actor, { name: "bob", email: "bob@example.com", planId: lite.id });
  await createUser(actor, { name: "carol", email: "carol@example.com", planId: staff.id });

  for (const n of [fra.nodeId, sgp.nodeId]) {
    await db.transaction((tx) => publishStructural(tx, n, actor));
    const [row] = await db.select().from(nodes).where(eq(nodes.id, n));
    await db
      .update(nodes)
      .set({
        status: "active",
        nodeKeyHash: sha256(randomToken(24)),
        lastSeenAt: new Date(),
        agentVersion: "demo-sim",
        appliedEpoch: 1,
        appliedStructuralSeq: row.structuralSeq,
        appliedMembershipSeq: row.membershipSeq,
        appliedState: "VERIFIED",
        components: [
          { name: "sing-box", state: "VERIFIED" },
          { name: "nftables", state: "VERIFIED" },
        ],
      })
      .where(eq(nodes.id, n));
  }

  // Simulated cumulative counters from agents.
  const principals = await db
    .select({ p: endpointPrincipals, ib: inbounds, u: users })
    .from(endpointPrincipals)
    .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
    .innerJoin(users, eq(users.id, endpointPrincipals.userId))
    .where(eq(endpointPrincipals.state, "active"));
  const usageByUser: Record<string, number> = { alice: 6, bob: 9.8, carol: 3 };
  for (const nodeId of [fra.nodeId, sgp.nodeId]) {
    const obs = [];
    for (const { p, u } of principals.filter((x) => x.ib.nodeId === nodeId)) {
      const perPath = ((usageByUser[u.name] ?? 1) * GB) / 2;
      obs.push({ attributionKey: p.attributionKey, generation: "g1", seq: 1, up: 0, down: 0, generationStart: true });
      obs.push({ attributionKey: p.attributionKey, generation: "g1", seq: 2, up: Math.round(perPath * 0.08), down: Math.round(perPath * 0.92) });
    }
    await ingestMetering(nodeId, obs);
  }
  // A counter reset for carol on fra-1 demonstrates typed discontinuities.
  const carolFra = principals.find((x) => x.u.name === "carol" && x.ib.nodeId === fra.nodeId);
  if (carolFra) {
    await ingestMetering(fra.nodeId, [{ attributionKey: carolFra.p.attributionKey, generation: "g1", seq: 3, up: 10, down: 20 }]);
  }

  const ibs = await db.select().from(inbounds);
  for (const ib of ibs) {
    if (ib.transport !== "tcp") continue;
    for (const [vantage, level] of [["control-plane", "L0"], ["probe-eu", "L2"], ["probe-asia", "L2"]] as const) {
      await db.transaction((tx) => recordObservation(tx, { nodeId: ib.nodeId, inboundId: ib.id, vantage, level, ok: true, latencyMs: 40 + ib.id * 7, detail: "simulated" }));
    }
  }
  await drainOutbox();

  const base = process.env.OMNI_PUBLIC_URL?.replace(/\/$/, "") ?? "";
  return {
    message: "Demo topology loaded: 2 providers, 3 endpoints, 3 users, simulated metering. Bob is close to his quota.",
    secret: alice.token ? { label: "alice's subscription URL (shown once)", value: `${base}/sub/${alice.token}` } : undefined,
  };
}
