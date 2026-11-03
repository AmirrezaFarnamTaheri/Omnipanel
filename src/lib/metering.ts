import { and, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import {
  endpointPrincipals,
  meterObservations,
  meterStreams,
  outboxJobs,
  usageAggregates,
  usageQualityIntervals,
} from "@/db/schema";
import type { Tx } from "@/lib/tx";
import { ProblemError } from "@/lib/problem";

export type Observation = {
  attributionKey: string;
  generation: string;
  seq: number;
  up: number;
  down: number;
  observedAt?: string;
  /** True when the agent witnessed the core process start, so counters began at zero. */
  generationStart?: boolean;
};

export type Gap = { from?: string; to?: string; reason: string; attributionKey?: string };

export type Classification =
  | "accepted"
  | "baseline"
  | "duplicate"
  | "stale"
  | "counter_reset"
  | "conflict"
  | "probe_excluded"
  | "unknown_principal";

const MAX_BATCH = 1000;

function parseObs(o: unknown): Observation {
  const x = o as Record<string, unknown>;
  const isCount = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
  if (
    !x ||
    typeof x.attributionKey !== "string" ||
    typeof x.generation !== "string" ||
    x.generation.length > 80 ||
    !isCount(x.seq) ||
    !isCount(x.up) ||
    !isCount(x.down)
  ) {
    throw new ProblemError(422, "Validation failed", "Malformed meter observation");
  }
  return x as unknown as Observation;
}

/**
 * Cumulative accounting. Deltas are computed only when continuity is established; resets, missing
 * baselines and conflicts become typed quality intervals, never fabricated usage. Duplicates have no effect.
 */
export async function ingestMetering(nodeId: number, rawObs: unknown[], rawGaps: Gap[] = []) {
  if (rawObs.length > MAX_BATCH) throw new ProblemError(413, "Batch too large", `At most ${MAX_BATCH} observations per request`);
  const observations = rawObs.map(parseObs);
  const summary: Record<Classification, number> = {
    accepted: 0,
    baseline: 0,
    duplicate: 0,
    stale: 0,
    counter_reset: 0,
    conflict: 0,
    probe_excluded: 0,
    unknown_principal: 0,
  };
  const affected = new Set<number>();

  await db.transaction(async (tx) => {
    for (const o of observations) {
      const cls = await ingestOne(tx, nodeId, o, affected);
      summary[cls]++;
    }
    for (const g of rawGaps.slice(0, 100)) {
      let userId: number | null = null;
      if (g.attributionKey) {
        const [p] = await tx
          .select({ userId: endpointPrincipals.userId })
          .from(endpointPrincipals)
          .where(eq(endpointPrincipals.attributionKey, g.attributionKey));
        userId = p?.userId ?? null;
      }
      await tx.insert(usageQualityIntervals).values({
        userId,
        nodeId,
        kind: "agent_overflow",
        note: `${g.reason}${g.from ? ` (${g.from} → ${g.to ?? "?"})` : ""}`.slice(0, 300),
      });
      if (userId) affected.add(userId);
    }
    // Quota policy is applied by the outbox worker, committed atomically with the accounting.
    for (const userId of affected) {
      await tx.insert(outboxJobs).values({ kind: "quota.evaluate", payload: { userId } });
    }
  });
  return summary;
}

async function ingestOne(tx: Tx, nodeId: number, o: Observation, affected: Set<number>): Promise<Classification> {
  if (o.attributionKey.startsWith("probe-")) return "probe_excluded"; // probe identities never consume quota
  const [principal] = await tx
    .select({ userId: endpointPrincipals.userId })
    .from(endpointPrincipals)
    .where(eq(endpointPrincipals.attributionKey, o.attributionKey));
  if (!principal) return "unknown_principal";
  const userId = principal.userId;
  const now = new Date();
  let observedAt = o.observedAt ? new Date(o.observedAt) : now;
  if (Number.isNaN(observedAt.getTime()) || observedAt.getTime() > now.getTime()) observedAt = now;

  const quality = (kind: string, note: string) =>
    tx.insert(usageQualityIntervals).values({ userId, nodeId, kind, note });

  const [stream] = await tx
    .select()
    .from(meterStreams)
    .where(
      and(
        eq(meterStreams.nodeId, nodeId),
        eq(meterStreams.attributionKey, o.attributionKey),
        eq(meterStreams.generation, o.generation),
      ),
    )
    .for("update");

  let cls: Classification;
  let dUp = 0;
  let dDown = 0;
  let streamId: number;

  if (!stream) {
    const [prior] = await tx
      .select({ id: meterStreams.id })
      .from(meterStreams)
      .where(and(eq(meterStreams.nodeId, nodeId), eq(meterStreams.attributionKey, o.attributionKey)))
      .limit(1);
    if (o.generationStart) {
      dUp = o.up;
      dDown = o.down;
      cls = "accepted";
    } else {
      cls = "baseline";
      if (prior) await quality("missing_baseline", `New counter generation ${o.generation} observed without a start marker`);
    }
    const [s] = await tx
      .insert(meterStreams)
      .values({
        nodeId,
        attributionKey: o.attributionKey,
        generation: o.generation,
        userId,
        lastSeq: o.seq,
        lastUp: o.up,
        lastDown: o.down,
      })
      .returning({ id: meterStreams.id });
    streamId = s.id;
  } else {
    streamId = stream.id;
    if (o.seq <= stream.lastSeq) {
      const [existing] = await tx
        .select()
        .from(meterObservations)
        .where(and(eq(meterObservations.streamId, stream.id), eq(meterObservations.seq, o.seq)));
      if (existing && existing.up === o.up && existing.down === o.down) return "duplicate";
      if (existing) {
        await quality("conflict", `Conflicting observation for seq ${o.seq}`);
        return "conflict";
      }
      return "stale"; // cumulative counters: a later observation already covers this interval
    }
    if (o.up < stream.lastUp || o.down < stream.lastDown) {
      cls = "counter_reset";
      await quality("counter_reset", `Counter decreased within generation ${o.generation}; usage since last observation unknown`);
    } else {
      cls = "accepted";
      dUp = o.up - stream.lastUp;
      dDown = o.down - stream.lastDown;
    }
    await tx
      .update(meterStreams)
      .set({ lastSeq: o.seq, lastUp: o.up, lastDown: o.down, updatedAt: now })
      .where(eq(meterStreams.id, stream.id));
  }

  await tx.insert(meterObservations).values({
    streamId,
    seq: o.seq,
    up: o.up,
    down: o.down,
    deltaUp: dUp,
    deltaDown: dDown,
    classification: cls,
    observedAt,
  });
  if (dUp || dDown) {
    const bucket = new Date(Math.floor(observedAt.getTime() / 3_600_000) * 3_600_000);
    await tx
      .insert(usageAggregates)
      .values({ userId, bucket, up: dUp, down: dDown })
      .onConflictDoUpdate({
        target: [usageAggregates.userId, usageAggregates.bucket],
        set: { up: sql`${usageAggregates.up} + ${dUp}`, down: sql`${usageAggregates.down} + ${dDown}` },
      });
  }
  affected.add(userId);
  return cls;
}
