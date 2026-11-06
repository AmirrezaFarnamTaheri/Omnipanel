import { and, asc, desc, eq, gt, sql } from "drizzle-orm";
import { db } from "@/db";
import {
  endpointPrincipals,
  inbounds,
  membershipEvents,
  nodes,
  settings,
  structuralRevisions,
  users,
} from "@/db/schema";
import { audit } from "@/lib/audit";
import { decryptSecret, digestOf, getSigner, sha256 } from "@/lib/crypto";
import { DENY_CIDRS } from "@/lib/netguard";
import { notFound } from "@/lib/problem";
import type { Actor, Tx } from "@/lib/tx";

type Executor = Tx | typeof db;

export const DISRUPTION_ORDER = ["none", "hot", "reload", "listener_restart", "network", "unsupported"] as const;
export type Disruption = (typeof DISRUPTION_ORDER)[number];
const worse = (a: Disruption, b: Disruption) => (DISRUPTION_ORDER.indexOf(a) >= DISRUPTION_ORDER.indexOf(b) ? a : b);

/* ---------- Control-plane epoch ---------- */

export async function getEpoch(ex: Executor = db): Promise<number> {
  const [row] = await ex.select().from(settings).where(eq(settings.key, "control_plane_epoch"));
  if (row) return Number(row.value);
  await ex.insert(settings).values({ key: "control_plane_epoch", value: "1" }).onConflictDoNothing();
  return 1;
}

/* ---------- Manifests ---------- */

export type ManifestInbound = {
  id: number;
  name: string;
  protocol: string;
  runtime: string;
  transport: string;
  port: number;
  sni: string;
  params: Record<string, string>;
  secretRefs: Record<string, { ref: string; digest: string }>;
};

export type Manifest = {
  schema: "omni.desired-state/v1";
  node: { id: number; name: string };
  egress: { mode: "direct"; denyCidrs: string[] };
  inbounds: ManifestInbound[];
};

export async function buildManifest(ex: Executor, nodeId: number): Promise<Manifest> {
  const [node] = await ex.select().from(nodes).where(eq(nodes.id, nodeId));
  if (!node) throw notFound("Node");
  const rows = await ex
    .select()
    .from(inbounds)
    .where(and(eq(inbounds.nodeId, nodeId), eq(inbounds.enabled, true)))
    .orderBy(asc(inbounds.id));
  return {
    schema: "omni.desired-state/v1",
    node: { id: node.id, name: node.name },
    egress: { mode: "direct", denyCidrs: DENY_CIDRS },
    inbounds: rows.map((r) => ({
      id: r.id,
      name: r.name,
      protocol: r.protocol,
      runtime: r.runtime,
      transport: r.transport,
      port: r.port,
      sni: r.sni,
      params: r.params,
      secretRefs: Object.fromEntries(
        Object.entries(r.secrets).map(([k, enc]) => [
          k,
          { ref: `inbound/${r.id}/${k}`, digest: sha256(decryptSecret(enc)) },
        ]),
      ),
    })),
  };
}

export type InboundChange = { inboundId: number; name: string; kind: "added" | "removed" | "changed"; fields: string[]; disruption: Disruption };

export function diffManifests(prev: Manifest | null, next: Manifest) {
  const changes: InboundChange[] = [];
  const prevMap = new Map((prev?.inbounds ?? []).map((i) => [i.id, i]));
  const nextMap = new Map(next.inbounds.map((i) => [i.id, i]));
  for (const n of next.inbounds) {
    const p = prevMap.get(n.id);
    if (!p) {
      changes.push({ inboundId: n.id, name: n.name, kind: "added", fields: [], disruption: "listener_restart" });
      continue;
    }
    const fields: string[] = [];
    let d: Disruption = "none";
    if (p.port !== n.port || p.transport !== n.transport) {
      fields.push("listener (port/transport)");
      d = worse(d, "network");
    }
    if (p.runtime !== n.runtime || p.protocol !== n.protocol) {
      fields.push("runtime/protocol");
      d = worse(d, "listener_restart");
    }
    if (p.sni !== n.sni) {
      fields.push("sni");
      d = worse(d, "reload");
    }
    if (digestOf(p.params) !== digestOf(n.params)) {
      fields.push("transport parameters");
      d = worse(d, "listener_restart");
    }
    if (digestOf(p.secretRefs) !== digestOf(n.secretRefs)) {
      fields.push("secret material (digest changed)");
      d = worse(d, "listener_restart");
    }
    if (fields.length) changes.push({ inboundId: n.id, name: n.name, kind: "changed", fields, disruption: d });
  }
  for (const p of prev?.inbounds ?? []) {
    if (!nextMap.has(p.id)) {
      changes.push({ inboundId: p.id, name: p.name, kind: "removed", fields: [], disruption: "listener_restart" });
    }
  }
  if (prev && digestOf(prev.egress) !== digestOf(next.egress)) {
    changes.push({ inboundId: 0, name: "egress policy", kind: "changed", fields: ["egress"], disruption: "network" });
  }
  const disruption = changes.reduce<Disruption>((a, c) => worse(a, c.disruption), "none");
  return { changes, disruption };
}

export async function latestRevision(ex: Executor, nodeId: number) {
  const [rev] = await ex
    .select()
    .from(structuralRevisions)
    .where(eq(structuralRevisions.nodeId, nodeId))
    .orderBy(desc(structuralRevisions.sequence))
    .limit(1);
  return rev ?? null;
}

/** Preview of what publishing would do (redacted: only refs and digests, never raw secrets). */
export async function previewPublish(nodeId: number) {
  const manifest = await buildManifest(db, nodeId);
  const latest = await latestRevision(db, nodeId);
  const digest = digestOf(manifest);
  const diff = diffManifests((latest?.manifest as Manifest) ?? null, manifest);
  return { manifest, digest, latest, unchanged: latest?.digest === digest, ...diff };
}

/** Publishes an immutable structural revision. Rollback = new revision copying an earlier validated manifest. */
export async function publishStructural(
  tx: Tx,
  nodeId: number,
  actor: Actor,
  opts: { rollbackOfSequence?: number; force?: boolean } = {},
) {
  const latest = await latestRevision(tx, nodeId);
  let manifest: Manifest;
  let rollbackOf: number | null = null;
  if (opts.rollbackOfSequence) {
    const [target] = await tx
      .select()
      .from(structuralRevisions)
      .where(and(eq(structuralRevisions.nodeId, nodeId), eq(structuralRevisions.sequence, opts.rollbackOfSequence)));
    if (!target) throw notFound("Revision");
    manifest = target.manifest as Manifest;
    rollbackOf = target.sequence;
  } else {
    manifest = await buildManifest(tx, nodeId);
  }
  const digest = digestOf(manifest);
  if (!opts.force && latest?.digest === digest) return null;
  const { disruption } = diffManifests((latest?.manifest as Manifest) ?? null, manifest);
  const epoch = await getEpoch(tx);
  const [bumped] = await tx
    .update(nodes)
    .set({ structuralSeq: sql`${nodes.structuralSeq} + 1` })
    .where(eq(nodes.id, nodeId))
    .returning({ seq: nodes.structuralSeq });
  const [rev] = await tx
    .insert(structuralRevisions)
    .values({
      nodeId,
      epoch,
      sequence: bumped.seq,
      digest,
      manifest,
      disruption: latest ? disruption : "listener_restart",
      rollbackOf,
      createdBy: actor.label,
    })
    .returning();
  await audit(tx, actor, rollbackOf ? "revision.rollback" : "revision.publish", "node", nodeId, {
    sequence: rev.sequence,
    epoch,
    digest,
    disruption: rev.disruption,
    rollbackOf,
  });
  return rev;
}

export async function publishStructuralRevision(nodeId: number, actorLabel: string) {
  return db.transaction(async (tx) => {
    const rev = await publishStructural(tx, nodeId, { label: actorLabel }, { force: true });
    if (!rev) throw new Error("Failed to publish structural revision");
    return rev;
  });
}

/**
 * Publishes an exact dual-approved desired-state manifest inside the caller's transaction.
 * Refuses publication if any inbound or egress configuration on the node was modified
 * after the proposal envelope was signed (preventing content substitution).
 */
export async function publishApprovedManifest(
  tx: Tx,
  nodeId: number,
  actor: Actor,
  approvedManifest: Manifest,
  expectedSequence: number,
  expectedEpoch: number,
) {
  const [node] = await tx.select().from(nodes).where(eq(nodes.id, nodeId));
  if (!node) throw notFound("Node");

  const epoch = await getEpoch(tx);
  if (epoch !== expectedEpoch) {
    throw new Error(`Proposal epoch #${expectedEpoch} does not match current control-plane epoch #${epoch}`);
  }
  if (node.structuralSeq + 1 !== expectedSequence) {
    throw new Error(
      `Signed publication sequence #${expectedSequence} is not next after head #${node.structuralSeq}`,
    );
  }

  const liveCandidateManifest = await buildManifest(tx, nodeId);
  const approvedDigest = digestOf(approvedManifest);
  const liveCandidateDigest = digestOf(liveCandidateManifest);
  if (liveCandidateDigest !== approvedDigest) {
    throw new Error(
      `CANDIDATE_MANIFEST_DRIFT: Node #${nodeId} candidate configuration changed after signing (approved sha256:${approvedDigest.slice(0, 16)}… vs live sha256:${liveCandidateDigest.slice(0, 16)}…). Stage and approve a fresh proposal.`,
    );
  }

  const latest = await latestRevision(tx, nodeId);
  const { disruption } = diffManifests((latest?.manifest as Manifest) ?? null, approvedManifest);

  const [bumped] = await tx
    .update(nodes)
    .set({ structuralSeq: sql`${nodes.structuralSeq} + 1` })
    .where(eq(nodes.id, nodeId))
    .returning({ seq: nodes.structuralSeq });

  const [rev] = await tx
    .insert(structuralRevisions)
    .values({
      nodeId,
      epoch,
      sequence: bumped.seq,
      digest: approvedDigest,
      manifest: approvedManifest,
      disruption: latest ? disruption : "listener_restart",
      rollbackOf: null,
      createdBy: actor.label,
    })
    .returning();

  await audit(tx, actor, "revision.publish", "node", nodeId, {
    sequence: rev.sequence,
    epoch,
    digest: approvedDigest,
    disruption: rev.disruption,
    dualApproved: true,
  });

  return rev;
}

/* ---------- Membership stream ---------- */

export async function emitMembership(
  tx: Tx,
  type: "add" | "remove" | "suspend" | "resume",
  principal: { id: number; attributionKey: string; inboundId: number },
) {
  const [ib] = await tx.select({ nodeId: inbounds.nodeId }).from(inbounds).where(eq(inbounds.id, principal.inboundId));
  if (!ib) return;
  const [bumped] = await tx
    .update(nodes)
    .set({ membershipSeq: sql`${nodes.membershipSeq} + 1` })
    .where(eq(nodes.id, ib.nodeId))
    .returning({ seq: nodes.membershipSeq });
  await tx.insert(membershipEvents).values({
    nodeId: ib.nodeId,
    epoch: await getEpoch(tx),
    sequence: bumped.seq,
    type,
    principalId: principal.id,
    attributionKey: principal.attributionKey,
    inboundId: principal.inboundId,
  });
}

/* ---------- Delivery to agents ---------- */

export async function resolveSecrets(manifest: Manifest) {
  const out: Record<string, string> = {};
  for (const ib of manifest.inbounds) {
    if (!Object.keys(ib.secretRefs).length) continue;
    const [row] = await db.select({ secrets: inbounds.secrets }).from(inbounds).where(eq(inbounds.id, ib.id));
    for (const [name, ref] of Object.entries(ib.secretRefs)) {
      const enc = row?.secrets[name];
      if (!enc) continue;
      const plain = decryptSecret(enc);
      if (sha256(plain) === ref.digest) out[ref.ref] = plain; // only deliver material matching the signed digest
    }
  }
  return out;
}

export async function effectivePrincipals(nodeId: number) {
  return db
    .select({
      id: endpointPrincipals.id,
      attributionKey: endpointPrincipals.attributionKey,
      inboundId: endpointPrincipals.inboundId,
      credentialEnc: endpointPrincipals.credentialEnc,
    })
    .from(endpointPrincipals)
    .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
    .innerJoin(users, eq(users.id, endpointPrincipals.userId))
    .where(and(eq(inbounds.nodeId, nodeId), eq(endpointPrincipals.state, "active"), eq(users.status, "active")))
    .orderBy(asc(endpointPrincipals.id));
}

export async function buildDesiredResponse(
  nodeId: number,
  cursor: { epoch: number | null; structural: number; membership: number },
) {
  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  if (!node) throw notFound("Node");
  const epoch = await getEpoch();
  const signer = await getSigner();
  const crossEpoch = cursor.epoch !== epoch;
  const issuedAt = new Date().toISOString();

  let structural: unknown = null;
  const rev = await latestRevision(db, nodeId);
  if (rev && (crossEpoch || rev.sequence !== cursor.structural)) {
    const payload = {
      schema: "omni.structural/v1",
      epoch: rev.epoch,
      nodeId,
      sequence: rev.sequence,
      digest: rev.digest,
      disruption: rev.disruption,
      manifest: rev.manifest,
      rollbackOf: rev.rollbackOf,
      recovery: crossEpoch && cursor.epoch !== null ? { fromEpoch: cursor.epoch, toEpoch: epoch } : undefined,
      issuedAt,
    };
    structural = {
      payload,
      secrets: await resolveSecrets(rev.manifest as Manifest),
      signature: signer.sign(payload),
    };
  }

  let membership: unknown;
  if (crossEpoch || cursor.membership > node.membershipSeq) {
    const principals = await effectivePrincipals(nodeId);
    const payload = {
      schema: "omni.membership/v1",
      epoch,
      nodeId,
      mode: "snapshot",
      toSequence: node.membershipSeq,
      principals: principals.map((p) => ({
        attributionKey: p.attributionKey,
        inboundId: p.inboundId,
        credential: decryptSecret(p.credentialEnc),
      })),
      recovery: crossEpoch && cursor.epoch !== null ? { fromEpoch: cursor.epoch, toEpoch: epoch } : undefined,
      issuedAt,
    };
    membership = { payload, signature: signer.sign(payload) };
  } else if (cursor.membership < node.membershipSeq) {
    const events = await db
      .select()
      .from(membershipEvents)
      .where(and(eq(membershipEvents.nodeId, nodeId), gt(membershipEvents.sequence, cursor.membership)))
      .orderBy(asc(membershipEvents.sequence))
      .limit(500);
    const withCreds = [];
    for (const e of events) {
      let credential: string | null = null;
      if (e.type === "add" || e.type === "resume") {
        const [p] = await db.select().from(endpointPrincipals).where(eq(endpointPrincipals.id, e.principalId));
        if (p?.state === "active") credential = decryptSecret(p.credentialEnc);
      }
      withCreds.push({
        sequence: e.sequence,
        type: e.type,
        attributionKey: e.attributionKey,
        inboundId: e.inboundId,
        credential,
      });
    }
    const payload = {
      schema: "omni.membership/v1",
      epoch,
      nodeId,
      mode: "incremental",
      fromSequence: cursor.membership,
      toSequence: events.length ? events[events.length - 1].sequence : cursor.membership,
      events: withCreds,
      issuedAt,
    };
    membership = { payload, signature: signer.sign(payload) };
  } else {
    membership = null;
  }

  return { epoch, signingKeyId: signer.keyId, structural, membership };
}

/* ---------- Recovery epoch ---------- */

/** After a point-in-time restore: authorize a new epoch; every node gets a fresh signed revision. */
export async function declareRecoveryEpoch(tx: Tx, actor: Actor, reason: string) {
  const current = await getEpoch(tx);
  const next = current + 1;
  await tx.update(settings).set({ value: String(next) }).where(eq(settings.key, "control_plane_epoch"));
  const all = await tx.select({ id: nodes.id }).from(nodes);
  for (const n of all) await publishStructural(tx, n.id, actor, { force: true });
  await audit(tx, actor, "epoch.declare", "control_plane", next, { from: current, to: next, reason });
  return next;
}
