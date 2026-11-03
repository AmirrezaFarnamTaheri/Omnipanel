import { and, eq, gt, isNull, ne } from "drizzle-orm";
import { db } from "@/db";
import { endpointPrincipals, enrollmentTokens, inbounds, nodes, users } from "@/db/schema";
import { audit } from "@/lib/audit";
import { loadEvidence, findCapability, isAdmissible, isHardQuotaCapable } from "@/lib/capabilities";
import { encryptSecret, newRealityKeypair, randomToken, safeEqual, sha256 } from "@/lib/crypto";
import { idempotent } from "@/lib/idempotency";
import { resolvePublicAddress } from "@/lib/netguard";
import { conflict, invalid, notFound, ProblemError } from "@/lib/problem";
import { emitMembership } from "@/lib/revisions";
import type { Actor } from "@/lib/tx";
import { provisionPrincipal } from "@/lib/users";
import { plans } from "@/db/schema";

const RESERVED_PORTS = new Set([22]); // protected host-management / SSH recovery path
const ENROLL_TTL_MS = 60 * 60 * 1000;

/* ---------- Nodes ---------- */

export async function createNode(
  actor: Actor,
  input: { name: string; address: string; provider: string; asn: string; region: string },
  idemKey?: string | null,
) {
  const name = input.name.trim();
  if (!/^[a-z0-9][a-z0-9-]{1,38}$/i.test(name)) throw invalid("Node name: 2-39 letters, digits or dashes");
  if (!input.provider.trim()) throw invalid("Provider is required (needed for diversity analysis)");
  try {
    await resolvePublicAddress(input.address);
  } catch (e) {
    throw invalid((e as Error).message);
  }
  let token: string | undefined;
  const res = await db.transaction((tx) =>
    idempotent(tx, "node.create", idemKey, input, async () => {
      const dup = await tx.select({ id: nodes.id }).from(nodes).where(eq(nodes.name, name));
      if (dup.length) throw conflict(`A node named "${name}" already exists`);
      const [n] = await tx
        .insert(nodes)
        .values({
          name,
          publicAddress: input.address.trim(),
          provider: input.provider.trim(),
          asn: input.asn.trim(),
          region: input.region.trim(),
        })
        .returning();
      token = `omni-enroll_${randomToken(32)}`;
      await tx.insert(enrollmentTokens).values({
        nodeId: n.id,
        tokenHash: sha256(token),
        expiresAt: new Date(Date.now() + ENROLL_TTL_MS),
      });
      await audit(tx, actor, "node.create", "node", n.id, { name, provider: n.provider, asn: n.asn });
      return { nodeId: n.id };
    }),
  );
  return { ...res, token };
}

export async function reissueEnrollment(actor: Actor, nodeId: number) {
  const token = `omni-enroll_${randomToken(32)}`;
  await db.transaction(async (tx) => {
    const [n] = await tx.select().from(nodes).where(eq(nodes.id, nodeId));
    if (!n) throw notFound("Node");
    await tx.delete(enrollmentTokens).where(and(eq(enrollmentTokens.nodeId, nodeId)));
    await tx.insert(enrollmentTokens).values({
      nodeId,
      tokenHash: sha256(token),
      expiresAt: new Date(Date.now() + ENROLL_TTL_MS),
    });
    await tx.update(nodes).set({ nodeKeyHash: null, status: "pending_enrollment" }).where(eq(nodes.id, nodeId));
    await audit(tx, actor, "node.reenroll", "node", nodeId, {});
  });
  return token;
}

/** Single-use token exchange. Node identity is derived from the token, never from request fields. */
export async function enrollNode(token: string, agentVersion: string | null) {
  const nodeKey = randomToken(32);
  return db.transaction(async (tx) => {
    const claimed = await tx
      .update(enrollmentTokens)
      .set({ usedAt: new Date() })
      .where(and(eq(enrollmentTokens.tokenHash, sha256(token)), isNull(enrollmentTokens.usedAt), gt(enrollmentTokens.expiresAt, new Date())))
      .returning();
    if (!claimed.length) throw new ProblemError(401, "Unauthorized", "Enrollment token is invalid, expired or already used");
    const nodeId = claimed[0].nodeId;
    await tx
      .update(nodes)
      .set({ nodeKeyHash: sha256(nodeKey), status: "active", agentVersion, lastSeenAt: new Date() })
      .where(eq(nodes.id, nodeId));
    await audit(tx, { label: `node:${nodeId}` }, "node.enroll", "node", nodeId, { agentVersion });
    return { nodeId, nodeKey };
  });
}

/** Agent authentication: `Authorization: Bearer <nodeId>.<key>`. Forwarded headers are never consulted. */
export async function authenticateAgent(req: Request) {
  const h = req.headers.get("authorization") ?? "";
  const m = /^Bearer (\d+)\.([A-Za-z0-9_-]{20,})$/.exec(h);
  if (!m) throw new ProblemError(401, "Unauthorized", "Missing or malformed agent credential");
  const [node] = await db.select().from(nodes).where(eq(nodes.id, Number(m[1])));
  if (!node || !node.nodeKeyHash || !safeEqual(node.nodeKeyHash, sha256(m[2]))) {
    throw new ProblemError(401, "Unauthorized", "Invalid agent credential");
  }
  if (node.status === "quarantined") throw new ProblemError(403, "Forbidden", "Node is quarantined");
  return node;
}

export async function setNodeStatus(actor: Actor, nodeId: number, status: "active" | "draining") {
  await db.transaction(async (tx) => {
    const [n] = await tx.select().from(nodes).where(eq(nodes.id, nodeId));
    if (!n) throw notFound("Node");
    if (n.status === "quarantined" || n.status === "pending_enrollment") throw conflict(`Node is ${n.status}`);
    await tx.update(nodes).set({ status }).where(eq(nodes.id, nodeId));
    await audit(tx, actor, status === "draining" ? "node.drain" : "node.undrain", "node", nodeId, {});
  });
}

export async function updateNodeAddress(actor: Actor, nodeId: number, address: string) {
  try {
    await resolvePublicAddress(address);
  } catch (e) {
    throw invalid((e as Error).message);
  }
  await db.transaction(async (tx) => {
    const [n] = await tx.select().from(nodes).where(eq(nodes.id, nodeId));
    if (!n) throw notFound("Node");
    await tx.update(nodes).set({ publicAddress: address.trim() }).where(eq(nodes.id, nodeId));
    await audit(tx, actor, "node.address_change", "node", nodeId, { from: n.publicAddress, to: address.trim() });
  });
}

/** Revokes the node's identity and returns the credentials that were installed on it. */
export async function quarantineNode(actor: Actor, nodeId: number) {
  return db.transaction(async (tx) => {
    const [n] = await tx.select().from(nodes).where(eq(nodes.id, nodeId));
    if (!n) throw notFound("Node");
    await tx.update(nodes).set({ status: "quarantined", nodeKeyHash: null }).where(eq(nodes.id, nodeId));
    await tx.delete(enrollmentTokens).where(eq(enrollmentTokens.nodeId, nodeId));
    const affected = await tx
      .select({ id: endpointPrincipals.id })
      .from(endpointPrincipals)
      .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
      .where(and(eq(inbounds.nodeId, nodeId), eq(endpointPrincipals.state, "active")));
    await audit(tx, actor, "node.quarantine", "node", nodeId, { affectedCredentials: affected.length });
    return affected.length;
  });
}

/** Post-compromise response: new credentials for every principal on the node and new Reality keys. */
export async function rotateNodeSecrets(actor: Actor, nodeId: number) {
  return db.transaction(async (tx) => {
    const rows = await tx
      .select({ p: endpointPrincipals, u: users, ib: inbounds })
      .from(endpointPrincipals)
      .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
      .innerJoin(users, eq(users.id, endpointPrincipals.userId))
      .where(and(eq(inbounds.nodeId, nodeId), eq(endpointPrincipals.state, "active")));
    for (const { p, u, ib } of rows) {
      await tx
        .update(endpointPrincipals)
        .set({ state: "revoked", revokedAt: new Date() })
        .where(eq(endpointPrincipals.id, p.id));
      await emitMembership(tx, "remove", p);
      await provisionPrincipal(tx, u, ib);
    }
    const ibs = await tx.select().from(inbounds).where(eq(inbounds.nodeId, nodeId));
    for (const ib of ibs) {
      if (ib.protocol === "vless-reality-vision") {
        const k = newRealityKeypair();
        await tx
          .update(inbounds)
          .set({
            params: { ...ib.params, realityPublicKey: k.publicKey, shortId: k.shortId },
            secrets: { ...ib.secrets, realityPrivateKey: encryptSecret(k.privateKey) },
          })
          .where(eq(inbounds.id, ib.id));
      }
    }
    await audit(tx, actor, "node.rotate_secrets", "node", nodeId, { credentials: rows.length, inbounds: ibs.length });
    return rows.length;
  });
}

/* ---------- Inbounds ---------- */

export type InboundInput = {
  nodeId: number;
  name: string;
  runtime: string;
  protocol: string;
  port: number;
  sni: string;
};

function validateListener(port: number, sni: string) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw invalid("Port must be 1-65535");
  if (RESERVED_PORTS.has(port)) throw invalid(`Port ${port} is reserved for the protected host-management path`);
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(sni)) {
    throw invalid("SNI must be a valid hostname");
  }
}

export async function createInbound(actor: Actor, input: InboundInput, idemKey?: string | null) {
  const cap = findCapability(input.runtime, input.protocol);
  if (!cap) throw invalid(`Unsupported combination ${input.runtime}/${input.protocol}: not in the capability registry`);
  const ev = await loadEvidence();
  if (!isAdmissible(cap, ev)) {
    throw invalid(`${cap.key} is gated: record verified "admission" evidence on the Capabilities page first`);
  }
  validateListener(input.port, input.sni);
  const name = input.name.trim();
  if (name.length < 2 || name.length > 60) throw invalid("Inbound name must be 2-60 characters");

  return db.transaction((tx) =>
    idempotent(tx, "inbound.create", idemKey, input, async () => {
      const [node] = await tx.select().from(nodes).where(eq(nodes.id, input.nodeId));
      if (!node) throw notFound("Node");
      const clash = await tx
        .select({ id: inbounds.id, name: inbounds.name })
        .from(inbounds)
        .where(and(eq(inbounds.nodeId, node.id), eq(inbounds.transport, cap.transport), eq(inbounds.port, input.port)));
      if (clash.length) {
        throw conflict(`${cap.transport.toUpperCase()} port ${input.port} on ${node.name} is already owned by "${clash[0].name}"`);
      }
      // Hard-quota plans in use? Then the new endpoint must itself be verified hard-enforceable.
      const hardUsers = await tx
        .select({ id: users.id })
        .from(users)
        .innerJoin(plans, eq(plans.id, users.planId))
        .where(and(eq(plans.enforcement, "hard"), ne(users.status, "expired")))
        .limit(1);
      if (hardUsers.length && !isHardQuotaCapable(cap, ev)) {
        throw invalid("Users on hard-quota plans exist; this endpoint has no verified hard-quota evidence");
      }
      let params: Record<string, string> = {};
      let secrets: Record<string, string> = {};
      if (cap.protocol === "vless-reality-vision") {
        const k = newRealityKeypair();
        params = { realityPublicKey: k.publicKey, shortId: k.shortId, flow: "xtls-rprx-vision", fingerprint: "chrome" };
        secrets = { realityPrivateKey: encryptSecret(k.privateKey) };
      }
      const [ib] = await tx
        .insert(inbounds)
        .values({
          nodeId: node.id,
          name,
          runtime: cap.runtime,
          protocol: cap.protocol,
          transport: cap.transport,
          port: input.port,
          sni: input.sni.trim().toLowerCase(),
          params,
          secrets,
        })
        .returning();
      const all = await tx.select().from(users).where(ne(users.status, "expired"));
      for (const u of all) await provisionPrincipal(tx, u, ib);
      await audit(tx, actor, "inbound.create", "node", node.id, {
        inboundId: ib.id,
        capability: cap.key,
        port: ib.port,
        provisioned: all.length,
      });
      return { inboundId: ib.id };
    }),
  );
}

export async function updateInbound(actor: Actor, inboundId: number, port: number, sni: string) {
  validateListener(port, sni);
  return db.transaction(async (tx) => {
    const [ib] = await tx.select().from(inbounds).where(eq(inbounds.id, inboundId));
    if (!ib) throw notFound("Inbound");
    const clash = await tx
      .select({ id: inbounds.id })
      .from(inbounds)
      .where(and(eq(inbounds.nodeId, ib.nodeId), eq(inbounds.transport, ib.transport), eq(inbounds.port, port), ne(inbounds.id, ib.id)));
    if (clash.length) throw conflict(`${ib.transport.toUpperCase()} port ${port} is already owned by another inbound`);
    await tx.update(inbounds).set({ port, sni: sni.trim().toLowerCase() }).where(eq(inbounds.id, ib.id));
    await audit(tx, actor, "inbound.update", "node", ib.nodeId, { inboundId, port, sni, was: { port: ib.port, sni: ib.sni } });
  });
}

export async function setInboundEnabled(actor: Actor, inboundId: number, enabled: boolean) {
  await db.transaction(async (tx) => {
    const [ib] = await tx.select().from(inbounds).where(eq(inbounds.id, inboundId));
    if (!ib) throw notFound("Inbound");
    await tx.update(inbounds).set({ enabled }).where(eq(inbounds.id, inboundId));
    await audit(tx, actor, enabled ? "inbound.enable" : "inbound.disable", "node", ib.nodeId, { inboundId });
  });
}
