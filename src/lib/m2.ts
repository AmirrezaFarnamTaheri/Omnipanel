import { db } from "@/db";
import {
  cdnMappings,
  relayTunnels,
  warpPeers,
  bpbPolicies,
  nodes,
  inbounds,
  capabilityEvidence,
} from "@/db/schema";
import { eq, and, desc, sql } from "drizzle-orm";
import { randomToken } from "@/lib/crypto";
import { ProblemError } from "@/lib/problem";
import { loadEvidence, findCapabilityByKey, isAdmissible } from "@/lib/capabilities";

/* ========================================================================
   M2: CDN (Content Delivery Network) integration
   ======================================================================== */

export type CdnProvider = {
  id: string;
  name: string;
  supported: boolean;
};

const CDN_PROVIDERS: CdnProvider[] = [
  { id: "cloudflare", name: "Cloudflare", supported: true },
  { id: "fastly", name: "Fastly", supported: true },
  { id: "aws_cloudfront", name: "AWS CloudFront", supported: true },
];

export async function listCdnProviders(): Promise<CdnProvider[]> {
  return CDN_PROVIDERS;
}

export type CdnMapping = {
  id: number;
  domain: string;
  origin: string;
  provider: string;
  status: string;
  createdAt: Date;
};

export async function createCdnMapping(input: {
  domain: string;
  origin: string;
  provider: string;
  ttl?: number;
}): Promise<CdnMapping> {
  if (!input.domain || !input.origin || !input.provider) {
    throw new ProblemError(422, "Validation failed", "domain, origin, and provider are required");
  }
  const [row] = await db
    .insert(cdnMappings)
    .values({
      domain: input.domain,
      origin: input.origin,
      provider: input.provider,
      status: "pending",
      createdAt: new Date(),
    })
    .returning();
  return {
    id: row.id,
    domain: row.domain,
    origin: row.origin,
    provider: row.provider,
    status: row.status,
    createdAt: row.createdAt,
  };
}

export async function listCdnMappings(): Promise<CdnMapping[]> {
  const rows = await db.select().from(cdnMappings).orderBy(desc(cdnMappings.createdAt));
  return rows.map((r) => ({
    id: r.id,
    domain: r.domain,
    origin: r.origin,
    provider: r.provider,
    status: r.status,
    createdAt: r.createdAt,
  }));
}

/* ========================================================================
   M2: Relay nodes
   ======================================================================== */

export type RelayNode = {
  id: string;
  name: string;
  address: string;
  status: string;
};

const RELAY_NODES: RelayNode[] = [
  { id: "relay-fra-1", name: "Frankfurt Relay 1", address: "relay-fra.omnipanel.example.net:443", status: "healthy" },
  { id: "relay-sin-1", name: "Singapore Relay 1", address: "relay-sin.omnipanel.example.net:443", status: "healthy" },
  { id: "relay-nyc-1", name: "New York Relay 1", address: "relay-nyc.omnipanel.example.net:443", status: "degraded" },
];

export async function listRelayNodes(): Promise<RelayNode[]> {
  return RELAY_NODES;
}

export type RelayTunnel = {
  id: number;
  sourceNode: string;
  destination: string;
  protocol: string;
  status: string;
  createdAt: Date;
};

export async function createRelayTunnel(input: {
  sourceNode: string;
  destination: string;
  protocol: string;
}): Promise<RelayTunnel> {
  if (!input.sourceNode || !input.destination || !input.protocol) {
    throw new ProblemError(422, "Validation failed", "sourceNode, destination, and protocol are required");
  }
  const [row] = await db
    .insert(relayTunnels)
    .values({
      sourceNode: input.sourceNode,
      destination: input.destination,
      protocol: input.protocol,
      status: "pending",
      createdAt: new Date(),
    })
    .returning();
  return {
    id: row.id,
    sourceNode: row.sourceNode,
    destination: row.destination,
    protocol: row.protocol,
    status: row.status,
    createdAt: row.createdAt,
  };
}

export async function listRelayTunnels(): Promise<RelayTunnel[]> {
  const rows = await db.select().from(relayTunnels).orderBy(desc(relayTunnels.createdAt));
  return rows.map((r) => ({
    id: r.id,
    sourceNode: r.sourceNode,
    destination: r.destination,
    protocol: r.protocol,
    status: r.status,
    createdAt: r.createdAt,
  }));
}

/* ========================================================================
   M2: WARP peers
   ======================================================================== */

export type WarpPeer = {
  id: string;
  publicKey: string;
  endpoint: string;
  status: string;
};

const WARP_PEERS: WarpPeer[] = [
  { id: "warp-peer-1", publicKey: "", endpoint: "warp1.omnipanel.example.net:51820", status: "connected" },
  { id: "warp-peer-2", publicKey: "", endpoint: "warp2.omnipanel.example.net:51820", status: "handshaking" },
];

export async function listWarpPeers(): Promise<WarpPeer[]> {
  return WARP_PEERS;
}

export type WarpInterface = {
  name: string;
  status: string;
  peers: number;
};

export async function configureWarp(input: {
  interfaceName: string;
  privateKey: string;
  peers: Array<{ publicKey: string; endpoint: string }>;
}): Promise<WarpInterface> {
  if (!input.interfaceName || !input.privateKey || !Array.isArray(input.peers)) {
    throw new ProblemError(422, "Validation failed", "interfaceName, privateKey, and peers are required");
  }
  for (const peer of input.peers) {
    await db
      .insert(warpPeers)
      .values({
        peerId: `warp-${randomToken(8)}`,
        publicKey: peer.publicKey,
        endpoint: peer.endpoint,
        status: "configured",
        createdAt: new Date(),
      })
      .onConflictDoNothing();
  }
  return {
    name: input.interfaceName,
    status: "active",
    peers: input.peers.length,
  };
}

/* ========================================================================
   M2: BPB (Bandwidth Policy Bridge) policy
   ======================================================================== */

export type BpbPolicy = {
  id: number;
  nodeId: number;
  bandwidthLimit: number;
  priority: number;
  updatedAt: Date;
};

export async function getBpbPolicy(nodeId?: number): Promise<BpbPolicy | null> {
  const rows = await db
    .select()
    .from(bpbPolicies)
    .where(nodeId ? eq(bpbPolicies.nodeId, nodeId) : sql`true`)
    .orderBy(desc(bpbPolicies.updatedAt));
  if (rows.length === 0) return null;
  const r = rows[0];
  return { id: r.id, nodeId: r.nodeId, bandwidthLimit: r.bandwidthLimit, priority: r.priority, updatedAt: r.updatedAt };
}

export async function updateBpbPolicy(input: {
  nodeId: number;
  bandwidthLimit: number;
  priority: number;
}): Promise<BpbPolicy> {
  if (!input.nodeId || !Number.isInteger(input.bandwidthLimit) || !Number.isInteger(input.priority)) {
    throw new ProblemError(422, "Validation failed", "nodeId, bandwidthLimit, and priority are required");
  }
  const existing = await getBpbPolicy(input.nodeId);
  if (existing) {
    const [row] = await db
      .update(bpbPolicies)
      .set({ bandwidthLimit: input.bandwidthLimit, priority: input.priority, updatedAt: new Date() })
      .where(eq(bpbPolicies.id, existing.id))
      .returning();
    return { id: row.id, nodeId: row.nodeId, bandwidthLimit: row.bandwidthLimit, priority: row.priority, updatedAt: row.updatedAt };
  }
  const [row] = await db
    .insert(bpbPolicies)
    .values({
      nodeId: input.nodeId,
      bandwidthLimit: input.bandwidthLimit,
      priority: input.priority,
      updatedAt: new Date(),
    })
    .returning();
  return { id: row.id, nodeId: row.nodeId, bandwidthLimit: row.bandwidthLimit, priority: row.priority, updatedAt: row.updatedAt };
}

/* ========================================================================
   M2: Xray node config (per-node Xray inbound configuration)
   ======================================================================== */

export type XrayNodeConfig = {
  nodeId: number;
  inbounds: Array<{
    tag: string;
    port: number;
    protocol: string;
    settings: unknown;
    streamSettings: unknown;
  }>;
};

export async function getXrayNodeConfig(nodeId: number): Promise<XrayNodeConfig> {
  const [node] = await db.select().from(nodes).where(eq(nodes.id, nodeId));
  if (!node) throw new ProblemError(404, "Not found", "Node not found");

  const ibs = await db.select().from(inbounds).where(eq(inbounds.nodeId, nodeId));
  const inboundsConfig = ibs.map((ib) => ({
    tag: `inbound-${ib.id}`,
    port: ib.port,
    protocol: ib.protocol,
    settings: { params: ib.params, secrets: ib.secrets },
    streamSettings: { network: ib.transport, security: "reality" },
  }));

  return { nodeId, inbounds: inboundsConfig };
}

/* ========================================================================
   Capability gating helpers for M2 runtimes
   ======================================================================== */

export async function checkM2Capability(key: string): Promise<{
  admissible: boolean;
  gated: boolean;
  evidence?: string | null;
}> {
  const cap = findCapabilityByKey(key);
  if (!cap) throw new ProblemError(404, "Not found", `Unknown capability: ${key}`);
  const ev = await loadEvidence();
  const admissible = isAdmissible(cap, ev);
  const evidence = ev.get(`${cap.key}|admission`) ?? null;
  return { admissible, gated: cap.gated, evidence };
}
