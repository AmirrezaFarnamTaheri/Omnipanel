import { desc } from "drizzle-orm";
import { db } from "@/db";
import { capabilityEvidence } from "@/db/schema";

/**
 * Evidence-backed capability registry (the in-code equivalent of
 * capabilities/runtime.yaml, clients.yaml and metering.yaml).
 * Unknown capability == unsupported for a contractual production guarantee.
 */

export type Claim = "admission" | "metering" | "revocation" | "hardQuota";

export type RuntimeCapability = {
  key: string;
  runtime: "singbox" | "xray" | "hysteria2" | "cdn" | "relay" | "warp" | "bpb";
  protocol: "vless-reality-vision" | "hysteria2" | "http" | "grpc" | "wireguard";
  transport: "tcp" | "udp";
  defaultPort: number;
  gated: boolean; // requires verified "admission" evidence before use
  metering: { source: string; counter: "cumulative" | "delta"; direction: string; note: string };
  revocation: { newSessions: string; existingSessions: string };
  hardQuotaCandidate: boolean; // can only be *used* once hardQuota evidence is verified
  credential: "uuid" | "password";
  notes: string;
};

export const RUNTIME_CAPABILITIES: RuntimeCapability[] = [
  {
    key: "singbox:vless-reality-vision",
    runtime: "singbox",
    protocol: "vless-reality-vision",
    transport: "tcp",
    defaultPort: 443,
    gated: false,
    metering: {
      source: "sing-box v2ray_api per-user stats (cumulative)",
      counter: "cumulative",
      direction: "uplink/downlink measured at the authenticating inbound; transport framing excluded",
      note: "Counters reset on process restart; the agent must report a new generation.",
    },
    revocation: { newSessions: "Blocked after config reload", existingSessions: "Persist until closed" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "Reference M0/M1 runtime for Reality/Vision.",
  },
  {
    key: "singbox:hysteria2",
    runtime: "singbox",
    protocol: "hysteria2",
    transport: "udp",
    defaultPort: 443,
    gated: false,
    metering: {
      source: "sing-box v2ray_api per-user stats",
      counter: "cumulative",
      direction: "measured at inbound",
      note: "Per-user stats on embedded Hysteria2 require lab confirmation.",
    },
    revocation: { newSessions: "Blocked after config reload", existingSessions: "Persist until closed" },
    hardQuotaCandidate: false,
    credential: "password",
    notes: "Embedded inbound alternative; compare against the standalone driver in the lab.",
  },
  {
    key: "hysteria2:hysteria2",
    runtime: "hysteria2",
    protocol: "hysteria2",
    transport: "udp",
    defaultPort: 443,
    gated: false,
    metering: {
      source: "Hysteria2 Traffic Stats API (/traffic)",
      counter: "cumulative",
      direction: "tx/rx per authenticated id",
      note: "HTTP auth backend gives per-client identity.",
    },
    revocation: { newSessions: "Denied by HTTP auth immediately", existingSessions: "Closable via /kick" },
    hardQuotaCandidate: true,
    credential: "password",
    notes: "Standalone driver. Hard quota may be claimed only after lab evidence is recorded.",
  },
  {
    key: "xray:vless-reality-vision",
    runtime: "xray",
    protocol: "vless-reality-vision",
    transport: "tcp",
    defaultPort: 443,
    gated: true,
    metering: {
      source: "Xray StatsService per-user counters",
      counter: "cumulative",
      direction: "uplink/downlink at inbound",
      note: "Dynamic user add/remove through handler API.",
    },
    revocation: { newSessions: "Hot user removal", existingSessions: "Persist until closed" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "Optional, gated until admission evidence is recorded.",
  },
  {
    key: "cdn:http",
    runtime: "cdn",
    protocol: "http",
    transport: "tcp",
    defaultPort: 443,
    gated: true,
    metering: {
      source: "CDN provider edge analytics",
      counter: "delta",
      direction: "edge-to-client bytes",
      note: "CDN billing is provider-reported; reconcile against origin metering.",
    },
    revocation: { newSessions: "DNS failover immediate", existingSessions: "TTL-bound" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "M2 CDN integration; gated until admission evidence recorded.",
  },
  {
    key: "relay:grpc",
    runtime: "relay",
    protocol: "grpc",
    transport: "tcp",
    defaultPort: 443,
    gated: true,
    metering: {
      source: "relay tunnel flow counters",
      counter: "cumulative",
      direction: "tunnel ingress/egress",
      note: "Relay nodes add a hop; per-flow attribution required.",
    },
    revocation: { newSessions: "Tunnel teardown", existingSessions: "Drain on tunnel close" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "M2 relay node integration; gated until admission evidence recorded.",
  },
  {
    key: "warp:wireguard",
    runtime: "warp",
    protocol: "wireguard",
    transport: "udp",
    defaultPort: 1701,
    gated: true,
    metering: {
      source: "WARP interface counters",
      counter: "cumulative",
      direction: "WARP tunnel bytes",
      note: "WARP provides client-to-edge connectivity.",
    },
    revocation: { newSessions: "Peer config revoke", existingSessions: "Keepalive timeout" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "M2 WARP integration; gated until admission evidence recorded.",
  },
  {
    key: "bpb:http",
    runtime: "bpb",
    protocol: "http",
    transport: "tcp",
    defaultPort: 443,
    gated: true,
    metering: {
      source: "BPB bandwidth policy engine",
      counter: "cumulative",
      direction: "shaped egress",
      note: "Bandwidth Policy Bridge enforces per-user rate limits.",
    },
    revocation: { newSessions: "Policy update immediate", existingSessions: "Token-bucket exhaustion" },
    hardQuotaCandidate: true,
    credential: "uuid",
    notes: "M2 BPB integration; hard quota candidate once evidence verified.",
  },
];

export const CLIENT_REGISTRY = [
  {
    id: "singbox",
    format: "singbox",
    label: "sing-box native JSON",
    uaHints: ["sing-box", "sfa", "sfi", "sfm", "singbox", "hiddify"],
    protocols: ["vless-reality-vision", "hysteria2"],
    failover: "urltest group with selector",
    evidence: "documented",
  },
  {
    id: "mihomo",
    format: "mihomo",
    label: "Mihomo YAML",
    uaHints: ["clash", "mihomo", "stash", "verge"],
    protocols: ["vless-reality-vision", "hysteria2"],
    failover: "url-test proxy group",
    evidence: "documented",
  },
  {
    id: "uri",
    format: "uri",
    label: "URI bundle (base64)",
    uaHints: [],
    protocols: ["vless-reality-vision", "hysteria2", "xray-vless-reality-vision"],
    failover: "client dependent",
    evidence: "documented",
  },
  {
    id: "xray",
    format: "xray",
    label: "Xray JSON inbound config",
    uaHints: ["xray", "v2ray", "v2rayn"],
    protocols: ["xray-vless-reality-vision"],
    failover: "uri fallback",
    evidence: "documented",
  },
] as const;

export type ClientFormat = (typeof CLIENT_REGISTRY)[number]["format"];

export const findCapability = (runtime: string, protocol: string) =>
  RUNTIME_CAPABILITIES.find((c) => c.runtime === runtime && c.protocol === protocol);

export const findCapabilityByKey = (key: string) =>
  RUNTIME_CAPABILITIES.find((c) => c.key === key);

export type EvidenceMap = Map<string, "verified" | "failed">; // `${key}|${claim}` -> latest status

export async function loadEvidence(): Promise<EvidenceMap> {
  const rows = await db.select().from(capabilityEvidence).orderBy(desc(capabilityEvidence.id));
  const m: EvidenceMap = new Map();
  for (const r of rows) {
    const k = `${r.capabilityKey}|${r.claim}`;
    if (!m.has(k)) m.set(k, r.status as "verified" | "failed");
  }
  return m;
}

export const hasEvidence = (m: EvidenceMap, key: string, claim: Claim) => m.get(`${key}|${claim}`) === "verified";

export function isAdmissible(cap: RuntimeCapability, ev: EvidenceMap) {
  return !cap.gated || hasEvidence(ev, cap.key, "admission");
}

export function isHardQuotaCapable(cap: RuntimeCapability, ev: EvidenceMap) {
  return cap.hardQuotaCandidate && hasEvidence(ev, cap.key, "hardQuota");
}

export function clientForRequest(format: string | null, userAgent: string | null): ClientFormat {
  if (format) {
    const f = CLIENT_REGISTRY.find((c) => c.format === format);
    if (f) return f.format;
  }
  const ua = (userAgent ?? "").toLowerCase();
  for (const c of CLIENT_REGISTRY) if (c.uaHints.some((h) => ua.includes(h))) return c.format;
  return "uri";
}
