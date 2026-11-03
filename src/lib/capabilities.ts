import { desc } from "drizzle-orm";
import { db } from "@/db";
import { capabilityEvidence } from "@/db/schema";

/**
 * Legacy candidate descriptions and historical notes, not runtime qualification.
 * Version-scoped laboratory registries live in capabilities/*.json.
 * Unknown capability == unsupported for a contractual production guarantee.
 */

export { hasEvidence, isAdmissible, isHardQuotaCapable } from "./capability-policy";
export type { Claim, EvidenceMap } from "./capability-policy";
import type { EvidenceMap } from "./capability-policy";

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
    gated: true,
    metering: {
      source: "sing-box v2ray_api per-user stats (cumulative)",
      counter: "cumulative",
      direction: "uplink/downlink measured at the authenticating inbound; transport framing excluded",
      note: "Counters reset on process restart; the agent must report a new generation.",
    },
    revocation: { newSessions: "Blocked after config reload", existingSessions: "Persist until closed" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "Unqualified Reality/Vision candidate; native validation and real connectivity evidence required.",
  },
  {
    key: "singbox:hysteria2",
    runtime: "singbox",
    protocol: "hysteria2",
    transport: "udp",
    defaultPort: 443,
    gated: true,
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
    gated: true,
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
      note: "Provider capacity billing is not authoritative per-user proxy usage; meter at the authenticating core.",
    },
    revocation: { newSessions: "DNS failover immediate", existingSessions: "TTL-bound" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "CDN integration candidate; gated until admission evidence recorded.",
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
      note: "Operational capacity telemetry only; never a second billable user meter.",
    },
    revocation: { newSessions: "Tunnel teardown", existingSessions: "Drain on tunnel close" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "Relay integration candidate; gated until admission evidence recorded.",
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
      note: "Tunnel capacity counters are not authoritative per-user billable usage.",
    },
    revocation: { newSessions: "Peer config revoke", existingSessions: "Keepalive timeout" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "WARP egress candidate; gated until admission evidence recorded.",
  },
  {
    key: "bpb:http",
    runtime: "bpb",
    protocol: "http",
    transport: "tcp",
    defaultPort: 443,
    gated: true,
    metering: {
      source: "Unmanaged external source; no authoritative per-user meter",
      counter: "cumulative",
      direction: "Unknown until source-specific verification",
      note: "Shared external credentials cannot guarantee individual suspension or quotas.",
    },
    revocation: { newSessions: "Not guaranteed", existingSessions: "Not guaranteed" },
    hardQuotaCandidate: false,
    credential: "uuid",
    notes: "BPB Workers are restricted external sources, not a managed bandwidth policy engine. No individual quota guarantee.",
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
    evidence: "unverified",
  },
  {
    id: "mihomo",
    format: "mihomo",
    label: "Mihomo YAML",
    uaHints: ["clash", "mihomo", "stash", "verge"],
    protocols: ["vless-reality-vision", "hysteria2"],
    failover: "url-test proxy group",
    evidence: "unverified",
  },
  {
    id: "uri",
    format: "uri",
    label: "URI bundle (base64)",
    uaHints: [],
    protocols: ["vless-reality-vision", "hysteria2"],
    failover: "client dependent",
    evidence: "unverified",
  },
  {
    id: "xray",
    format: "xray",
    label: "Xray JSON (unqualified emitter)",
    uaHints: ["xray", "v2ray", "v2rayn"],
    protocols: ["vless-reality-vision"],
    failover: "uri fallback",
    evidence: "unverified",
  },
] as const;

export type ClientFormat = (typeof CLIENT_REGISTRY)[number]["format"];

export type ClientDefinition = (typeof CLIENT_REGISTRY)[number];

/** A client format is admitted only after protocol support and release evidence are verified. */
export function clientAdmissionReason(client: ClientDefinition | null, protocol: string): string | null {
  if (!client) return null;
  if (!(client.protocols as readonly string[]).includes(protocol)) {
    return `Client format ${client.label} does not support ${protocol}`;
  }
  if (client.evidence !== "verified") {
    return `Client format ${client.label} has no verified exact-release compatibility evidence`;
  }
  return null;
}

export const findCapability = (runtime: string, protocol: string) =>
  RUNTIME_CAPABILITIES.find((c) => c.runtime === runtime && c.protocol === protocol);

export const findCapabilityByKey = (key: string) =>
  RUNTIME_CAPABILITIES.find((c) => c.key === key);

export async function loadEvidence(): Promise<EvidenceMap> {
  const rows = await db.select().from(capabilityEvidence).orderBy(desc(capabilityEvidence.id));
  const m: EvidenceMap = new Map();
  for (const r of rows) {
    const k = `${r.capabilityKey}|${r.claim}`;
    if (!m.has(k)) m.set(k, r.status as "verified" | "failed");
  }
  return m;
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
