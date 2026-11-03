import { and, asc, eq, isNull } from "drizzle-orm";
import { db } from "@/db";
import { endpointPrincipals, inboundHealth, inbounds, nodes, plans, subscriptionTokens, users } from "@/db/schema";
import { CLIENT_REGISTRY, findCapability, isAdmissible, isHardQuotaCapable, loadEvidence, type ClientFormat } from "@/lib/capabilities";
import { decryptSecret, sha256 } from "@/lib/crypto";
import { validateInboundCompatibility } from "@/lib/protocol-compatibility";

/** Canonical intermediate representation of one access path. */
export type AccessPath = {
  inboundId: number;
  tag: string;
  nodeName: string;
  server: string;
  port: number;
  protocol: "vless-reality-vision" | "hysteria2";
  transport: "tcp" | "udp";
  runtime: "singbox" | "xray" | "hysteria2";
  credential: string;
  sni: string;
  tlsModel: "reality" | "tls-self-managed";
  reality?: { publicKey: string; shortId: string; fingerprint: string; flow: string };
  route: "direct";
  enforceability: "hard" | "metered";
  revision: number;
  health: string;
};

export type Exclusion = { inboundId: number; name: string; reason: string };

export type IR = {
  user: { id: number; name: string; status: string };
  paths: AccessPath[];
  excluded: Exclusion[];
  diagnostics: string[];
  quotaBytes: number | null;
  expiresAt: Date | null;
};

export class CompileError extends Error {
  diagnostics: string[];
  constructor(diagnostics: string[]) {
    super("Subscription could not be compiled safely");
    this.diagnostics = diagnostics;
  }
}

export async function findUserByToken(token: string) {
  const [row] = await db
    .select({ u: users, t: subscriptionTokens })
    .from(subscriptionTokens)
    .innerJoin(users, eq(users.id, subscriptionTokens.userId))
    .where(and(eq(subscriptionTokens.tokenHash, sha256(token)), isNull(subscriptionTokens.revokedAt)));
  return row ?? null;
}

/** Builds the IR plus a per-endpoint explanation of why each path is included or excluded. */
export async function buildIR(userId: number, client: ClientFormat | null = null): Promise<IR> {
  const [u] = await db.select().from(users).where(eq(users.id, userId));
  const [plan] = await db.select().from(plans).where(eq(plans.id, u.planId));
  const ev = await loadEvidence();
  const rows = await db
    .select({ ib: inbounds, node: nodes, h: inboundHealth.state })
    .from(inbounds)
    .innerJoin(nodes, eq(nodes.id, inbounds.nodeId))
    .leftJoin(inboundHealth, eq(inboundHealth.inboundId, inbounds.id))
    .orderBy(asc(inbounds.id));
  const principals = await db
    .select()
    .from(endpointPrincipals)
    .where(and(eq(endpointPrincipals.userId, userId), eq(endpointPrincipals.state, "active")));
  const clientDef = client ? CLIENT_REGISTRY.find((c) => c.format === client) : null;

  const paths: AccessPath[] = [];
  const excluded: Exclusion[] = [];
  for (const { ib, node, h } of rows) {
    const exclude = (reason: string) => excluded.push({ inboundId: ib.id, name: `${node.name} / ${ib.name}`, reason });
    const cap = findCapability(ib.runtime, ib.protocol);
    const compatibility = validateInboundCompatibility({
      runtime: ib.runtime,
      protocol: ib.protocol,
      transport: ib.transport,
      serverName: ib.sni,
      params: ib.params,
    });
    if (!ib.enabled) exclude("Endpoint administratively disabled");
    else if (!cap) exclude("Unsupported runtime/protocol (not in capability registry)");
    else if (!compatibility.supported) exclude(`Incompatible runtime configuration: ${compatibility.reason}`);
    else if (!isAdmissible(cap, ev)) exclude("Runtime build has no production qualification; lab evidence required");
    else if (node.status === "quarantined") exclude("Node quarantined for security");
    else if (node.status === "draining") exclude("Node draining");
    else if (node.status === "pending_enrollment") exclude("Node not enrolled yet");
    else if (h === "confirmed_unreachable") exclude("Sustained failure confirmed by independent vantages");
    else if (clientDef && !(clientDef.protocols as readonly string[]).includes(ib.protocol)) {
      exclude(`Client format ${clientDef.label} does not support ${ib.protocol}`);
    } else {
      const p = principals.find((x) => x.inboundId === ib.id);
      if (!p) exclude("No credential provisioned for this user on this endpoint");
      else {
        paths.push({
          inboundId: ib.id,
          tag: `${node.name}-${ib.name}`.replace(/[^a-zA-Z0-9_.-]+/g, "-"),
          nodeName: node.name,
          server: node.publicAddress,
          port: ib.port,
          protocol: ib.protocol as AccessPath["protocol"],
          transport: ib.transport as AccessPath["transport"],
          runtime: ib.runtime as AccessPath["runtime"],
          credential: decryptSecret(p.credentialEnc),
          sni: ib.sni,
          tlsModel: ib.protocol === "vless-reality-vision" ? "reality" : "tls-self-managed",
          reality:
            ib.protocol === "vless-reality-vision"
              ? {
                  publicKey: ib.params.realityPublicKey,
                  shortId: ib.params.shortId,
                  fingerprint: ib.params.fingerprint ?? "chrome",
                  flow: ib.params.flow ?? "xtls-rprx-vision",
                }
              : undefined,
          route: "direct",
          enforceability: cap && isHardQuotaCapable(cap, ev) ? "hard" : "metered",
          revision: node.structuralSeq,
          health: h ?? "healthy",
        });
      }
    }
  }
  const diagnostics: string[] = [];
  return {
    user: { id: u.id, name: u.name, status: u.status },
    paths,
    excluded,
    diagnostics,
    quotaBytes: plan?.quotaBytes ?? null,
    expiresAt: u.expiresAt,
  };
}

/* ---------- Emitters (deterministic: ordered by inbound id) ---------- */

export function emitSingbox(ir: IR): string {
  const outbounds: unknown[] = ir.paths.map((p) =>
    p.protocol === "vless-reality-vision"
      ? {
          type: "vless",
          tag: p.tag,
          server: p.server,
          server_port: p.port,
          uuid: p.credential,
          flow: p.reality!.flow,
          tls: {
            enabled: true,
            server_name: p.sni,
            utls: { enabled: true, fingerprint: p.reality!.fingerprint },
            reality: { enabled: true, public_key: p.reality!.publicKey, short_id: p.reality!.shortId },
          },
        }
      : {
          type: "hysteria2",
          tag: p.tag,
          server: p.server,
          server_port: p.port,
          password: p.credential,
          tls: { enabled: true, server_name: p.sni },
        },
  );
  const tags = ir.paths.map((p) => p.tag);
  return JSON.stringify(
    {
      log: { level: "warn" },
      outbounds: [
        { type: "selector", tag: "proxy", outbounds: ["auto", ...tags], default: "auto" },
        { type: "urltest", tag: "auto", outbounds: tags, url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: 50 },
        ...outbounds,
        { type: "direct", tag: "direct" },
      ],
      route: { final: "proxy", auto_detect_interface: true },
    },
    null,
    2,
  );
}

/** Xray JSON inbound config for M2 Xray runtime nodes. */
export function emitXray(ir: IR): string {
  const inbounds: unknown[] = ir.paths.map((p) => {
    const base: Record<string, unknown> = {
      tag: p.tag,
      listen: "0.0.0.0",
      port: p.port,
      protocol: "vless",
      settings: {
        clients: [{ id: p.credential, flow: p.reality!.flow }],
        decryption: "none",
      },
      streamSettings: {
        network: p.transport,
        security: "reality",
        realitySettings: {
          show: false,
          dest: `${p.sni}:443`,
          xver: 0,
          serverNames: [p.sni],
          privateKey: "", // filled by control plane from node secrets
          shortIds: [p.reality!.shortId],
        },
      },
    };
    if (p.transport === "tcp") {
      base.streamSettings = { ...(base.streamSettings as Record<string, unknown>), tcpSettings: { header: { type: "none" } } };
    }
    return base;
  });

  const outbounds: unknown[] = [
    { tag: "direct", protocol: "freedom", settings: {} },
    { tag: "block", protocol: "blackhole", settings: {} },
  ];

  return JSON.stringify(
    {
      log: { loglevel: "warning" },
      inbounds,
      outbounds,
      routing: {
        rules: [
          { type: "field", inboundTag: [...ir.paths.map((p) => p.tag)], outboundTag: "proxy" },
          { ip: ["geoip:private"], outboundTag: "block" },
        ],
      },
      dns: { servers: ["https://dns.google/dns-query"] },
    },
    null,
    2,
  );
}

const q = (s: string | number) => JSON.stringify(s); // JSON strings are valid YAML scalars

export function emitMihomo(ir: IR): string {
  const lines = ["proxies:"];
  for (const p of ir.paths) {
    if (p.protocol === "vless-reality-vision") {
      lines.push(
        `  - {name: ${q(p.tag)}, type: vless, server: ${q(p.server)}, port: ${p.port}, uuid: ${q(p.credential)}, network: tcp, udp: true, tls: true, flow: ${q(p.reality!.flow)}, servername: ${q(p.sni)}, client-fingerprint: ${q(p.reality!.fingerprint)}, reality-opts: {public-key: ${q(p.reality!.publicKey)}, short-id: ${q(p.reality!.shortId)}}}`,
      );
    } else {
      lines.push(
        `  - {name: ${q(p.tag)}, type: hysteria2, server: ${q(p.server)}, port: ${p.port}, password: ${q(p.credential)}, sni: ${q(p.sni)}}`,
      );
    }
  }
  const names = ir.paths.map((p) => q(p.tag)).join(", ");
  lines.push(
    "proxy-groups:",
    `  - {name: "PROXY", type: select, proxies: ["AUTO", ${names}]}`,
    `  - {name: "AUTO", type: url-test, url: "https://www.gstatic.com/generate_204", interval: 180, tolerance: 50, proxies: [${names}]}`,
    "rules:",
    '  - MATCH,PROXY',
    "",
  );
  return lines.join("\n");
}

const host = (s: string) => (s.includes(":") ? `[${s}]` : s);

export function emitUris(ir: IR): string {
  const uris = ir.paths.map((p) =>
    p.protocol === "vless-reality-vision"
      ? `vless://${p.credential}@${host(p.server)}:${p.port}?encryption=none&flow=${p.reality!.flow}&security=reality&sni=${encodeURIComponent(p.sni)}&fp=${p.reality!.fingerprint}&pbk=${p.reality!.publicKey}&sid=${p.reality!.shortId}&type=tcp#${encodeURIComponent(p.tag)}`
      : `hysteria2://${encodeURIComponent(p.credential)}@${host(p.server)}:${p.port}?sni=${encodeURIComponent(p.sni)}#${encodeURIComponent(p.tag)}`,
  );
  return Buffer.from(uris.join("\n"), "utf8").toString("base64");
}

export function compile(ir: IR, format: ClientFormat): { body: string; contentType: string } {
  if (ir.diagnostics.length) throw new CompileError(ir.diagnostics);
  switch (format) {
    case "singbox":
      return { body: emitSingbox(ir), contentType: "application/json; charset=utf-8" };
    case "xray":
      return { body: emitXray(ir), contentType: "application/json; charset=utf-8" };
    case "mihomo":
      return { body: emitMihomo(ir), contentType: "text/yaml; charset=utf-8" };
    default:
      return { body: emitUris(ir), contentType: "text/plain; charset=utf-8" };
  }
}
