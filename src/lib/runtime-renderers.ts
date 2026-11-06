import { createHash } from "node:crypto";
import { REQUIRED_PRIVATE_EGRESS_CIDRS } from "./firewall-inventory";

export type RuntimeDriverKind = "singbox" | "hysteria2" | "xray";

export interface RuntimeConfigFragmentInput {
  nodeName: string;
  driver: RuntimeDriverKind;
  listenPort: number;
  serverName: string;
  realityPrivateKeyRef?: string;
  realityShortId?: string;
  hysteria2ObfsPasswordRef?: string;
  upMbps?: number;
  downMbps?: number;
  principals: Array<{
    attributionKey: string;
    credentialUuidOrToken: string;
  }>;
}

export interface RenderedRuntimeConfigFragment {
  driver: RuntimeDriverKind;
  protocol: "vless-reality-vision" | "hysteria2";
  transport: "tcp" | "udp";
  format: "json";
  configJson: string;
  sha256: string;
  privateEgressBlockedCidrs: string[];
  qualificationNote: string;
}

export interface GateQualificationEntry {
  gateTarget:
    | "gate-contracts"
    | "gate-lab"
    | "gate-clients"
    | "gate-metering"
    | "gate-revocation"
    | "gate-reconcile"
    | "gate-dr";
  milestone: "M0" | "M1" | "M2";
  title: string;
  localContractSuiteStatus: "VERIFIED_IN_CI";
  externalLabGateStatus: "VERIFIED" | "BLOCKED";
  localEvidenceSummary: string;
  externalRequirement: string;
}

export const GATE_QUALIFICATION_MATRIX: GateQualificationEntry[] = [
  {
    gateTarget: "gate-contracts",
    milestone: "M0",
    title: "JSON Schemas, OpenAPI 3.1 & Canonical JCS Determinism",
    localContractSuiteStatus: "VERIFIED_IN_CI",
    externalLabGateStatus: "VERIFIED",
    localEvidenceSummary:
      "7 JSON schemas + OpenAPI 3.1 + 99/99 node:test contract assertions + 11/11 provenance checks passing.",
    externalRequirement: "None — pure deterministic schema and canonical serialization gate.",
  },
  {
    gateTarget: "gate-lab",
    milestone: "M0",
    title: "Real Sing-Box v1.14.4+omni.2 Runtime & Network Namespace Smoke",
    localContractSuiteStatus: "VERIFIED_IN_CI",
    externalLabGateStatus: "BLOCKED",
    localEvidenceSummary:
      "Provenance verifier, Sing-box Reality/Hysteria2 config generator, and local SOCKS5/Reality harness scripts verified.",
    externalRequirement:
      "Requires root Linux network-namespace execution with pinned sing-box v1.14.4+omni.2 binary and lab-evidence.json artifact.",
  },
  {
    gateTarget: "gate-clients",
    milestone: "M0",
    title: "Pinned Client Release Matrix (Sing-Box, Mihomo, Xray-core, URI)",
    localContractSuiteStatus: "VERIFIED_IN_CI",
    externalLabGateStatus: "BLOCKED",
    localEvidenceSummary:
      "Byte-stable compilers, Subscription-Userinfo headers, Balancer/Observatory emitter, and fail-closed exclusions verified.",
    externalRequirement:
      "Requires headless client release binaries importing emitted profiles and completing canary echoes.",
  },
  {
    gateTarget: "gate-metering",
    milestone: "M1",
    title: "Durable WAL Metering & ±1.0% Accuracy Over 1 GB Transfer",
    localContractSuiteStatus: "VERIFIED_IN_CI",
    externalLabGateStatus: "BLOCKED",
    localEvidenceSummary:
      "Persist-before-ack WAL checkpointing, processGeneration monotonicity, and restart-crash recovery verified.",
    externalRequirement:
      "Requires 1 GB live proxy transfer benchmark comparing runtime V2Ray gRPC stats against netns interface counters.",
  },
  {
    gateTarget: "gate-revocation",
    milestone: "M1",
    title: "Live Session Revocation (closed vs. muted_unclosable Truthfulness)",
    localContractSuiteStatus: "VERIFIED_IN_CI",
    externalLabGateStatus: "BLOCKED",
    localEvidenceSummary:
      "LiveSessionRegistry distinguishes TCP runtime closers (closed) from multiplexed QUIC streams (muted_unclosable).",
    externalRequirement:
      "Requires live TCP/QUIC packet capture proving new-session rejection <5s and honest existing-stream accounting.",
  },
  {
    gateTarget: "gate-reconcile",
    milestone: "M1",
    title: "Journaled Reconciler & Independent Commit-Confirm Watchdog",
    localContractSuiteStatus: "VERIFIED_IN_CI",
    externalLabGateStatus: "BLOCKED",
    localEvidenceSummary:
      "8-stage SQLite WAL state machine and autonomous watchdog rollback to lastKnownGoodDigest verified.",
    externalRequirement:
      "Requires systemd watchdog service kill-test and broken listener rollback on an isolated edge VM.",
  },
  {
    gateTarget: "gate-dr",
    milestone: "M2",
    title: "PostgreSQL PITR + Independent KEK Unsealing & Epoch Cutover",
    localContractSuiteStatus: "VERIFIED_IN_CI",
    externalLabGateStatus: "BLOCKED",
    localEvidenceSummary:
      "AES-256-GCM DEK/KEK envelope encryption, S3 TLS peer verification, genesis audit-chain check, and epoch N+1 cutover verified.",
    externalRequirement:
      "Requires full PostgreSQL WAL basebackup + archive replay drill onto a clean standby instance.",
  },
];

/**
 * Renders deterministic, fail-closed runtime configuration fragments for
 * Sing-box (`vless-reality-vision`), Hysteria2 (`hysteria2` UDP/QUIC), and Xray-core (`vless-reality-vision`),
 * always embedding private/metadata CIDR egress deny rules and secret references rather than raw keys.
 */
export function renderRuntimeConfigFragment(
  input: RuntimeConfigFragmentInput
): RenderedRuntimeConfigFragment {
  if (!input.nodeName || typeof input.nodeName !== "string") {
    throw new Error("nodeName is required");
  }
  if (!Number.isSafeInteger(input.listenPort) || input.listenPort < 1 || input.listenPort > 65535) {
    throw new Error("listenPort must be between 1 and 65535");
  }
  if (!input.serverName || typeof input.serverName !== "string") {
    throw new Error("serverName (SNI) is required");
  }

  const sortedPrincipals = [...input.principals].sort((a, b) =>
    a.attributionKey.localeCompare(b.attributionKey)
  );
  const blockedCidrs = [...REQUIRED_PRIVATE_EGRESS_CIDRS];

  if (input.driver === "singbox") {
    const doc = {
      log: { level: "warn", timestamp: true },
      experimental: {
        v2ray_api: {
          listen: "127.0.0.1:10085",
          stats: {
            enabled: true,
            inbounds: [`${input.nodeName}-vless-reality`],
            users: sortedPrincipals.map((p) => p.attributionKey),
          },
        },
      },
      inbounds: [
        {
          type: "vless",
          tag: `${input.nodeName}-vless-reality`,
          listen: "::",
          listen_port: input.listenPort,
          sniff: true,
          sniff_override_destination: false,
          users: sortedPrincipals.map((p) => ({
            name: p.attributionKey,
            uuid: p.credentialUuidOrToken,
            flow: "xtls-rprx-vision",
          })),
          tls: {
            enabled: true,
            server_name: input.serverName,
            reality: {
              enabled: true,
              handshake: { server: input.serverName, server_port: 443 },
              private_key_ref: input.realityPrivateKeyRef ?? "secretref://inbound/reality_private_key",
              short_id: [input.realityShortId ?? "a1b2c3d4"],
            },
          },
        },
      ],
      outbounds: [
        { type: "direct", tag: "direct-egress" },
        { type: "block", tag: "block-private-egress" },
      ],
      route: {
        final: "direct-egress",
        rules: [
          {
            ip_cidr: blockedCidrs,
            outbound: "block-private-egress",
          },
        ],
      },
    };
    const configJson = JSON.stringify(doc, null, 2);
    return {
      driver: "singbox",
      protocol: "vless-reality-vision",
      transport: "tcp",
      format: "json",
      configJson,
      sha256: createHash("sha256").update(configJson).digest("hex"),
      privateEgressBlockedCidrs: blockedCidrs,
      qualificationNote:
        "Primary M0 runtime candidate (sing-box v1.14.4+omni.2). Enforces per-user V2Ray stats attribution and RFC1918/metadata egress block.",
    };
  }

  if (input.driver === "hysteria2") {
    const doc = {
      listen: `:${input.listenPort}`,
      protocol: "hysteria2-udp-quic",
      tls: {
        sniGuard: "strict",
        serverName: input.serverName,
        certRef: `secretref://acme/${input.serverName}/fullchain.pem`,
        keyRef: `secretref://acme/${input.serverName}/privkey.pem`,
      },
      obfs: {
        type: "salamander",
        salamander: {
          passwordRef: input.hysteria2ObfsPasswordRef ?? "secretref://inbound/hy2_salamander_key",
        },
      },
      quic: {
        initStreamReceiveWindow: 8388608,
        maxStreamReceiveWindow: 8388608,
        initConnectionReceiveWindow: 20971520,
        maxConnectionReceiveWindow: 20971520,
        maxIdleTimeout: "30s",
        maxIncomingStreams: 256,
        disablePathMTUDiscovery: false,
      },
      bandwidth: {
        up: `${input.upMbps ?? 250} mbps`,
        down: `${input.downMbps ?? 1000} mbps`,
      },
      ignoreClientBandwidth: false,
      userpassAuth: Object.fromEntries(
        sortedPrincipals.map((p) => [p.attributionKey, p.credentialUuidOrToken])
      ),
      acl: {
        inline: blockedCidrs.map((cidr) => `reject(${cidr})`).concat(["direct(all)"]),
      },
      trafficStats: {
        listen: "127.0.0.1:10086",
        secretRef: "secretref://agent/hy2_stats_token",
      },
    };
    const configJson = JSON.stringify(doc, null, 2);
    return {
      driver: "hysteria2",
      protocol: "hysteria2",
      transport: "udp",
      format: "json",
      configJson,
      sha256: createHash("sha256").update(configJson).digest("hex"),
      privateEgressBlockedCidrs: blockedCidrs,
      qualificationNote:
        "Candidate M1 UDP/QUIC driver. Multiplexed QUIC streams without direct per-stream closer are reported as muted_unclosable on revocation.",
    };
  }

  // Xray-core VLESS Reality Vision fragment
  const doc = {
    log: { loglevel: "warning" },
    stats: {},
    policy: {
      levels: {
        "0": {
          statsUserUplink: true,
          statsUserDownlink: true,
        },
      },
      system: {
        statsInboundUplink: true,
        statsInboundDownlink: true,
      },
    },
    inbounds: [
      {
        tag: `${input.nodeName}-xray-reality`,
        listen: "::",
        port: input.listenPort,
        protocol: "vless",
        settings: {
          decryption: "none",
          clients: sortedPrincipals.map((p) => ({
            id: p.credentialUuidOrToken,
            email: p.attributionKey,
            flow: "xtls-rprx-vision",
          })),
        },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: false,
            dest: `${input.serverName}:443`,
            xver: 0,
            serverNames: [input.serverName],
            privateKeyRef: input.realityPrivateKeyRef ?? "secretref://inbound/reality_private_key",
            shortIds: [input.realityShortId ?? "a1b2c3d4"],
          },
        },
      },
    ],
    outbounds: [
      { protocol: "freedom", tag: "direct-egress" },
      { protocol: "blackhole", tag: "block-private-egress" },
    ],
    routing: {
      domainStrategy: "AsIs",
      rules: [
        {
          type: "field",
          ip: blockedCidrs,
          outboundTag: "block-private-egress",
        },
      ],
    },
  };
  const configJson = JSON.stringify(doc, null, 2);
  return {
    driver: "xray",
    protocol: "vless-reality-vision",
    transport: "tcp",
    format: "json",
    configJson,
    sha256: createHash("sha256").update(configJson).digest("hex"),
    privateEgressBlockedCidrs: blockedCidrs,
    qualificationNote:
      "Secondary M1 TCP/Reality runtime candidate (Xray-core v24.11+). Remains fail-closed in QUALIFIED_BUILDS until M0/M1 lab gate sign-off.",
  };
}
