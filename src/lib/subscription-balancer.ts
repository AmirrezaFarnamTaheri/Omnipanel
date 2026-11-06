import { createHash } from "node:crypto";

export type BalancerStrategy = "url-test" | "fallback" | "selector";

export interface BalancerEndpointCandidate {
  tag: string;
  protocol: "vless-reality-vision" | "hysteria2";
  weight?: number;
}

export interface ClientBalancerConfigInput {
  groupTag: string;
  strategy: BalancerStrategy;
  probeUrl: string;
  intervalSeconds: number;
  toleranceMs: number;
  endpoints: BalancerEndpointCandidate[];
}

export interface CompiledClientBalancerDocument {
  groupTag: string;
  strategy: BalancerStrategy;
  probeUrl: string;
  intervalSeconds: number;
  toleranceMs: number;
  memberTags: string[];
  guaranteesServerSideFailover: false;
  guaranteesExistingSessionMigration: false;
  singboxOutboundsFragment: Record<string, unknown>[];
  mihomoProxyGroupFragment: Record<string, unknown>;
  digest: string;
}

/**
 * Generates deterministic client-side balancer & observatory configuration documents
 * for Sing-box and Mihomo (`docs/adr/0002-source-project-reuse.md` 3X-UI balancer lesson).
 * Explicitly records `guaranteesServerSideFailover: false` and `guaranteesExistingSessionMigration: false`.
 */
export function compileClientBalancerDocument(
  input: ClientBalancerConfigInput
): CompiledClientBalancerDocument {
  if (!input.groupTag || !/^[a-zA-Z0-9._-]{1,64}$/.test(input.groupTag)) {
    throw new Error("invalid balancer groupTag");
  }
  if (!["url-test", "fallback", "selector"].includes(input.strategy)) {
    throw new Error(`unsupported balancer strategy: ${String(input.strategy)}`);
  }
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(input.probeUrl);
  } catch {
    throw new Error("invalid observatory probeUrl");
  }
  if (parsedUrl.protocol !== "https:" || !parsedUrl.hostname) {
    throw new Error("observatory probeUrl must use https://");
  }
  if (!Number.isSafeInteger(input.intervalSeconds) || input.intervalSeconds < 30 || input.intervalSeconds > 3600) {
    throw new Error("intervalSeconds must be between 30 and 3600");
  }
  if (!Number.isSafeInteger(input.toleranceMs) || input.toleranceMs < 10 || input.toleranceMs > 2000) {
    throw new Error("toleranceMs must be between 10 and 2000");
  }
  if (!input.endpoints || input.endpoints.length === 0) {
    throw new Error("balancer requires at least one admitted endpoint candidate");
  }

  // Preserve deterministic lexicographic order when weights are equal
  const sorted = [...input.endpoints].sort((a, b) => {
    const wa = a.weight ?? 100;
    const wb = b.weight ?? 100;
    if (wa !== wb) return wb - wa;
    return a.tag.localeCompare(b.tag);
  });
  const memberTags = sorted.map((e) => e.tag);

  const singboxOutboundsFragment: Record<string, unknown>[] =
    input.strategy === "selector"
      ? [
          {
            type: "selector",
            tag: input.groupTag,
            outbounds: memberTags,
            default: memberTags[0],
            interrupt_exist_connections: false,
          },
        ]
      : [
          {
            type: "urltest",
            tag: input.groupTag,
            outbounds: memberTags,
            url: parsedUrl.toString(),
            interval: `${input.intervalSeconds}s`,
            tolerance: input.toleranceMs,
            interrupt_exist_connections: false,
          },
        ];

  const mihomoProxyGroupFragment: Record<string, unknown> =
    input.strategy === "selector"
      ? {
          name: input.groupTag,
          type: "select",
          proxies: memberTags,
        }
      : {
          name: input.groupTag,
          type: input.strategy,
          proxies: memberTags,
          url: parsedUrl.toString(),
          interval: input.intervalSeconds,
          tolerance: input.toleranceMs,
        };

  const digest = createHash("sha256")
    .update(JSON.stringify({ singboxOutboundsFragment, mihomoProxyGroupFragment }))
    .digest("hex");

  return {
    groupTag: input.groupTag,
    strategy: input.strategy,
    probeUrl: parsedUrl.toString(),
    intervalSeconds: input.intervalSeconds,
    toleranceMs: input.toleranceMs,
    memberTags,
    guaranteesServerSideFailover: false,
    guaranteesExistingSessionMigration: false,
    singboxOutboundsFragment,
    mihomoProxyGroupFragment,
    digest,
  };
}
