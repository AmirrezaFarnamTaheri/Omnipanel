/**
 * Narrow runtime/protocol preflight for the currently designed M1/M2 subset.
 *
 * This checks structural compatibility only. Exact binary qualification,
 * native configuration validation, client support and connectivity remain
 * separate evidence gates.
 */
export type InboundCompatibilityInput = {
  runtime: string;
  protocol: string;
  transport: string;
  serverName: string;
  params?: Record<string, string>;
};

export type InboundCompatibilityResult =
  | { supported: true; capabilityId: string }
  | { supported: false; reason: string };

const EXPECTED_TRANSPORT: Readonly<Record<string, "tcp" | "udp">> = {
  "singbox:vless-reality-vision": "tcp",
  "xray:vless-reality-vision": "tcp",
  "singbox:hysteria2": "udp",
  "hysteria2:hysteria2": "udp",
};

const REALITY_FLOW = "xtls-rprx-vision";
const DEFAULT_FINGERPRINT = "chrome";
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SHORT_ID_PATTERN = /^(?:[a-f0-9]{2}){1,8}$/;
const FINGERPRINT_PATTERN = /^[a-z0-9_-]{1,32}$/;
const SERVER_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/i;

function unsupported(reason: string): InboundCompatibilityResult {
  return { supported: false, reason };
}

function validServerName(serverName: string): boolean {
  return serverName === serverName.trim() &&
    serverName.length <= 253 &&
    SERVER_NAME_PATTERN.test(serverName) &&
    !serverName.includes("..");
}

/**
 * Rejects protocol/transport/security combinations outside the deliberately
 * narrow runtime contract before a subscription artifact can be emitted.
 */
export function validateInboundCompatibility(
  input: InboundCompatibilityInput,
): InboundCompatibilityResult {
  const capabilityId = `${input.runtime}:${input.protocol}`;
  const expectedTransport = EXPECTED_TRANSPORT[capabilityId];

  if (!expectedTransport) {
    return unsupported(`Unsupported runtime/protocol combination: ${capabilityId}`);
  }
  if (input.transport !== expectedTransport) {
    return unsupported(`${capabilityId} requires ${expectedTransport.toUpperCase()} transport`);
  }
  if (!validServerName(input.serverName)) {
    return unsupported("A valid DNS server name is required for TLS identity");
  }

  if (input.protocol === "vless-reality-vision") {
    const params = input.params ?? {};
    if (!PUBLIC_KEY_PATTERN.test(params.realityPublicKey ?? "")) {
      return unsupported("Reality public key must be an unpadded 32-byte base64url value");
    }
    if (!SHORT_ID_PATTERN.test(params.shortId ?? "")) {
      return unsupported("Reality short ID must contain 1 to 8 bytes of lowercase hexadecimal");
    }
    const flow = params.flow || REALITY_FLOW;
    if (flow !== REALITY_FLOW) {
      return unsupported(`Reality/Vision requires the ${REALITY_FLOW} flow`);
    }
    const fingerprint = params.fingerprint || DEFAULT_FINGERPRINT;
    if (!FINGERPRINT_PATTERN.test(fingerprint)) {
      return unsupported("TLS fingerprint must be a non-empty identifier");
    }
  }

  return { supported: true, capabilityId };
}
