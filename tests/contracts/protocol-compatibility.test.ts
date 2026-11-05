import "./setup-database";
import test from "node:test";
import assert from "node:assert/strict";
import { CLIENT_REGISTRY, clientAdmissionReason } from "../../src/lib/capabilities";
import { validateInboundCompatibility, type InboundCompatibilityInput } from "../../src/lib/protocol-compatibility";

const reality = (changes: Partial<InboundCompatibilityInput> = {}): InboundCompatibilityInput => ({
  runtime: "singbox",
  protocol: "vless-reality-vision",
  transport: "tcp",
  serverName: "reality.example.test",
  params: {
    realityPublicKey: "A".repeat(43),
    shortId: "aabb",
    flow: "xtls-rprx-vision",
    fingerprint: "chrome",
  },
  ...changes,
});

const hysteria2 = (changes: Partial<InboundCompatibilityInput> = {}): InboundCompatibilityInput => ({
  runtime: "singbox",
  protocol: "hysteria2",
  transport: "udp",
  serverName: "hy2.example.test",
  params: {},
  ...changes,
});

test("accepts the Reality/Vision combinations for Sing-box and Xray", () => {
  for (const runtime of ["singbox", "xray"]) {
    assert.deepEqual(validateInboundCompatibility(reality({ runtime })), {
      supported: true,
      capabilityId: `${runtime}:vless-reality-vision`,
    });
  }
});

test("accepts Hysteria2 over UDP for embedded and standalone runtimes", () => {
  for (const runtime of ["singbox", "hysteria2"]) {
    assert.deepEqual(validateInboundCompatibility(hysteria2({ runtime })), {
      supported: true,
      capabilityId: `${runtime}:hysteria2`,
    });
  }
});

const invalidCases: Array<[string, InboundCompatibilityInput]> = [
  ["Reality over UDP", reality({ transport: "udp" })],
  ["Hysteria2 over TCP", hysteria2({ transport: "tcp" })],
  ["Xray Hysteria2", hysteria2({ runtime: "xray" })],
  ["unknown runtime", reality({ runtime: "shell" })],
  ["unknown protocol", reality({ protocol: "vmess" })],
  ["missing server name", reality({ serverName: "" })],
  ["whitespace in server name", reality({ serverName: "bad name.test" })],
  ["missing Reality public key", reality({ params: { shortId: "aabb" } })],
  ["malformed Reality public key", reality({ params: { realityPublicKey: "not-a-key", shortId: "aabb" } })],
  ["missing short ID", reality({ params: { realityPublicKey: "A".repeat(43) } })],
  ["odd-length short ID", reality({ params: { realityPublicKey: "A".repeat(43), shortId: "abc" } })],
  ["unsupported flow", reality({ params: { realityPublicKey: "A".repeat(43), shortId: "aabb", flow: "xtls-rprx-direct" } })],
  ["invalid fingerprint", reality({ params: { realityPublicKey: "A".repeat(43), shortId: "aabb", fingerprint: "bad fingerprint" } })],
];

for (const [name, input] of invalidCases) {
  test(`rejects ${name}`, () => {
    const result = validateInboundCompatibility(input);
    assert.equal(result.supported, false);
    if (!result.supported) assert.ok(result.reason.length > 0);
  });
}

test("defaults omitted optional Reality flow and fingerprint to supported values", () => {
  assert.deepEqual(
    validateInboundCompatibility(reality({ params: { realityPublicKey: "A".repeat(43), shortId: "aabb" } })),
    { supported: true, capabilityId: "singbox:vless-reality-vision" },
  );
});

test("client format declarations use canonical protocol IDs", () => {
  const xray = CLIENT_REGISTRY.find((client) => client.format === "xray");
  assert.deepEqual(xray?.protocols, ["vless-reality-vision"]);
  assert.deepEqual(
    CLIENT_REGISTRY.find((client) => client.format === "uri")?.protocols,
    ["vless-reality-vision", "hysteria2"],
  );
});

test("client formats remain excluded until exact-release compatibility evidence is verified", () => {
  for (const client of CLIENT_REGISTRY) {
    const protocol = client.protocols[0];
    assert.match(clientAdmissionReason(client, protocol) ?? "", /no verified exact-release compatibility evidence/);
  }
});

test("client protocol exclusions explain unsupported formats before evidence status", () => {
  const xray = CLIENT_REGISTRY.find((client) => client.format === "xray");
  assert.match(clientAdmissionReason(xray ?? null, "hysteria2") ?? "", /does not support hysteria2/);
  assert.equal(clientAdmissionReason(null, "hysteria2"), null);
});
