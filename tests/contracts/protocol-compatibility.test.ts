import test from "node:test";
import assert from "node:assert/strict";
import { validateInboundCompatibility } from "../../src/lib/protocol-compatibility";

const reality = (changes: Record<string, unknown> = {}) => ({
  runtime: "singbox", protocol: "vless-reality-vision", transport: "tcp",
  serverName: "reality.example.test",
  params: { realityPublicKey: "A".repeat(43), shortId: "aabb", flow: "xtls-rprx-vision", fingerprint: "chrome" },
  ...changes,
});
const hysteria2 = (changes: Record<string, unknown> = {}) => ({
  runtime: "singbox", protocol: "hysteria2", transport: "udp", serverName: "hy2.example.test", params: {}, ...changes,
});

test("accepts the Reality/Vision combinations for Sing-box and Xray", () => {
  for (const runtime of ["singbox", "xray"]) {
    assert.deepEqual(validateInboundCompatibility(reality({ runtime })), { supported: true, capabilityId: `${runtime}:vless-reality-vision` });
  }
});
test("accepts Hysteria2 over UDP for embedded and standalone runtimes", () => {
  for (const runtime of ["singbox", "hysteria2"]) {
    assert.deepEqual(validateInboundCompatibility(hysteria2({ runtime })), { supported: true, capabilityId: `${runtime}:hysteria2` });
  }
});
for (const [name, input] of [
  ["Reality over UDP", reality({ transport: "udp" })], ["Hysteria2 over TCP", hysteria2({ transport: "tcp" })],
  ["Xray Hysteria2", hysteria2({ runtime: "xray" })], ["unknown runtime", reality({ runtime: "shell" })],
  ["unknown protocol", reality({ protocol: "vmess" })], ["missing server name", reality({ serverName: "" })],
  ["whitespace in server name", reality({ serverName: "bad name.test" })],
  ["missing Reality public key", reality({ params: { shortId: "aabb" } })],
  ["malformed Reality public key", reality({ params: { realityPublicKey: "not-a-key", shortId: "aabb" } })],
  ["missing short ID", reality({ params: { realityPublicKey: "A".repeat(43) } })],
  ["odd-length short ID", reality({ params: { realityPublicKey: "A".repeat(43), shortId: "abc" } })],
  ["unsupported flow", reality({ params: { realityPublicKey: "A".repeat(43), shortId: "aabb", flow: "xtls-rprx-direct" } })],
  ["invalid fingerprint", reality({ params: { realityPublicKey: "A".repeat(43), shortId: "aabb", fingerprint: "bad fingerprint" } })],
] as const) {
  test(`rejects ${name}`, () => {
    const result = validateInboundCompatibility(input as never);
    assert.equal(result.supported, false);
    if (!result.supported) assert.ok(result.reason.length > 0);
  });
}
test("defaults omitted optional Reality flow and fingerprint to supported values", () => {
  assert.deepEqual(validateInboundCompatibility(reality({ params: { realityPublicKey: "A".repeat(43), shortId: "aabb" } })), { supported: true, capabilityId: "singbox:vless-reality-vision" });
});
