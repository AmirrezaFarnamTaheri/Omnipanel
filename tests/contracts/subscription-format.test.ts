import "./setup-database";
import test from "node:test";
import assert from "node:assert/strict";
import type { IR } from "../../src/lib/subscription";

import { CompileError, compile } from "../../src/lib/subscription";

const hysteriaIR: IR = {
  user: { id: 1, name: "test-user", status: "active" },
  paths: [{
    inboundId: 1,
    tag: "node-hysteria",
    nodeName: "node",
    server: "203.0.113.10",
    port: 443,
    protocol: "hysteria2",
    transport: "udp",
    runtime: "singbox",
    credential: "synthetic-credential",
    sni: "hy2.example.test",
    tlsModel: "tls-self-managed",
    route: "direct",
    enforceability: "metered",
    revision: 1,
    health: "healthy",
  }],
  excluded: [],
  diagnostics: [],
  quotaBytes: null,
  expiresAt: null,
};

test("Xray format refuses Hysteria2 rather than emitting an invalid config", () => {
  assert.throws(
    () => compile(hysteriaIR, "xray"),
    (error: unknown) => {
      assert.ok(error instanceof CompileError);
      assert.match(error.diagnostics.join("\n"), /does not support hysteria2/);
      return true;
    },
  );
});

test("Sing-box, Mihomo and URI formats retain supported Hysteria2 paths", () => {
  for (const format of ["singbox", "mihomo", "uri"] as const) {
    const result = compile(hysteriaIR, format);
    assert.ok(result.body.length > 0);
  }
});

test("Xray format accepts the canonical VLESS Reality protocol identity", () => {
  const realityIR: IR = {
    ...hysteriaIR,
    paths: [{
      ...hysteriaIR.paths[0],
      tag: "node-reality",
      protocol: "vless-reality-vision",
      transport: "tcp",
      runtime: "xray",
      tlsModel: "reality",
      reality: {
        publicKey: "A".repeat(43),
        shortId: "aabb",
        fingerprint: "chrome",
        flow: "xtls-rprx-vision",
      },
    }],
  };
  const result = compile(realityIR, "xray");
  assert.match(result.body, /"protocol": "vless"/);
});
