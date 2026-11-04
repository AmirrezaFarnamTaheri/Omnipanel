import "./setup-database";
import test from "node:test";
import assert from "node:assert/strict";
import { CompileError, compile, emitMihomo, emitSingbox, emitUris, type AccessPath, type IR } from "../../src/lib/subscription";

// Deterministic subscription emission contract, adopted as a regression from
// the 3X-UI host-ordering design (internal/sub/host_order.go at pinned
// revision 83ea59f; see docs/research/four-panel-integration-assessment.md).
// OmniPanel keeps ordering authority in the IR (buildIR orders by inbound id);
// emitters must be stable, preserve that order exactly and never introduce
// map-iteration or locale randomness. Per-format exclusions stay explicit.

const realityPath = (inboundId: number, tag: string): AccessPath => ({
  inboundId,
  tag,
  nodeName: "node",
  server: "203.0.113.10",
  port: 443,
  protocol: "vless-reality-vision",
  transport: "tcp",
  runtime: "singbox",
  credential: "0b6cdd6c-2f6a-4c8e-9d2a-7f4e1c0b9a55",
  sni: "www.example.test",
  tlsModel: "reality",
  reality: { publicKey: "A".repeat(43), shortId: "aabb", fingerprint: "chrome", flow: "xtls-rprx-vision" },
  route: "direct",
  enforceability: "metered",
  revision: 7,
  health: "healthy",
});

const hysteriaPath = (inboundId: number, tag: string): AccessPath => ({
  ...realityPath(inboundId, tag),
  protocol: "hysteria2",
  transport: "udp",
  credential: "synthetic-hy2-credential",
  sni: "hy2.example.test",
  tlsModel: "tls-self-managed",
  reality: undefined,
});

const mixedIR = (): IR => ({
  user: { id: 1, name: "determinism-user", status: "active" },
  paths: [realityPath(1, "node-reality-a"), hysteriaPath(2, "node-hysteria-b"), realityPath(3, "node-reality-c")],
  excluded: [],
  diagnostics: [],
  quotaBytes: 1024,
  expiresAt: null,
});

test("every emitter is byte-stable across repeated compilation", () => {
  const ir = mixedIR();
  for (const format of ["singbox", "mihomo", "uri"] as const) {
    const first = compile(ir, format);
    for (let i = 0; i < 5; i++) {
      const again = compile(ir, format);
      assert.equal(again.body, first.body, `${format} output drifted between identical compilations`);
      assert.equal(again.contentType, first.contentType);
    }
  }
  const xrayIR: IR = { ...ir, paths: ir.paths.filter((p) => p.protocol === "vless-reality-vision") };
  const xrayFirst = compile(xrayIR, "xray");
  assert.equal(compile(xrayIR, "xray").body, xrayFirst.body);
});

test("emitters preserve IR order exactly; ordering authority stays in the IR", () => {
  const ir = mixedIR();
  const tags = ir.paths.map((p) => p.tag);

  const singbox = JSON.parse(emitSingbox(ir)) as { outbounds: { tag: string }[] };
  const emittedSingbox = singbox.outbounds.filter((o) => tags.includes(o.tag)).map((o) => o.tag);
  assert.deepEqual(emittedSingbox, tags);
  const selector = singbox.outbounds.find((o) => o.tag === "proxy") as unknown as { outbounds: string[] };
  assert.deepEqual(selector.outbounds, ["auto", ...tags]);

  const mihomo = emitMihomo(ir);
  const mihomoOrder = tags.map((tag) => mihomo.indexOf(`name: ${JSON.stringify(tag)}`));
  assert.ok(mihomoOrder.every((index) => index >= 0));
  assert.deepEqual([...mihomoOrder].sort((a, b) => a - b), mihomoOrder);

  const uris = Buffer.from(emitUris(ir), "base64").toString("utf8").split("\n");
  assert.deepEqual(uris.map((uri) => decodeURIComponent(uri.split("#")[1])), tags);

  // The emitters must not silently re-sort: a permuted IR is a different
  // input and yields the permuted order. buildIR owns the canonical order.
  const permuted: IR = { ...ir, paths: [ir.paths[2], ir.paths[0], ir.paths[1]] };
  const permutedTags = permuted.paths.map((p) => p.tag);
  const permutedSingbox = JSON.parse(emitSingbox(permuted)) as { outbounds: { tag: string }[] };
  assert.deepEqual(
    permutedSingbox.outbounds.filter((o) => permutedTags.includes(o.tag)).map((o) => o.tag),
    permutedTags,
  );
});

test("per-format exclusion diagnostics are explicit, ordered and stable", () => {
  const ir = mixedIR();
  const expected = ir.paths
    .filter((p) => p.protocol === "hysteria2")
    .map((p) => `${p.tag}: Xray JSON (unqualified emitter) does not support hysteria2`);
  for (let i = 0; i < 3; i++) {
    assert.throws(
      () => compile(ir, "xray"),
      (error: unknown) => {
        assert.ok(error instanceof CompileError);
        assert.deepEqual(error.diagnostics, expected);
        return true;
      },
    );
  }
});

test("compilation refuses an IR carrying diagnostics instead of emitting it", () => {
  const ir: IR = { ...mixedIR(), diagnostics: ["refused upstream"] };
  assert.throws(() => compile(ir, "singbox"), (error: unknown) => {
    assert.ok(error instanceof CompileError);
    assert.deepEqual(error.diagnostics, ["refused upstream"]);
    return true;
  });
});

test("empty and single-path subscriptions remain deterministic and well-formed", () => {
  const empty: IR = { ...mixedIR(), paths: [] };
  for (const emit of [emitSingbox, emitMihomo, emitUris]) {
    assert.equal(emit(empty), emit(empty));
  }
  const single: IR = { ...mixedIR(), paths: [realityPath(9, "solo")] };
  const parsed = JSON.parse(emitSingbox(single)) as { outbounds: { tag: string }[] };
  assert.ok(parsed.outbounds.some((o) => o.tag === "solo"));
  assert.equal(Buffer.from(emitUris(single), "base64").toString("utf8").includes("#solo"), true);
});
