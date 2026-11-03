import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { listenersConflict, planIngress, type Listener } from "../../src/lib/ingress";
import { isAdmissible, isHardQuotaCapable } from "../../src/lib/capability-policy";
import { validateContract, validateDesiredState } from "../../lab/contracts";
import { evaluateLab, runLab, verifyArtifact, type Evidence, type Runtime } from "../../lab/gate";

const root = path.resolve(__dirname, "../..");
const read = (file: string) => JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
const desired = () => read("testdata/contracts/desired-state.json");
const listener = (changes: Partial<Listener> = {}): Listener => ({
  nodeId: "node-a", owner: "reality", address: "0.0.0.0", port: 443, transport: "tcp", ipv6Only: false, ...changes,
});

for (const [name, first, second, expected] of [
  ["exact binding", {}, {}, true],
  ["wildcard versus IPv4", {}, { address: "203.0.113.10" }, true],
  ["different IPv4", { address: "203.0.113.10" }, { address: "203.0.113.11" }, false],
  ["dual-stack wildcard", { address: "::" }, { address: "203.0.113.10" }, true],
  ["v6-only wildcard", { address: "::", ipv6Only: true }, {}, false],
  ["v6 wildcard versus specific", { address: "::", ipv6Only: true }, { address: "2001:db8::1", ipv6Only: true }, true],
  ["IPv6 spelling normalization", { address: "2001:db8::1" }, { address: "2001:0db8:0:0:0:0:0:1" }, true],
  ["IPv4-mapped IPv6", { address: "::ffff:cb00:710a" }, { address: "203.0.113.10" }, true],
  ["TCP and UDP independent", {}, { transport: "udp" }, false],
  ["separate nodes", {}, { nodeId: "node-b" }, false],
  ["separate ports", {}, { port: 8443 }, false],
] as [string, Partial<Listener>, Partial<Listener>, boolean][]) {
  test(`ingress: ${name} (symmetric)`, () => {
    assert.equal(listenersConflict(listener(first), listener(second)), expected);
    assert.equal(listenersConflict(listener(second), listener(first)), expected);
  });
}
for (const invalid of [{ port: 0 }, { port: 65536 }, { port: 3.5 }, { address: "localhost" }, { address: "fe80::1%eth0" }, { address: "::ffff:127.0.0.1", ipv6Only: true }, { ipv6Only: true }]) {
  test(`ingress rejects ${JSON.stringify(invalid)}`, () => assert.throws(() => planIngress([listener(invalid)])));
}
test("same named owner cannot bypass effective socket conflicts", () => {
  assert.equal(planIngress([listener(), listener()]).valid, false);
});

test("historical notes and ungated flag cannot qualify a runtime", () => {
  const cap = { key: "singbox:vless-reality-vision", gated: false, hardQuotaCandidate: true };
  const ev = new Map(["admission", "metering", "revocation", "hardQuota"].map((claim) => [`${cap.key}|${claim}`, "verified" as const]));
  assert.equal(isAdmissible(cap, ev), false);
  assert.equal(isHardQuotaCapable(cap, ev), false);
});
test("BPB is neither a managed meter nor a hard quota candidate", () => {
  const source = fs.readFileSync(path.join(root, "src/lib/capabilities.ts"), "utf8");
  const bpb = source.slice(source.indexOf('key: "bpb:http"'), source.indexOf("export const CLIENT_REGISTRY"));
  assert.match(bpb, /hardQuotaCandidate: false/);
  assert.doesNotMatch(bpb, /Bandwidth Policy Bridge/);
});
test("unsigned desired-state fixture passes only contract preflight", () => assert.deepEqual(validateDesiredState(desired()), []));
for (const [name, mutate] of [
  ["unknown operation", (v) => { v.manifest.exec = "arbitrary command"; }],
  ["unknown schema", (v) => { v.manifest.schemaVersion = "3.0"; }],
  ["unsafe sequence", (v) => { v.manifest.structuralSequence = Number.MAX_SAFE_INTEGER + 1; }],
  ["raw path", (v) => { v.manifest.components[0].configurationRef = "/etc/passwd"; }],
  ["missing egress policy", (v) => { delete v.manifest.baseEgressPolicy; }],
  ["inverted validity", (v) => { v.manifest.expiresAt = "2026-11-02T00:00:00Z"; }],
  ["dependency cycle", (v) => { v.manifest.components[0].dependsOn = ["reality"]; }],
  ["unknown dependency", (v) => { v.manifest.components[0].dependsOn = ["missing"]; }],
  ["duplicate component", (v) => { v.manifest.components.push(structuredClone(v.manifest.components[0])); }],
  ["dual-stack overlap", (v) => { v.manifest.components[0].listeners.push({ address: "::", port: 443, transport: "tcp", ipv6Only: false }); }],
] as [string, (value: ReturnType<typeof desired>) => void][]) {
  test(`manifest rejects ${name}`, () => { const value = desired(); mutate(value); assert.ok(validateDesiredState(value).length); });
}
test("canonical IR disallows secret values, TLS weakening and incompatible transport", () => {
  const ir = {
    schemaVersion: "2.0", id: randomUUID(), nodeId: randomUUID(), principalId: randomUUID(),
    runtime: "singbox", runtimeVersion: "0.0.0", protocol: "vless-reality-vision", address: "example.invalid", port: 443,
    transport: "tcp", credentialRef: "user-secret", tls: { model: "reality", serverName: "example.invalid",
      publicKey: "A".repeat(43), shortId: "aabb", fingerprint: "chrome", flow: "xtls-rprx-vision", verifyCertificate: true },
    route: "direct", health: "unknown", enforceability: "metered", requiredClientCapabilities: ["reality"],
    provenance: { source: "managed", revisionDigest: "a".repeat(64), controlPlaneEpoch: randomUUID(), structuralSequence: 1 },
  };
  assert.deepEqual(validateContract("canonical-endpoint", ir), []);
  assert.ok(validateContract("canonical-endpoint", { ...ir, credential: "raw-secret" }).length);
  assert.ok(validateContract("canonical-endpoint", { ...ir, tls: { ...ir.tls, verifyCertificate: false } }).length);
  assert.ok(validateContract("canonical-endpoint", { ...ir, transport: "udp" }).length);
  assert.ok(validateContract("canonical-endpoint", { ...ir, route: "cdn" }).length);
});

function measurements(claim: string): Record<string, number> {
  const values: Record<string, Record<string, number>> = {
    accounting: { uploadExpectedBytes: 1000, downloadExpectedBytes: 1000, uploadMeasuredBytes: 1000, downloadMeasuredBytes: 1000, maxRelativeError: 0.01 },
    credential_revocation: { newAuthBlockedAfterMs: 100, existingSessionTerminated: 0, existingSessionObservationMs: 60000 },
    connectivity_l3: { successfulCanaryRequests: 1, failedCanaryRequests: 0 },
    client_import: { importSucceeded: 1 }, outbound_reconciliation: { outboundPullVerified: 1 },
    last_good_recovery: { nativeValidatorPassed: 1, rejectedConfigPreservedService: 1, lastGoodRecovered: 1 },
    version_rejection: { rejectedInvalidVersions: 1, rejectedUnknownRequiredFields: 1 },
    impairment_diagnosis: { packetLossTested: 1, udpFilteringTested: 1, delayTested: 1 },
  };
  return values[claim];
}

function labFixture() {
  const evidenceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "omni-lab-"));
  fs.writeFileSync(path.join(evidenceRoot, "transcript.txt"), "Synthetic unit-test data. NOT real networking evidence.\n");
  const digest = createHash("sha256").update(fs.readFileSync(path.join(evidenceRoot, "transcript.txt"))).digest("hex");
  const runtimes: Runtime[] = read("capabilities/runtime.json").runtimes.map((runtime: Runtime) => ({ ...runtime, version: "0.0.0", artifactDigest: "a".repeat(64) }));
  const evidence: Evidence[] = runtimes.flatMap((runtime) => runtime.requiredClaims.map((claim) => ({
    id: randomUUID(), capabilityId: runtime.id, runtimeVersion: "0.0.0", runtimeArtifactDigest: "a".repeat(64), platform: "linux/amd64",
    claim, result: "passed", testedAt: "2026-11-03T00:00:00Z", operator: "unit-test-only",
    client: { application: "synthetic", version: "0.0.0", os: "test" }, summary: "Synthetic unit test; no network guarantee.", measurements: measurements(claim),
    artifacts: [{ path: "transcript.txt", sha256: digest }],
  })));
  const clients = [{ id: "synthetic", embeddedCore: "synthetic 0.0.0", format: "singbox", supportedFields: [], failoverBehavior: "not evaluated", dnsRoutingBehavior: "synthetic", importRefreshBehavior: "synthetic", testedAt: "2026-11-03T00:00:00Z", application: "synthetic", version: "0.0.0", os: "test", capabilityIds: runtimes.map((r) => r.id), evidenceIds: evidence.map((e) => e.id), status: "verified" }];
  const meters = runtimes.map((runtime) => ({ measurementPoint: "synthetic inbound", attributionKey: "synthetic-user", uploadSemantics: "inbound payload", downloadSemantics: "outbound payload", overhead: "excluded", counterType: "cumulative", counterLifetime: "process", generationIdentity: "synthetic-uuid", apiAuthentication: "synthetic local auth", collectionIntervalSeconds: 5, knownGaps: [], newSessionRevocation: "synthetic block", existingSessionRevocation: "synthetic persists", capabilityId: runtime.id, runtimeVersion: "0.0.0", artifactDigest: "a".repeat(64), enforceability: "metered", maxOvershootBytes: null,
    evidenceIds: evidence.filter((e) => e.capabilityId === runtime.id && e.claim === "accounting").map((e) => e.id) }));
  return { runtimes, evidence, clients, meters, evidenceRoot, now: Date.parse("2026-11-03T01:00:00Z") };
}
test("real repository lab gate is blocked, never green from fixtures", () => {
  const report = runLab(root, path.join(root, ".data/nonexistent-unit-test-evidence"));
  assert.equal(report.status, "blocked"); assert.ok(report.blockers.some((item) => item.includes("not pinned")));
});
test("gate accepts complete synthetic evidence only inside isolated unit test", (t) => {
  const fixture = labFixture(); t.after(() => fs.rmSync(fixture.evidenceRoot, { recursive: true }));
  assert.equal(evaluateLab(fixture).status, "passed");
});
for (const [name, mutate] of [
  ["missing claim", (v) => { v.evidence.shift(); }],
  ["missing accounting measurements", (v) => { v.evidence.find((e) => e.claim === "accounting")!.measurements = {}; }],
  ["accounting outside error bound", (v) => { v.evidence.find((e) => e.claim === "accounting")!.measurements.uploadMeasuredBytes = 1500; }],
  ["ambiguous simultaneous results", (v) => { v.evidence.push({ ...v.evidence[0], id: randomUUID() }); }],
  ["wrong runtime version", (v) => { v.evidence[0].runtimeVersion = "9.9.9"; }],
  ["wrong binary digest", (v) => { v.evidence[0].runtimeArtifactDigest = "b".repeat(64); }],
  ["wrong platform", (v) => { v.evidence[0].platform = "linux/arm64"; }],
  ["failed claim", (v) => { v.evidence[0].result = "failed"; }],
  ["stale evidence", (v) => { v.evidence[0].testedAt = "2020-01-01T00:00:00Z"; }],
  ["future evidence", (v) => { v.evidence[0].testedAt = "2030-01-01T00:00:00Z"; }],
  ["unknown field", (v) => { Object.assign(v.evidence[0], { arbitraryField: true }); }],
  ["duplicate evidence id", (v) => { v.evidence.push(structuredClone(v.evidence[0])); }],
  ["artifact tampering", (v) => { fs.writeFileSync(path.join(v.evidenceRoot, "transcript.txt"), "changed"); }],
  ["client release mismatch", (v) => { v.clients[0].version = "9.9.9"; }],
  ["missing metering contract", (v) => { v.meters = []; }],
  ["hard quota without enforcement gate", (v) => { v.meters[0].enforceability = "hard"; }],
  ["missing Hysteria comparison", (v) => { v.runtimes.pop(); }],
  ["new failure supersedes success", (v) => { v.evidence.push({ ...v.evidence[0], id: randomUUID(), result: "failed", testedAt: "2026-11-03T00:30:00Z" }); }],
] as [string, (value: ReturnType<typeof labFixture>) => void][]) {
  test(`gate blocks ${name}`, (t) => {
    const fixture = labFixture(); t.after(() => fs.rmSync(fixture.evidenceRoot, { recursive: true }));
    mutate(fixture); assert.equal(evaluateLab(fixture).status, "blocked");
  });
}
test("artifact traversal and symlink escape rejected", (t) => {
  const fixture = labFixture(); t.after(() => fs.rmSync(fixture.evidenceRoot, { recursive: true }));
  const artifact = fixture.evidence[0].artifacts[0];
  assert.equal(verifyArtifact(fixture.evidenceRoot, { ...artifact, path: "../outside.txt" }), false);
  fs.symlinkSync(path.join(root, "package.json"), path.join(fixture.evidenceRoot, "escape"));
  assert.equal(verifyArtifact(fixture.evidenceRoot, { ...artifact, path: "escape" }), false);
});

test("runLab loads complete schema-valid synthetic registries and evidence", (t) => {
  const fixture = labFixture(); t.after(() => fs.rmSync(fixture.evidenceRoot, { recursive: true }));
  for (const record of fixture.evidence) record.testedAt = new Date(Date.now() - 1000).toISOString();
  const fixtureRoot = path.join(fixture.evidenceRoot, "repository");
  fs.mkdirSync(path.join(fixtureRoot, "capabilities"), { recursive: true });
  for (const [name, key, value] of [
    ["runtime", "runtimes", fixture.runtimes], ["clients", "clients", fixture.clients], ["metering", "contracts", fixture.meters],
  ] as const) fs.writeFileSync(path.join(fixtureRoot, "capabilities", `${name}.json`), JSON.stringify({ schemaVersion: "2.0", [key]: value }));
  for (const record of fixture.evidence) fs.writeFileSync(path.join(fixture.evidenceRoot, `${record.id}.json`), JSON.stringify(record));
  assert.equal(runLab(fixtureRoot, fixture.evidenceRoot).status, "passed");
  const registryFile = path.join(fixtureRoot, "capabilities/runtime.json");
  const registry = JSON.parse(fs.readFileSync(registryFile, "utf8"));
  registry.runtimes[0].requiredClaims = [];
  fs.writeFileSync(registryFile, JSON.stringify(registry));
  assert.throws(() => runLab(fixtureRoot, fixture.evidenceRoot), /Invalid runtime-registry/);
});
