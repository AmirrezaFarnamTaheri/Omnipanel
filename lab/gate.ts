import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { validateContract } from "./contracts";

export const REQUIRED_CANDIDATES = ["singbox-reality-vision", "singbox-hysteria2", "standalone-hysteria2"];
export type Runtime = {
  id: string; runtime: string; protocol: string; version: string | null;
  artifactDigest: string | null; platform: string; status: string; requiredClaims: string[];
};
export type Evidence = {
  id: string; capabilityId: string; runtimeVersion: string; runtimeArtifactDigest: string;
  platform: string; claim: string; result: string; testedAt: string; operator: string;
  client: { application: string; version: string; os: string };
  summary: string; measurements: Record<string, number>;
  artifacts: { path: string; sha256: string }[];
};
export type Client = {
  application: string; version: string; os: string; capabilityIds: string[];
  evidenceIds: string[]; status: string;
};
export type Meter = {
  capabilityId: string; runtimeVersion: string; artifactDigest: string;
  enforceability: string; maxOvershootBytes: number | null; evidenceIds: string[];
};
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_EVIDENCE_AGE_MS = 90 * 24 * 60 * 60 * 1000;

function boundedRead(filename: string): Buffer {
  if (!fs.statSync(filename).isFile() || fs.statSync(filename).size > MAX_FILE_BYTES) throw new Error("invalid evidence file");
  return fs.readFileSync(filename);
}

/** Resolve artifacts under the evidence root, including through symlinks. Never fetch URLs. */
export function verifyArtifact(root: string, artifact: Evidence["artifacts"][number]): boolean {
  try {
    const realRoot = fs.realpathSync(root);
    const resolved = fs.realpathSync(path.resolve(realRoot, artifact.path));
    const relative = path.relative(realRoot, resolved);
    if (path.isAbsolute(artifact.path) || relative.startsWith("..") || path.isAbsolute(relative)) return false;
    return createHash("sha256").update(boundedRead(resolved)).digest("hex") === artifact.sha256;
  } catch { return false; }
}

export function evaluateLab(input: {
  runtimes: Runtime[]; clients: Client[]; meters: Meter[]; evidence: Evidence[];
  evidenceRoot: string; now?: number;
}) {
  const blockers: string[] = [];
  const now = input.now ?? Date.now();
  const seen = new Set<string>();
  const records: Evidence[] = [];
  for (const record of input.evidence) {
    const errors = validateContract("lab-evidence", record);
    if (errors.length) { blockers.push("Malformed evidence record"); continue; }
    if (seen.has(record.id)) blockers.push(`Duplicate evidence id: ${record.id}`);
    seen.add(record.id);
    const age = now - Date.parse(record.testedAt);
    if (age < 0 || age > MAX_EVIDENCE_AGE_MS) { blockers.push(`Stale or future evidence: ${record.id}`); continue; }
    if (!record.artifacts.every((artifact) => verifyArtifact(input.evidenceRoot, artifact))) {
      blockers.push(`Missing, out-of-bounds or digest-mismatched artifacts: ${record.id}`); continue;
    }
    if (record.result === "passed" && record.claim === "accounting") {
      const m = record.measurements;
      const upError = Math.abs(m.uploadMeasuredBytes - m.uploadExpectedBytes) / m.uploadExpectedBytes;
      const downError = Math.abs(m.downloadMeasuredBytes - m.downloadExpectedBytes) / m.downloadExpectedBytes;
      if (upError > m.maxRelativeError || downError > m.maxRelativeError) {
        blockers.push(`Accounting error exceeds declared bound: ${record.id}`); continue;
      }
    }
    records.push(record);
  }
  for (const required of REQUIRED_CANDIDATES) {
    if (!input.runtimes.some((runtime) => runtime.id === required)) blockers.push(`Required laboratory comparison missing: ${required}`);
  }
  for (const runtime of input.runtimes) {
    if (!runtime.version || !runtime.artifactDigest) {
      blockers.push(`${runtime.id}: exact build and digest not pinned`);
      continue;
    }
    for (const claim of runtime.requiredClaims) {
      const matching = records.filter((record) => record.capabilityId === runtime.id && record.claim === claim &&
        record.runtimeVersion === runtime.version && record.runtimeArtifactDigest === runtime.artifactDigest && record.platform === runtime.platform)
        .sort((a, b) => Date.parse(b.testedAt) - Date.parse(a.testedAt));
      const latest = matching[0];
      if (!latest || latest.result !== "passed") {
        blockers.push(`${runtime.id}/${claim}: no current passing evidence for the pinned build`);
        continue;
      }
      if (matching[1]?.testedAt === latest.testedAt) blockers.push(`${runtime.id}/${claim}: ambiguous simultaneous evidence`);
      if (["client_import", "connectivity_l3"].includes(claim) && !input.clients.some((client) =>
        client.status === "verified" && client.capabilityIds.includes(runtime.id) && client.evidenceIds.includes(latest.id) &&
        client.application === latest.client.application && client.version === latest.client.version && client.os === latest.client.os)) {
        blockers.push(`${runtime.id}/${claim}: exact client release not verified in registry`);
      }
      if (claim === "accounting" && !input.meters.some((meter) => meter.capabilityId === runtime.id &&
        meter.runtimeVersion === runtime.version && meter.artifactDigest === runtime.artifactDigest && meter.evidenceIds.includes(latest.id))) {
        blockers.push(`${runtime.id}: authoritative metering contract missing`);
      }
    }
  }
  // This gate tests metering and revocation, not a bounded byte-lease implementation.
  for (const meter of input.meters) {
    if (meter.enforceability === "hard") blockers.push(`${meter.capabilityId}: hard quota requires a separate verified lease/session enforcement gate`);
  }
  return { gate: "lab", status: blockers.length ? "blocked" : "passed", evaluatedAt: new Date(now).toISOString(), blockers };
}

export function runLab(root: string, evidenceRoot: string) {
  const load = (file: string) => JSON.parse(boundedRead(file).toString("utf8"));
  const runtimeRegistry = load(path.join(root, "capabilities/runtime.json"));
  const clientRegistry = load(path.join(root, "capabilities/clients.json"));
  const meterRegistry = load(path.join(root, "capabilities/metering.json"));
  for (const [schema, value] of [["runtime-registry", runtimeRegistry], ["client-registry", clientRegistry], ["metering-registry", meterRegistry]] as const) {
    if (validateContract(schema, value).length) throw new Error(`Invalid ${schema}`);
  }
  if (new Set(runtimeRegistry.runtimes.map((runtime: Runtime) => runtime.id)).size !== runtimeRegistry.runtimes.length) throw new Error("Duplicate runtime id");
  const evidence = fs.existsSync(evidenceRoot)
    ? fs.readdirSync(evidenceRoot).filter((file) => file.endsWith(".json")).sort().map((file) => load(path.join(evidenceRoot, file)))
    : [];
  return evaluateLab({ runtimes: runtimeRegistry.runtimes, clients: clientRegistry.clients, meters: meterRegistry.contracts, evidence, evidenceRoot });
}
