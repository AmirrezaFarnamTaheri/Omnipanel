/**
 * Validated, read-only node resource snapshots (1Panel-informed observability contract).
 * Host metrics are strictly separated from L0–L3 proxy listener health, traffic accounting, and quota enforcement.
 */

export type FilesystemUsage = {
  id: string;
  totalBytes: number;
  usedBytes: number;
};

export type NetworkInterfaceCounters = {
  interface: string;
  receivedBytes: number;
  sentBytes: number;
};

export type ResourceSnapshot = {
  nodeId: string;
  generation: number;
  sampledAt: Date;
  cpuPercent: number;
  memoryTotalBytes: number;
  memoryUsedBytes: number;
  filesystems: FilesystemUsage[];
  network: NetworkInterfaceCounters[];
};

export type ResourceFreshness = "fresh" | "stale" | "unknown";

export class InvalidSnapshotError extends Error {
  constructor(message = "invalid resource snapshot") {
    super(message);
    this.name = "InvalidSnapshotError";
  }
}

const isNonNegSafeInt = (n: unknown): n is number =>
  typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

export function validateResourceSnapshot(s: ResourceSnapshot): void {
  if (
    !s ||
    typeof s.nodeId !== "string" ||
    s.nodeId.trim() === "" ||
    s.nodeId.length > 128 ||
    !isNonNegSafeInt(s.generation) ||
    s.generation === 0 ||
    !(s.sampledAt instanceof Date) ||
    Number.isNaN(s.sampledAt.getTime()) ||
    typeof s.cpuPercent !== "number" ||
    !Number.isFinite(s.cpuPercent) ||
    s.cpuPercent < 0 ||
    s.cpuPercent > 100 ||
    !isNonNegSafeInt(s.memoryTotalBytes) ||
    s.memoryTotalBytes === 0 ||
    !isNonNegSafeInt(s.memoryUsedBytes) ||
    s.memoryUsedBytes > s.memoryTotalBytes ||
    !Array.isArray(s.filesystems) ||
    s.filesystems.length > 256 ||
    !Array.isArray(s.network) ||
    s.network.length > 256
  ) {
    throw new InvalidSnapshotError();
  }

  const seenFs = new Set<string>();
  for (const fs of s.filesystems) {
    if (
      !fs ||
      typeof fs.id !== "string" ||
      fs.id.trim() === "" ||
      fs.id.length > 256 ||
      !isNonNegSafeInt(fs.totalBytes) ||
      fs.totalBytes === 0 ||
      !isNonNegSafeInt(fs.usedBytes) ||
      fs.usedBytes > fs.totalBytes ||
      seenFs.has(fs.id)
    ) {
      throw new InvalidSnapshotError();
    }
    seenFs.add(fs.id);
  }

  const seenNet = new Set<string>();
  for (const net of s.network) {
    if (
      !net ||
      typeof net.interface !== "string" ||
      net.interface.trim() === "" ||
      net.interface.length > 128 ||
      !isNonNegSafeInt(net.receivedBytes) ||
      !isNonNegSafeInt(net.sentBytes) ||
      seenNet.has(net.interface)
    ) {
      throw new InvalidSnapshotError();
    }
    seenNet.add(net.interface);
  }
}

/**
 * Classifies resource telemetry freshness. Returns "unknown" for invalid inputs or future-dated samples.
 * Resource freshness never implies inbound proxy reachability or runtime health.
 */
export function classifyResourceFreshness(
  snapshot: ResourceSnapshot,
  now: Date = new Date(),
  maxAgeMs = 120_000,
): ResourceFreshness {
  try {
    validateResourceSnapshot(snapshot);
  } catch {
    return "unknown";
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime()) || maxAgeMs <= 0) {
    return "unknown";
  }
  const ageMs = now.getTime() - snapshot.sampledAt.getTime();
  if (ageMs < 0) {
    return "unknown";
  }
  if (ageMs > maxAgeMs) {
    return "stale";
  }
  return "fresh";
}
