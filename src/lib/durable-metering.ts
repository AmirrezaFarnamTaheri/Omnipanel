import { createHash } from "node:crypto";

export interface PrincipalCounterSample {
  principalId: string;
  processGeneration: number;
  sequence: number;
  cumulativeUplinkBytes: number;
  cumulativeDownlinkBytes: number;
}

export interface TrackedPrincipalMeterState {
  principalId: string;
  lastGeneration: number;
  lastSequence: number;
  lastUplinkBytes: number;
  lastDownlinkBytes: number;
  totalAccumulatedUplinkBytes: number;
  totalAccumulatedDownlinkBytes: number;
  dirty: boolean;
}

export interface DurableMeteringCheckpointEnvelope {
  schemaVersion: "omnipanel-durable-metering-v1";
  nodeId: string;
  checkpointSequence: number;
  trackedUsers: TrackedPrincipalMeterState[];
  checkpointDigest: string;
  updatedAt: string;
}

export interface AbsoluteTotalFlushRecord {
  principalId: string;
  totalUplinkBytes: number;
  totalDownlinkBytes: number;
  lastGeneration: number;
  lastSequence: number;
}

/**
 * Durable S-UI-inspired metering checkpoint & destructive-drain accumulator.
 * Enforces:
 * - persist-before-ack (`acceptDurable` commits to the WAL checkpoint before returning success);
 * - generation-scoped monotonicity (refuses stale generations and counter regressions);
 * - idempotent replay of identical `(generation, sequence, counters)`;
 * - bounded tracked user capacity and dirty-window capacity;
 * - at-least-once `flushDurable` that clears `dirty` only after remote destination commit.
 */
export class DurableMeteringAccumulator {
  private readonly nodeId: string;
  private readonly maxTrackedUsers: number;
  private readonly maxDirtyWindow: number;
  private checkpointSequence = 0;
  private readonly users = new Map<string, TrackedPrincipalMeterState>();
  private persistedJson: string | null = null;

  public constructor(opts: { nodeId: string; maxTrackedUsers?: number; maxDirtyWindow?: number }) {
    if (!opts.nodeId || typeof opts.nodeId !== "string") {
      throw new Error("nodeId is required");
    }
    this.nodeId = opts.nodeId;
    this.maxTrackedUsers = opts.maxTrackedUsers ?? 2048;
    this.maxDirtyWindow = opts.maxDirtyWindow ?? 512;
  }

  public static rehydrateFromWal(
    rawJson: string,
    opts?: { maxTrackedUsers?: number; maxDirtyWindow?: number }
  ): DurableMeteringAccumulator {
    if (!rawJson || rawJson.length > 2 * 1024 * 1024) {
      throw new Error("checkpoint payload is empty or exceeds 2 MiB ceiling");
    }
    let parsed: DurableMeteringCheckpointEnvelope;
    try {
      parsed = JSON.parse(rawJson) as DurableMeteringCheckpointEnvelope;
    } catch {
      throw new Error("corrupt durable metering checkpoint JSON");
    }
    if (!parsed || parsed.schemaVersion !== "omnipanel-durable-metering-v1") {
      throw new Error("unsupported durable metering checkpoint schemaVersion");
    }
    const expectedDigest = computeCheckpointDigest(
      parsed.nodeId,
      parsed.checkpointSequence,
      parsed.trackedUsers
    );
    if (parsed.checkpointDigest !== expectedDigest) {
      throw new Error("durable metering checkpoint digest mismatch");
    }

    const acc = new DurableMeteringAccumulator({
      nodeId: parsed.nodeId,
      maxTrackedUsers: opts?.maxTrackedUsers,
      maxDirtyWindow: opts?.maxDirtyWindow,
    });
    acc.checkpointSequence = parsed.checkpointSequence;
    for (const u of parsed.trackedUsers) {
      if (
        u.totalAccumulatedUplinkBytes < u.lastUplinkBytes ||
        u.totalAccumulatedDownlinkBytes < u.lastDownlinkBytes
      ) {
        throw new Error(`corrupt total/counter relationship for principal ${u.principalId}`);
      }
      acc.users.set(u.principalId, { ...u });
    }
    acc.persistedJson = rawJson;
    return acc;
  }

  public acceptDurable(
    sample: PrincipalCounterSample,
    persistHook?: (checkpointJson: string) => void
  ): { replay: boolean; deltaUplink: number; deltaDownlink: number; checkpoint: DurableMeteringCheckpointEnvelope } {
    if (!sample.principalId || typeof sample.principalId !== "string") {
      throw new Error("principalId is required");
    }
    if (!Number.isSafeInteger(sample.processGeneration) || sample.processGeneration < 1) {
      throw new Error("processGeneration must be a positive safe integer");
    }
    if (!Number.isSafeInteger(sample.sequence) || sample.sequence < 1) {
      throw new Error("sequence must be a positive safe integer");
    }
    if (
      !Number.isSafeInteger(sample.cumulativeUplinkBytes) ||
      sample.cumulativeUplinkBytes < 0 ||
      !Number.isSafeInteger(sample.cumulativeDownlinkBytes) ||
      sample.cumulativeDownlinkBytes < 0
    ) {
      throw new Error("cumulative byte counters must be non-negative safe integers");
    }

    const existing = this.users.get(sample.principalId);
    if (existing) {
      if (sample.processGeneration < existing.lastGeneration) {
        throw new Error(
          `stale processGeneration ${sample.processGeneration} < ${existing.lastGeneration}`
        );
      }
      if (sample.processGeneration === existing.lastGeneration) {
        if (sample.sequence < existing.lastSequence) {
          throw new Error(`sequence regression ${sample.sequence} < ${existing.lastSequence}`);
        }
        if (sample.sequence === existing.lastSequence) {
          if (
            sample.cumulativeUplinkBytes === existing.lastUplinkBytes &&
            sample.cumulativeDownlinkBytes === existing.lastDownlinkBytes
          ) {
            return {
              replay: true,
              deltaUplink: 0,
              deltaDownlink: 0,
              checkpoint: this.exportCheckpoint(),
            };
          }
          throw new Error("conflicting counter payload for already-accepted (generation, sequence)");
        }
        if (
          sample.cumulativeUplinkBytes < existing.lastUplinkBytes ||
          sample.cumulativeDownlinkBytes < existing.lastDownlinkBytes
        ) {
          throw new Error("counter regression within same processGeneration");
        }
      }
    } else {
      if (this.users.size >= this.maxTrackedUsers) {
        throw new Error("tracked principal capacity exhausted");
      }
    }

    const currentDirtyCount = [...this.users.values()].filter((u) => u.dirty).length;
    if ((!existing || !existing.dirty) && currentDirtyCount >= this.maxDirtyWindow) {
      throw new Error("dirty pending-window capacity exhausted; flushDurable required before draining more");
    }

    const snapshotBefore = existing ? { ...existing } : undefined;
    const prevSeq = this.checkpointSequence;

    const deltaUplink =
      !existing || sample.processGeneration > existing.lastGeneration
        ? sample.cumulativeUplinkBytes
        : sample.cumulativeUplinkBytes - existing.lastUplinkBytes;
    const deltaDownlink =
      !existing || sample.processGeneration > existing.lastGeneration
        ? sample.cumulativeDownlinkBytes
        : sample.cumulativeDownlinkBytes - existing.lastDownlinkBytes;

    const nextState: TrackedPrincipalMeterState = {
      principalId: sample.principalId,
      lastGeneration: sample.processGeneration,
      lastSequence: sample.sequence,
      lastUplinkBytes: sample.cumulativeUplinkBytes,
      lastDownlinkBytes: sample.cumulativeDownlinkBytes,
      totalAccumulatedUplinkBytes: (existing?.totalAccumulatedUplinkBytes ?? 0) + deltaUplink,
      totalAccumulatedDownlinkBytes: (existing?.totalAccumulatedDownlinkBytes ?? 0) + deltaDownlink,
      dirty: true,
    };

    this.users.set(sample.principalId, nextState);
    this.checkpointSequence += 1;
    const checkpoint = this.exportCheckpoint();
    const json = JSON.stringify(checkpoint);

    try {
      if (persistHook) {
        persistHook(json);
      }
      this.persistedJson = json;
    } catch (err) {
      // Roll back in-memory mutation if WAL checkpoint persistence fails!
      this.checkpointSequence = prevSeq;
      if (snapshotBefore) {
        this.users.set(sample.principalId, snapshotBefore);
      } else {
        this.users.delete(sample.principalId);
      }
      throw err;
    }

    return {
      replay: false,
      deltaUplink,
      deltaDownlink,
      checkpoint,
    };
  }

  public flushDurable(
    deliverBatch: (records: AbsoluteTotalFlushRecord[]) => void,
    persistHook?: (checkpointJson: string) => void
  ): AbsoluteTotalFlushRecord[] {
    const dirtyRecords: AbsoluteTotalFlushRecord[] = [];
    for (const u of this.users.values()) {
      if (u.dirty) {
        dirtyRecords.push({
          principalId: u.principalId,
          totalUplinkBytes: u.totalAccumulatedUplinkBytes,
          totalDownlinkBytes: u.totalAccumulatedDownlinkBytes,
          lastGeneration: u.lastGeneration,
          lastSequence: u.lastSequence,
        });
      }
    }
    if (dirtyRecords.length === 0) return [];

    // Destination must succeed before clearing dirty flags
    deliverBatch(dirtyRecords);

    for (const r of dirtyRecords) {
      const st = this.users.get(r.principalId);
      if (st) st.dirty = false;
    }
    this.checkpointSequence += 1;
    const checkpoint = this.exportCheckpoint();
    const json = JSON.stringify(checkpoint);
    if (persistHook) {
      persistHook(json);
    }
    this.persistedJson = json;
    return dirtyRecords;
  }

  public exportCheckpoint(now: Date = new Date()): DurableMeteringCheckpointEnvelope {
    const trackedUsers = [...this.users.values()]
      .sort((a, b) => a.principalId.localeCompare(b.principalId))
      .map((u) => ({ ...u }));
    const checkpointDigest = computeCheckpointDigest(
      this.nodeId,
      this.checkpointSequence,
      trackedUsers
    );
    return {
      schemaVersion: "omnipanel-durable-metering-v1",
      nodeId: this.nodeId,
      checkpointSequence: this.checkpointSequence,
      trackedUsers,
      checkpointDigest,
      updatedAt: now.toISOString(),
    };
  }
}

function computeCheckpointDigest(
  nodeId: string,
  checkpointSequence: number,
  trackedUsers: TrackedPrincipalMeterState[]
): string {
  return createHash("sha256")
    .update(JSON.stringify({ nodeId, checkpointSequence, trackedUsers }))
    .digest("hex");
}
