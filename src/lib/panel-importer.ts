import { createHash } from "node:crypto";
import { validateInboundCompatibility } from "./protocol-compatibility";

export type SourcePanelKind = "s-ui" | "3x-ui";

export interface SourcePanelClientRecord {
  id: string;
  emailOrName: string;
  enable: boolean;
  upBytes: number;
  downBytes: number;
  totalQuotaBytes: number;
  expiryEpochMs: number | null;
}

export interface SourcePanelInboundRecord {
  tag: string;
  protocol: string;
  transport: string;
  runtime: string;
  listenPort: number;
  serverName?: string;
  realityPublicKey?: string;
  realityShortId?: string;
  clients: SourcePanelClientRecord[];
}

export interface SourcePanelExportPayload {
  sourcePanel: SourcePanelKind;
  sourceVersion: string;
  exportedAt: string;
  inbounds: SourcePanelInboundRecord[];
}

export interface ImportedHistoricalUsageRecord {
  logicalUserName: string;
  sourcePanel: SourcePanelKind;
  historicalUpBytes: number;
  historicalDownBytes: number;
  accountingClassification: "historical_non_billable";
}

export interface DryRunImportReport {
  mode: "dry_run" | "committed";
  sourcePanel: SourcePanelKind;
  sourceVersion: string;
  migrationJournalDigest: string;
  readyToCommit: boolean;
  requiresOperatorApproval: boolean;
  admittedInbounds: {
    tag: string;
    canonicalProtocol: string;
    port: number;
    clientCount: number;
  }[];
  rejectedInbounds: {
    tag: string;
    reason: string;
  }[];
  logicalUsers: {
    name: string;
    status: "active" | "suspended";
    quotaBytes: number | null;
    expiresAt: string | null;
    endpointCount: number;
  }[];
  historicalUsage: ImportedHistoricalUsageRecord[];
  collisionsAndWarnings: string[];
}

/**
 * Dry-run-first S-UI and 3X-UI migration importer (`internal/importers` M3 contract).
 * Parses source exports into OmniPanel's canonical model without touching SQLite files,
 * validates every inbound against `protocol-compatibility`, flags port/user collisions,
 * and marks all imported traffic counters strictly as `historical_non_billable` so
 * unverified legacy counters never trigger automated quota suspension or billing.
 */
export function evaluatePanelImportDryRun(
  payload: SourcePanelExportPayload,
  existingPorts: number[] = [],
  existingUserNames: string[] = []
): DryRunImportReport {
  if (!payload || (payload.sourcePanel !== "s-ui" && payload.sourcePanel !== "3x-ui")) {
    throw new Error("sourcePanel must be 's-ui' or '3x-ui'");
  }
  if (!payload.sourceVersion || typeof payload.sourceVersion !== "string") {
    throw new Error("sourceVersion is required");
  }

  const portSet = new Set<number>(existingPorts);
  const existingUsersSet = new Set<string>(existingUserNames.map((u) => u.toLowerCase()));
  const admittedInbounds: DryRunImportReport["admittedInbounds"] = [];
  const rejectedInbounds: DryRunImportReport["rejectedInbounds"] = [];
  const collisionsAndWarnings: string[] = [];

  const userMap = new Map<
    string,
    {
      name: string;
      status: "active" | "suspended";
      quotaBytes: number | null;
      expiresAt: string | null;
      endpointCount: number;
      upBytes: number;
      downBytes: number;
    }
  >();

  for (const ib of payload.inbounds ?? []) {
    if (portSet.has(ib.listenPort)) {
      rejectedInbounds.push({
        tag: ib.tag,
        reason: `port collision on ${ib.listenPort}`,
      });
      collisionsAndWarnings.push(`Inbound "${ib.tag}" conflicts on port ${ib.listenPort}`);
      continue;
    }

    const normalizedRuntime = ib.runtime === "sing-box" ? "singbox" : ib.runtime;
    const compat = validateInboundCompatibility({
      runtime: normalizedRuntime,
      protocol: ib.protocol,
      transport: ib.transport,
      serverName: ib.serverName ?? "",
      params:
        ib.protocol === "vless-reality-vision"
          ? {
              realityPublicKey: ib.realityPublicKey ?? "",
              shortId: ib.realityShortId ?? "",
              flow: "xtls-rprx-vision",
              fingerprint: "chrome",
            }
          : undefined,
    });

    if (!compat.supported) {
      rejectedInbounds.push({
        tag: ib.tag,
        reason: compat.reason,
      });
      collisionsAndWarnings.push(`Inbound "${ib.tag}" excluded: ${compat.reason}`);
      continue;
    }

    portSet.add(ib.listenPort);
    admittedInbounds.push({
      tag: ib.tag,
      canonicalProtocol: ib.protocol,
      port: ib.listenPort,
      clientCount: (ib.clients ?? []).length,
    });

    for (const cl of ib.clients ?? []) {
      const normalized = cl.emailOrName.trim();
      if (!normalized) continue;
      if (existingUsersSet.has(normalized.toLowerCase())) {
        collisionsAndWarnings.push(
          `Client "${normalized}" collides with an existing OmniPanel user; credentials will be re-keyed under existing logical identity`
        );
      }

      const existing = userMap.get(normalized.toLowerCase());
      const expiresIso =
        cl.expiryEpochMs && cl.expiryEpochMs > 0 ? new Date(cl.expiryEpochMs).toISOString() : null;
      const quota = cl.totalQuotaBytes > 0 ? cl.totalQuotaBytes : null;

      if (!existing) {
        userMap.set(normalized.toLowerCase(), {
          name: normalized,
          status: cl.enable ? "active" : "suspended",
          quotaBytes: quota,
          expiresAt: expiresIso,
          endpointCount: 1,
          upBytes: Math.max(0, cl.upBytes || 0),
          downBytes: Math.max(0, cl.downBytes || 0),
        });
      } else {
        existing.endpointCount += 1;
        existing.upBytes += Math.max(0, cl.upBytes || 0);
        existing.downBytes += Math.max(0, cl.downBytes || 0);
      }
    }
  }

  const logicalUsers = [...userMap.values()].map((u) => ({
    name: u.name,
    status: u.status,
    quotaBytes: u.quotaBytes,
    expiresAt: u.expiresAt,
    endpointCount: u.endpointCount,
  }));

  const historicalUsage: ImportedHistoricalUsageRecord[] = [...userMap.values()].map((u) => ({
    logicalUserName: u.name,
    sourcePanel: payload.sourcePanel,
    historicalUpBytes: u.upBytes,
    historicalDownBytes: u.downBytes,
    accountingClassification: "historical_non_billable",
  }));

  const migrationJournalDigest = createHash("sha256")
    .update(
      JSON.stringify({
        sourcePanel: payload.sourcePanel,
        sourceVersion: payload.sourceVersion,
        admittedInbounds,
        rejectedInbounds,
        logicalUsers,
        historicalUsage,
      })
    )
    .digest("hex");

  return {
    mode: "dry_run",
    sourcePanel: payload.sourcePanel,
    sourceVersion: payload.sourceVersion,
    migrationJournalDigest,
    readyToCommit: admittedInbounds.length > 0,
    requiresOperatorApproval: rejectedInbounds.length > 0 || collisionsAndWarnings.length > 0,
    admittedInbounds,
    rejectedInbounds,
    logicalUsers,
    historicalUsage,
    collisionsAndWarnings,
  };
}
