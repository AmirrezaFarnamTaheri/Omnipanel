import { createHash } from "node:crypto";

export type FirewallEngine = "nftables" | "iptables" | "ufw" | "firewalld";
export type FirewallDirection = "ingress" | "egress" | "forward";
export type FirewallVerdict = "accept" | "drop" | "reject";
export type FirewallProtocol = "tcp" | "udp" | "icmp" | "any";

export interface FirewallRuleRecord {
  ruleId: string;
  table: string;
  chain: string;
  direction: FirewallDirection;
  protocol: FirewallProtocol;
  portRange: string | null;
  sourceCidr: string;
  destinationCidr: string;
  verdict: FirewallVerdict;
  ownedByOmniPanel: boolean;
  protectedRule: boolean;
  comment?: string;
}

export interface FirewallInventorySnapshot {
  nodeId: string;
  engine: FirewallEngine;
  generation: number;
  sampledAt: string;
  loopbackAcceptPresent: boolean;
  protectedSshPort: number;
  protectedManagementPort: number;
  privateEgressBlockedCidrs: string[];
  rules: FirewallRuleRecord[];
}

export interface FirewallSafetyReport {
  valid: boolean;
  inventoryDigest: string;
  sshManagementProtected: boolean;
  loopbackProtected: boolean;
  privateEgressGuardComplete: boolean;
  ownedRuleCount: number;
  unmanagedRuleCount: number;
  requiresCommitConfirmWatchdog: true;
  invokesHostShell: false;
  warnings: string[];
  errors: string[];
}

export const REQUIRED_PRIVATE_EGRESS_CIDRS = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
  "127.0.0.0/8",
  "fc00::/7",
  "fe80::/10",
] as const;

const RULE_ID_RE = /^[a-zA-Z0-9._:-]{1,96}$/;

function portInRange(port: number, spec: string | null): boolean {
  if (!spec || spec === "any" || spec === "*") return true;
  if (/^\d+$/.test(spec)) {
    return Number(spec) === port;
  }
  const m = /^(\d+)-(\d+)$/.exec(spec);
  if (m) {
    const lo = Number(m[1]);
    const hi = Number(m[2]);
    return port >= lo && port <= hi;
  }
  return false;
}

/**
 * Validates a read-only firewall inventory snapshot (1Panel firewall-inventory lesson).
 * Never executes host commands; verifies that SSH/management reachability is preserved,
 * private/metadata egress ranges are blocked for proxy traffic, and owned rules are
 * separated from unmanaged host rules.
 */
export function evaluateFirewallInventory(snapshot: FirewallInventorySnapshot): FirewallSafetyReport {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!snapshot || typeof snapshot !== "object") {
    throw new Error("firewall snapshot must be an object");
  }
  if (!snapshot.nodeId || typeof snapshot.nodeId !== "string") {
    errors.push("nodeId is required");
  }
  if (!["nftables", "iptables", "ufw", "firewalld"].includes(snapshot.engine)) {
    errors.push(`unsupported firewall engine: ${String(snapshot.engine)}`);
  }
  if (!Number.isSafeInteger(snapshot.generation) || snapshot.generation < 1) {
    errors.push("generation must be a positive safe integer");
  }
  if (
    !Number.isSafeInteger(snapshot.protectedSshPort) ||
    snapshot.protectedSshPort < 1 ||
    snapshot.protectedSshPort > 65535
  ) {
    errors.push("protectedSshPort must be a valid TCP port (1..65535)");
  }
  if (
    !Number.isSafeInteger(snapshot.protectedManagementPort) ||
    snapshot.protectedManagementPort < 1 ||
    snapshot.protectedManagementPort > 65535
  ) {
    errors.push("protectedManagementPort must be a valid TCP port (1..65535)");
  }

  const seenIds = new Set<string>();
  let ownedRuleCount = 0;
  let unmanagedRuleCount = 0;
  let sshAcceptSeen = false;
  let sshDropBeforeAccept = false;
  let mgmtDropBeforeAccept = false;
  let mgmtAcceptSeen = false;

  for (const r of snapshot.rules ?? []) {
    if (!RULE_ID_RE.test(r.ruleId)) {
      errors.push(`invalid ruleId: ${r.ruleId}`);
    }
    if (seenIds.has(r.ruleId)) {
      errors.push(`duplicate ruleId: ${r.ruleId}`);
    }
    seenIds.add(r.ruleId);

    if (r.ownedByOmniPanel) {
      ownedRuleCount += 1;
    } else {
      unmanagedRuleCount += 1;
    }

    if (r.direction === "ingress" && (r.protocol === "tcp" || r.protocol === "any")) {
      if (portInRange(snapshot.protectedSshPort, r.portRange)) {
        if (r.verdict === "accept" && r.sourceCidr === "0.0.0.0/0") {
          sshAcceptSeen = true;
        } else if ((r.verdict === "drop" || r.verdict === "reject") && !sshAcceptSeen) {
          sshDropBeforeAccept = true;
        }
      }
      if (portInRange(snapshot.protectedManagementPort, r.portRange)) {
        if (r.verdict === "accept") {
          mgmtAcceptSeen = true;
        } else if ((r.verdict === "drop" || r.verdict === "reject") && !mgmtAcceptSeen) {
          mgmtDropBeforeAccept = true;
        }
      }
    }
  }

  const loopbackProtected = Boolean(snapshot.loopbackAcceptPresent);
  if (!loopbackProtected) {
    errors.push("loopback interface accept rule is missing; local control/health sockets could be severed");
  }

  const sshManagementProtected = sshAcceptSeen && !sshDropBeforeAccept && !mgmtDropBeforeAccept;
  if (!sshAcceptSeen || sshDropBeforeAccept) {
    errors.push(
      `protected SSH port ${snapshot.protectedSshPort}/tcp is not safely accepted before drop/reject rules`
    );
  }
  if (mgmtDropBeforeAccept) {
    errors.push(
      `protected management port ${snapshot.protectedManagementPort}/tcp is blocked before an accept rule`
    );
  }

  const blockedSet = new Set(snapshot.privateEgressBlockedCidrs ?? []);
  const missingCidrs = REQUIRED_PRIVATE_EGRESS_CIDRS.filter((c) => !blockedSet.has(c));
  const privateEgressGuardComplete = missingCidrs.length === 0;
  if (!privateEgressGuardComplete) {
    errors.push(`private/metadata egress guard is missing required CIDRs: ${missingCidrs.join(", ")}`);
  }

  if (unmanagedRuleCount > 0) {
    warnings.push(
      `${unmanagedRuleCount} unmanaged host rule(s) detected; OmniPanel reconciler will never mutate or delete unmanaged chains`
    );
  }

  const canonical = JSON.stringify({
    nodeId: snapshot.nodeId,
    engine: snapshot.engine,
    generation: snapshot.generation,
    protectedSshPort: snapshot.protectedSshPort,
    protectedManagementPort: snapshot.protectedManagementPort,
    privateEgressBlockedCidrs: [...(snapshot.privateEgressBlockedCidrs ?? [])].sort(),
    rules: (snapshot.rules ?? []).map((r) => ({
      ruleId: r.ruleId,
      table: r.table,
      chain: r.chain,
      direction: r.direction,
      protocol: r.protocol,
      portRange: r.portRange,
      sourceCidr: r.sourceCidr,
      destinationCidr: r.destinationCidr,
      verdict: r.verdict,
      ownedByOmniPanel: r.ownedByOmniPanel,
      protectedRule: r.protectedRule,
    })),
  });
  const inventoryDigest = createHash("sha256").update(canonical).digest("hex");

  return {
    valid: errors.length === 0,
    inventoryDigest,
    sshManagementProtected,
    loopbackProtected,
    privateEgressGuardComplete,
    ownedRuleCount,
    unmanagedRuleCount,
    requiresCommitConfirmWatchdog: true,
    invokesHostShell: false,
    warnings,
    errors,
  };
}
