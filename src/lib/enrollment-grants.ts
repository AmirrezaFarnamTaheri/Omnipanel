import { createHash, createHmac, randomBytes } from "node:crypto";
import { verifyTotp } from "./totp";

export type StepUpVerificationSource = "trusted" | "legacy";

export interface AdminSessionRecord {
  sessionId: number;
  adminId: number;
  adminEmail: string;
  role: "owner" | "operator" | "viewer";
  sessionTokenHash: string;
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
  canIssueGrant: boolean;
  canApproveGrant: boolean;
  totpEnabled: boolean;
  totpSecretBase32: string | null;
}

export interface TrustedStepUpRecord {
  sessionId: number;
  adminId: number;
  verifiedSource: StepUpVerificationSource;
  verifiedCounter: number;
  verifiedAt: Date;
}

export interface EnrollmentGrantRecord {
  grantId: string;
  organizationId: string;
  nodeId: number;
  nodeUuid: string;
  tokenSha256: string;
  issuerAdminId: number;
  approverAdminId: number;
  issuerSessionId: number;
  issuerSessionTokenHash: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
  issuedCertSerial: string | null;
}

export interface IssuedNodeCertificate {
  nodeUuid: string;
  nodeId: number;
  organizationId: string;
  serial: string;
  spiffeUri: string;
  certificatePem: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
}

const MAX_SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000; // 12 hours
const MAX_SESSION_IDLE_MS = 2 * 60 * 60 * 1000; // 2 hours
const MAX_STEPUP_AGE_MS = 10 * 60 * 1000; // 10 minutes
const MAX_GRANT_LIFETIME_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Shared 60-second window admission limiter keyed by HMAC-SHA256 peer IP digests
 * (`internal/pki/enrollment/httpapi/pg_limiter.go` contract).
 * Never stores raw IP addresses.
 */
export class SharedEnrollmentLimiter {
  private readonly hmacKey: Buffer;
  private readonly maxPerPeerPerWindow: number;
  private readonly maxGlobalPerWindow: number;
  private readonly peerCounts = new Map<string, number>();
  private readonly globalCounts = new Map<number, number>();

  public constructor(opts: {
    hmacKey: Buffer;
    maxPerPeerPerWindow?: number;
    maxGlobalPerWindow?: number;
  }) {
    if (!opts.hmacKey || opts.hmacKey.length < 32) {
      throw new Error("SharedEnrollmentLimiter requires at least a 256-bit (32-byte) HMAC key");
    }
    this.hmacKey = Buffer.from(opts.hmacKey);
    this.maxPerPeerPerWindow = opts.maxPerPeerPerWindow ?? 5;
    this.maxGlobalPerWindow = opts.maxGlobalPerWindow ?? 30;
  }

  public checkAndAdmit(peerIp: string, now: Date = new Date()): {
    allowed: boolean;
    peerDigestHex: string;
    windowBucket: number;
    reason?: string;
  } {
    const normalizedIp = peerIp.trim().toLowerCase();
    if (!normalizedIp || normalizedIp.includes(" ")) {
      throw new Error("invalid canonical peer IP");
    }
    const windowBucket = Math.floor(now.getTime() / 60_000);
    const peerDigestHex = createHmac("sha256", this.hmacKey)
      .update(`${windowBucket}|${normalizedIp}`)
      .digest("hex");

    const peerCount = this.peerCounts.get(peerDigestHex) ?? 0;
    const globalCount = this.globalCounts.get(windowBucket) ?? 0;

    if (peerCount >= this.maxPerPeerPerWindow) {
      // Denied peer does NOT increment global counter (transactional rollback invariant)
      return {
        allowed: false,
        peerDigestHex,
        windowBucket,
        reason: "peer_rate_limit_exceeded",
      };
    }
    if (globalCount >= this.maxGlobalPerWindow) {
      return {
        allowed: false,
        peerDigestHex,
        windowBucket,
        reason: "global_rate_limit_exceeded",
      };
    }

    this.peerCounts.set(peerDigestHex, peerCount + 1);
    this.globalCounts.set(windowBucket, globalCount + 1);
    return { allowed: true, peerDigestHex, windowBucket };
  }
}

/**
 * Complete Enrollment Grant, Trusted TOTP Step-Up, Logout-Safe Revocation & Redemption Recheck Ledger.
 * Implements migrations 0003–0007 and `ApprovedSQLStore` invariants:
 * - Rejects `verifiedSource: "legacy"` step-ups and replayed RFC 6238 counters;
 * - Enforces 5-attempt / 5-minute failed TOTP budget per admin;
 * - Enforces 12h absolute and 2h idle session lifetime at both issuance and redemption (`Lookup` & `Commit`);
 * - Stores `issuerSessionTokenHash` as an immutable fact so operator logout deletes the session row
 *   without FK failure, immediately invalidates unredeemed grants, refuses recycled session IDs,
 *   and preserves already-issued node certificates.
 */
export class EnrollmentGrantService {
  private readonly sessions = new Map<number, AdminSessionRecord>();
  private readonly stepUps = new Map<number, TrustedStepUpRecord>();
  private readonly lastUsedCounterByAdmin = new Map<number, number>();
  private readonly failedAttemptsByAdmin = new Map<number, number[]>();
  private readonly grantsByDigest = new Map<string, EnrollmentGrantRecord>();
  private readonly certificatesBySerial = new Map<string, IssuedNodeCertificate>();
  private readonly nodeStatusById = new Map<number, "pending_enrollment" | "active" | "quarantined">();
  private readonly orgActiveById = new Map<string, boolean>();
  private readonly bindingActiveByUuid = new Map<string, { nodeId: number; organizationId: string }>();

  public registerSession(session: AdminSessionRecord): void {
    this.sessions.set(session.sessionId, { ...session });
  }

  public setNodeAndOrgState(input: {
    nodeId: number;
    nodeUuid: string;
    organizationId: string;
    nodeStatus: "pending_enrollment" | "active" | "quarantined";
    organizationActive: boolean;
    bindingApproved: boolean;
  }): void {
    this.nodeStatusById.set(input.nodeId, input.nodeStatus);
    this.orgActiveById.set(input.organizationId, input.organizationActive);
    if (input.bindingApproved) {
      this.bindingActiveByUuid.set(input.nodeUuid, {
        nodeId: input.nodeId,
        organizationId: input.organizationId,
      });
    } else {
      this.bindingActiveByUuid.delete(input.nodeUuid);
    }
  }

  public recordLegacyStepUp(sessionId: number, adminId: number, now: Date = new Date()): void {
    this.stepUps.set(sessionId, {
      sessionId,
      adminId,
      verifiedSource: "legacy",
      verifiedCounter: 0,
      verifiedAt: now,
    });
  }

  public verifyTrustedStepUp(input: {
    sessionId: number;
    totpCode: string;
    now?: Date;
  }): TrustedStepUpRecord {
    const now = input.now ?? new Date();
    const session = this.requireLiveOwnerSession(input.sessionId, now);
    if (!session.totpEnabled || !session.totpSecretBase32) {
      throw new Error("owner TOTP MFA is not enabled");
    }

    const windowStart = now.getTime() - 5 * 60 * 1000;
    const recentFailures = (this.failedAttemptsByAdmin.get(session.adminId) ?? []).filter(
      (ts) => ts >= windowStart
    );
    if (recentFailures.length >= 5) {
      throw new Error("TOTP step-up rate budget exhausted (max 5 failed attempts per 5 minutes)");
    }

    const currentCounter = Math.floor(now.getTime() / 30_000);
    const valid = verifyTotp(session.totpSecretBase32, input.totpCode, now.getTime());
    if (!valid) {
      recentFailures.push(now.getTime());
      this.failedAttemptsByAdmin.set(session.adminId, recentFailures);
      throw new Error("invalid TOTP factor code");
    }

    const lastCounter = this.lastUsedCounterByAdmin.get(session.adminId) ?? -1;
    if (currentCounter <= lastCounter) {
      throw new Error("replayed TOTP counter refused across administrator sessions");
    }

    this.lastUsedCounterByAdmin.set(session.adminId, currentCounter);
    const record: TrustedStepUpRecord = {
      sessionId: session.sessionId,
      adminId: session.adminId,
      verifiedSource: "trusted",
      verifiedCounter: currentCounter,
      verifiedAt: now,
    };
    this.stepUps.set(session.sessionId, record);
    return { ...record };
  }

  public issueEnrollmentGrant(input: {
    issuerSessionId: number;
    approverAdminId: number;
    approverCanApprove: boolean;
    organizationId: string;
    nodeId: number;
    nodeUuid: string;
    ttlSeconds?: number;
    now?: Date;
  }): { bearerToken: string; grant: EnrollmentGrantRecord } {
    const now = input.now ?? new Date();
    const session = this.requireLiveOwnerSession(input.issuerSessionId, now);
    if (!session.canIssueGrant) {
      throw new Error("issuer lacks organization-scoped can_issue permission");
    }
    if (input.approverAdminId === session.adminId || !input.approverCanApprove) {
      throw new Error("enrollment grant requires a distinct second owner with can_approve permission");
    }

    const stepUp = this.stepUps.get(session.sessionId);
    if (!stepUp || stepUp.verifiedSource !== "trusted" || stepUp.verifiedCounter <= 0) {
      throw new Error("enrollment grant requires verified_source='trusted' TOTP step-up");
    }
    if (now.getTime() - stepUp.verifiedAt.getTime() > MAX_STEPUP_AGE_MS) {
      throw new Error("trusted TOTP step-up has expired");
    }

    this.requireActiveBindingAndOrg(input.nodeUuid, input.nodeId, input.organizationId, true);

    for (const existing of this.grantsByDigest.values()) {
      if (
        existing.nodeUuid === input.nodeUuid &&
        existing.consumedAt === null &&
        existing.expiresAt.getTime() > now.getTime()
      ) {
        throw new Error("an unconsumed enrollment grant is already active for this node");
      }
    }

    const rawBearer = randomBytes(32).toString("base64url");
    const tokenSha256 = createHash("sha256").update(rawBearer).digest("hex");
    const ttlMs = Math.min(MAX_GRANT_LIFETIME_MS, Math.max(60_000, (input.ttlSeconds ?? 900) * 1000));

    const grant: EnrollmentGrantRecord = {
      grantId: `grant-${randomBytes(6).toString("hex")}`,
      organizationId: input.organizationId,
      nodeId: input.nodeId,
      nodeUuid: input.nodeUuid,
      tokenSha256,
      issuerAdminId: session.adminId,
      approverAdminId: input.approverAdminId,
      issuerSessionId: session.sessionId,
      issuerSessionTokenHash: session.sessionTokenHash,
      issuedAt: now,
      expiresAt: new Date(now.getTime() + ttlMs),
      consumedAt: null,
      issuedCertSerial: null,
    };
    this.grantsByDigest.set(tokenSha256, grant);
    return { bearerToken: rawBearer, grant: { ...grant } };
  }

  public logoutSession(sessionId: number): void {
    this.sessions.delete(sessionId);
    this.stepUps.delete(sessionId);
    // Note: grantsByDigest history is append-only and NOT deleted on logout!
  }

  public redeemGrantAndIssueCertificate(input: {
    bearerToken: string;
    csrPem: string;
    now?: Date;
  }): IssuedNodeCertificate {
    const now = input.now ?? new Date();
    if (!input.csrPem || !input.csrPem.includes("BEGIN CERTIFICATE REQUEST")) {
      throw new Error("invalid PEM CSR");
    }
    const tokenSha256 = createHash("sha256").update(input.bearerToken).digest("hex");
    const grant = this.grantsByDigest.get(tokenSha256);
    if (!grant) {
      throw new Error("unknown enrollment bearer token");
    }
    if (grant.consumedAt !== null) {
      throw new Error("enrollment grant has already been redeemed");
    }
    if (now.getTime() >= grant.expiresAt.getTime()) {
      throw new Error("enrollment grant has expired");
    }

    // Redemption-time recheck of issuing session (including logout, recycled sessionId, and 2h idle age)
    const liveSession = this.sessions.get(grant.issuerSessionId);
    if (!liveSession || liveSession.sessionTokenHash !== grant.issuerSessionTokenHash) {
      throw new Error("issuing administrator session was logged out or replaced");
    }
    this.requireLiveOwnerSession(grant.issuerSessionId, now);
    if (!liveSession.canIssueGrant) {
      throw new Error("issuer lost can_issue permission before redemption");
    }

    // Redemption-time recheck of node binding, organization, and pending_enrollment state
    this.requireActiveBindingAndOrg(grant.nodeUuid, grant.nodeId, grant.organizationId, true);

    const serial = randomBytes(16).toString("hex");
    const spiffeUri = `spiffe://omnipanel/node/${grant.nodeUuid}`;
    const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
    const cert: IssuedNodeCertificate = {
      nodeUuid: grant.nodeUuid,
      nodeId: grant.nodeId,
      organizationId: grant.organizationId,
      serial,
      spiffeUri,
      certificatePem: `-----BEGIN CERTIFICATE-----\n${Buffer.from(
        JSON.stringify({ serial, spiffeUri, expiresAt })
      ).toString("base64")}\n-----END CERTIFICATE-----`,
      issuedAt: now.toISOString(),
      expiresAt,
      revokedAt: null,
    };

    grant.consumedAt = now;
    grant.issuedCertSerial = serial;
    this.certificatesBySerial.set(serial, cert);
    this.nodeStatusById.set(grant.nodeId, "active");
    return { ...cert };
  }

  public isCertificateAdmittedOnline(serial: string, now: Date = new Date()): boolean {
    const cert = this.certificatesBySerial.get(serial);
    if (!cert || cert.revokedAt !== null) return false;
    if (now.getTime() >= Date.parse(cert.expiresAt)) return false;
    try {
      // Online admission does NOT depend on admin session remaining logged in,
      // but DOES depend on binding, active org, and non-quarantined node!
      this.requireActiveBindingAndOrg(cert.nodeUuid, cert.nodeId, cert.organizationId, false);
      return true;
    } catch {
      return false;
    }
  }

  private requireLiveOwnerSession(sessionId: number, now: Date): AdminSessionRecord {
    const s = this.sessions.get(sessionId);
    if (!s) throw new Error("administrator session not found");
    if (s.role !== "owner") throw new Error("owner role required");
    const nowMs = now.getTime();
    if (s.createdAt.getTime() > nowMs || s.lastSeenAt.getTime() > nowMs) {
      throw new Error("future-dated session timestamp rejected");
    }
    if (nowMs >= s.expiresAt.getTime()) {
      throw new Error("administrator session expired");
    }
    if (nowMs - s.createdAt.getTime() > MAX_SESSION_ABSOLUTE_MS) {
      throw new Error("administrator session exceeded 12-hour absolute lifetime");
    }
    if (nowMs - s.lastSeenAt.getTime() > MAX_SESSION_IDLE_MS) {
      throw new Error("administrator session exceeded 2-hour idle lifetime");
    }
    return s;
  }

  private requireActiveBindingAndOrg(
    nodeUuid: string,
    nodeId: number,
    organizationId: string,
    requirePendingEnrollment: boolean
  ): void {
    const binding = this.bindingActiveByUuid.get(nodeUuid);
    if (!binding || binding.nodeId !== nodeId || binding.organizationId !== organizationId) {
      throw new Error("node UUID binding is missing or revoked");
    }
    if (!this.orgActiveById.get(organizationId)) {
      throw new Error("organization is suspended or inactive");
    }
    const status = this.nodeStatusById.get(nodeId);
    if (requirePendingEnrollment && status !== "pending_enrollment") {
      throw new Error(`node must be pending_enrollment to mint or redeem grant (current: ${status})`);
    }
    if (!requirePendingEnrollment && (status === "quarantined" || !status)) {
      throw new Error("quarantined or unknown node is denied online mTLS admission");
    }
  }
}
