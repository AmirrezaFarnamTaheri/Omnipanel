/**
 * Two-stage, session-bound, dual-operator desired-state publication approval contract
 * (mirrors internal/control/desiredapproval and internal/control/desiredpublish).
 *
 * Enforces:
 * 1. Canonical JSON Ed25519 signature + SHA-256 envelope digest verification.
 * 2. Bounded proposal TTL (60s–600s) and approval TTL (<= 300s, never exceeding proposal expiry).
 * 3. Independent second-owner approval (proposerAdminId !== approverAdminId) with exact SHA-256 confirmation.
 * 4. Monotonic same-epoch structural sequence (next === current + 1) and non-decreasing membership cursor.
 */

import crypto from "node:crypto";
import { canonicalJson, sha256 } from "@/lib/crypto";

export const MIN_PROPOSAL_LIFETIME_SEC = 60;
export const MAX_PROPOSAL_LIFETIME_SEC = 600;
export const MAX_APPROVAL_LIFETIME_SEC = 300;
export const MAX_ENVELOPE_BYTES = 1 << 20;

export type SignedDesiredEnvelope = {
  version: "ed25519-jcs-v1";
  keyId: string;
  manifestDigest: string;
  signature: string;
  manifest: {
    schema: "omni.desired-state/v1";
    nodeId: string;
    controlPlaneEpoch: string;
    structuralSequence: number;
    membershipSequence: number;
    issuedAt: string;
    expiresAt: string;
    disruption: string;
    payload: Record<string, unknown>;
  };
};

export type ProposalRecord = {
  proposalId: string;
  nodeId: number;
  nodeUuid: string;
  controlPlaneEpoch: number;
  structuralSequence: number;
  membershipSequence: number;
  disruption: string;
  envelopeJson: string;
  envelopeSha256: string;
  proposerAdminId: number;
  proposerEmail: string;
  createdAt: string;
  expiresAt: string;
  decision?: {
    approvalId: string;
    approverAdminId: number;
    approverEmail: string;
    reviewedSha256: string;
    approvedAt: string;
    approvalExpiresAt: string;
    consumedAt: string | null;
    publishedRevisionSeq?: number;
  };
};

export class PublicationApprovalError extends Error {
  code:
    | "INVALID_INPUT"
    | "UNAUTHORIZED"
    | "CONFLICT"
    | "SEQUENCE_CONFLICT"
    | "CANDIDATE_MANIFEST_DRIFT";
  constructor(
    code:
      | "INVALID_INPUT"
      | "UNAUTHORIZED"
      | "CONFLICT"
      | "SEQUENCE_CONFLICT"
      | "CANDIDATE_MANIFEST_DRIFT",
    message: string,
  ) {
    super(message);
    this.name = "PublicationApprovalError";
    this.code = code;
  }
}

const HEX64_PATTERN = /^[0-9a-f]{64}$/;

export function buildSignedEnvelope(input: {
  nodeUuid: string;
  controlPlaneEpoch: string;
  structuralSequence: number;
  membershipSequence: number;
  disruption: string;
  payload: Record<string, unknown>;
  keyId: string;
  sign: (canonicalPayload: string) => string;
  now?: Date;
  ttlSeconds?: number;
}): { envelope: SignedDesiredEnvelope; envelopeJson: string; envelopeSha256: string } {
  const now = input.now ?? new Date();
  const ttl = input.ttlSeconds ?? 300;
  if (
    !input.nodeUuid ||
    !input.controlPlaneEpoch ||
    !Number.isSafeInteger(input.structuralSequence) ||
    input.structuralSequence < 1 ||
    !Number.isSafeInteger(input.membershipSequence) ||
    input.membershipSequence < 0 ||
    ttl < MIN_PROPOSAL_LIFETIME_SEC ||
    ttl > MAX_PROPOSAL_LIFETIME_SEC
  ) {
    throw new PublicationApprovalError("INVALID_INPUT", "invalid publication proposal parameters");
  }

  const manifest: SignedDesiredEnvelope["manifest"] = {
    schema: "omni.desired-state/v1",
    nodeId: input.nodeUuid,
    controlPlaneEpoch: input.controlPlaneEpoch,
    structuralSequence: input.structuralSequence,
    membershipSequence: input.membershipSequence,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
    disruption: input.disruption,
    payload: input.payload,
  };

  const canonicalManifest = canonicalJson(manifest);
  const manifestDigest = `sha256:${sha256(canonicalManifest)}`;
  const signature = input.sign(canonicalManifest);

  const envelope: SignedDesiredEnvelope = {
    version: "ed25519-jcs-v1",
    keyId: input.keyId,
    manifestDigest,
    signature,
    manifest,
  };

  const envelopeJson = canonicalJson(envelope);
  if (Buffer.byteLength(envelopeJson, "utf8") > MAX_ENVELOPE_BYTES) {
    throw new PublicationApprovalError("INVALID_INPUT", "signed envelope exceeds 1 MiB ceiling");
  }
  const envelopeSha256 = sha256(envelopeJson);
  return { envelope, envelopeJson, envelopeSha256 };
}

export function verifySignedEnvelope(
  envelopeJson: string,
  opts: {
    expectedNodeUuid: string;
    expectedEpoch: string;
    publicKeyPem: string;
    now?: Date;
  },
): { envelope: SignedDesiredEnvelope; envelopeSha256: string } {
  if (!envelopeJson || Buffer.byteLength(envelopeJson, "utf8") > MAX_ENVELOPE_BYTES) {
    throw new PublicationApprovalError("INVALID_INPUT", "invalid or oversized signed envelope");
  }
  let parsed: SignedDesiredEnvelope;
  try {
    parsed = JSON.parse(envelopeJson) as SignedDesiredEnvelope;
  } catch {
    throw new PublicationApprovalError("INVALID_INPUT", "malformed JSON envelope");
  }
  if (
    !parsed ||
    parsed.version !== "ed25519-jcs-v1" ||
    !parsed.manifest ||
    parsed.manifest.schema !== "omni.desired-state/v1" ||
    parsed.manifest.nodeId !== opts.expectedNodeUuid ||
    parsed.manifest.controlPlaneEpoch !== opts.expectedEpoch ||
    !Number.isSafeInteger(parsed.manifest.structuralSequence) ||
    parsed.manifest.structuralSequence < 1 ||
    !Number.isSafeInteger(parsed.manifest.membershipSequence) ||
    parsed.manifest.membershipSequence < 0
  ) {
    throw new PublicationApprovalError("UNAUTHORIZED", "signed envelope metadata or epoch mismatch");
  }

  const canonicalManifest = canonicalJson(parsed.manifest);
  const expectedManifestDigest = `sha256:${sha256(canonicalManifest)}`;
  if (parsed.manifestDigest !== expectedManifestDigest) {
    throw new PublicationApprovalError("UNAUTHORIZED", "manifest digest mismatch");
  }

  try {
    const pubKey = crypto.createPublicKey(opts.publicKeyPem);
    const sigOk = crypto.verify(
      null,
      Buffer.from(canonicalManifest, "utf8"),
      pubKey,
      Buffer.from(parsed.signature, "base64"),
    );
    if (!sigOk) {
      throw new PublicationApprovalError("UNAUTHORIZED", "Ed25519 signature verification failed");
    }
  } catch (e) {
    if (e instanceof PublicationApprovalError) throw e;
    throw new PublicationApprovalError("UNAUTHORIZED", "Ed25519 signature verification failed");
  }

  const now = opts.now ?? new Date();
  const expiresAt = new Date(parsed.manifest.expiresAt);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= now.getTime()) {
    throw new PublicationApprovalError("UNAUTHORIZED", "signed manifest has expired");
  }

  return {
    envelope: parsed,
    envelopeSha256: sha256(envelopeJson),
  };
}

/**
 * Validates second-operator approval against an immutable proposal record.
 */
export function validateDualOperatorApproval(
  proposal: ProposalRecord,
  input: {
    approverAdminId: number;
    approverEmail: string;
    approverRole: string;
    expectedSha256: string;
    now?: Date;
    allowSelfApproval?: boolean;
  },
): NonNullable<ProposalRecord["decision"]> {
  const now = input.now ?? new Date();
  if (!HEX64_PATTERN.test(input.expectedSha256)) {
    throw new PublicationApprovalError("INVALID_INPUT", "Expected SHA-256 must be a 64-character lowercase hex digest");
  }
  if (input.approverRole !== "owner") {
    throw new PublicationApprovalError("UNAUTHORIZED", "Publication approval requires owner role");
  }
  if (input.approverAdminId === proposal.proposerAdminId) {
    throw new PublicationApprovalError(
      "UNAUTHORIZED",
      "Self-approval refused: a distinct second owner administrator must review and approve",
    );
  }
  if (proposal.decision) {
    throw new PublicationApprovalError("CONFLICT", "Proposal has already been reviewed and approved");
  }
  const proposalExpiry = new Date(proposal.expiresAt);
  if (Number.isNaN(proposalExpiry.getTime()) || proposalExpiry.getTime() <= now.getTime()) {
    throw new PublicationApprovalError("UNAUTHORIZED", "Proposal has expired before approval");
  }
  const actualDigest = sha256(proposal.envelopeJson);
  if (actualDigest !== proposal.envelopeSha256 || input.expectedSha256 !== actualDigest) {
    throw new PublicationApprovalError(
      "UNAUTHORIZED",
      "Reviewed SHA-256 digest does not match the immutable signed proposal envelope",
    );
  }

  const approvalExpiryMs = Math.min(
    proposalExpiry.getTime(),
    now.getTime() + MAX_APPROVAL_LIFETIME_SEC * 1000,
  );

  return {
    approvalId: crypto.randomUUID(),
    approverAdminId: input.approverAdminId,
    approverEmail: input.approverEmail,
    reviewedSha256: actualDigest,
    approvedAt: now.toISOString(),
    approvalExpiresAt: new Date(approvalExpiryMs).toISOString(),
    consumedAt: null,
  };
}

/**
 * Validates that an approved proposal is eligible for one-time atomic publication
 * at the node's current head cursor.
 */
export function validateApprovedPublicationWindow(
  proposal: ProposalRecord,
  head: {
    authorizedEpoch: number;
    currentStructuralSeq: number;
    currentMembershipSeq: number;
  },
  now: Date = new Date(),
  opts?: { allowSelfApproval?: boolean },
): void {
  if (!proposal.decision) {
    throw new PublicationApprovalError("UNAUTHORIZED", "Proposal has no independent second-owner approval decision");
  }
  if (proposal.decision.consumedAt !== null) {
    throw new PublicationApprovalError("UNAUTHORIZED", "Publication approval has already been consumed (replay refused)");
  }
  if (proposal.proposerAdminId === proposal.decision.approverAdminId) {
    throw new PublicationApprovalError("UNAUTHORIZED", "Dual-operator separation invariant violated");
  }
  const proposalExp = new Date(proposal.expiresAt);
  const approvalExp = new Date(proposal.decision.approvalExpiresAt);
  if (proposalExp.getTime() <= now.getTime() || approvalExp.getTime() <= now.getTime()) {
    throw new PublicationApprovalError("UNAUTHORIZED", "Publication approval window has expired");
  }
  if (proposal.controlPlaneEpoch !== head.authorizedEpoch) {
    throw new PublicationApprovalError("UNAUTHORIZED", "Proposal epoch does not match authorized control-plane epoch");
  }
  if (proposal.structuralSequence !== head.currentStructuralSeq + 1) {
    throw new PublicationApprovalError(
      "SEQUENCE_CONFLICT",
      `Signed publication sequence #${proposal.structuralSequence} is not next after head #${head.currentStructuralSeq}`,
    );
  }
  if (proposal.membershipSequence < head.currentMembershipSeq) {
    throw new PublicationApprovalError(
      "SEQUENCE_CONFLICT",
      "Signed publication membership cursor cannot regress below current head",
    );
  }
}
