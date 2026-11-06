import { createHash } from "node:crypto";

export type TlsTrustBoundary = "node_mtls" | "acme_public_tls" | "reality_decoy" | "cdn_origin";
export type CertificateLifecycleState = "healthy" | "renewal_due" | "rate_limited_backoff" | "expired" | "revoked";

export interface CertificateInventoryEntry {
  certId: string;
  nodeId: string | null;
  domainOrSan: string;
  boundary: TlsTrustBoundary;
  issuer: string;
  serialHex: string;
  sha256Fingerprint: string;
  notBefore: string;
  notAfter: string;
  autoRenewEnabled: boolean;
  acmeAccountUri?: string;
  failedRenewalAttempts: number;
  nextRetryAt?: string | null;
  revokedAt?: string | null;
  allowInsecureFallback?: boolean;
}

export interface CertificateEvaluation {
  certId: string;
  boundary: TlsTrustBoundary;
  state: CertificateLifecycleState;
  daysRemaining: number;
  recommendedBackoffSeconds: number;
  boundaryIsolated: boolean;
  errors: string[];
}

export interface CertificateInventoryReport {
  valid: boolean;
  inventoryDigest: string;
  counts: Record<CertificateLifecycleState, number>;
  evaluations: CertificateEvaluation[];
  errors: string[];
}

const HEX64_RE = /^[a-f0-9]{64}$/;
const SERIAL_HEX_RE = /^[a-f0-9]{2,64}$/i;
const RENEWAL_WINDOW_DAYS = 30;
const MAX_BACKOFF_SECONDS = 86_400; // 24h cap

/**
 * Evaluates a domain/node certificate inventory entry (Hiddify ACME/TLS boundary lesson).
 * Enforces strict separation between node mTLS, public ACME TLS, Reality decoy handshakes,
 * and CDN origin certificates. Refuses silent insecure or self-signed fallbacks on ACME paths.
 */
export function evaluateCertificateEntry(
  entry: CertificateInventoryEntry,
  now: Date = new Date()
): CertificateEvaluation {
  const errors: string[] = [];

  if (!entry.certId || typeof entry.certId !== "string") {
    errors.push("certId is required");
  }
  if (!["node_mtls", "acme_public_tls", "reality_decoy", "cdn_origin"].includes(entry.boundary)) {
    errors.push(`invalid TLS trust boundary: ${String(entry.boundary)}`);
  }
  if (!entry.domainOrSan || entry.domainOrSan.trim().length === 0) {
    errors.push("domainOrSan is required");
  }
  if (!HEX64_RE.test(entry.sha256Fingerprint)) {
    errors.push("sha256Fingerprint must be 64 lowercase hex characters");
  }
  if (!SERIAL_HEX_RE.test(entry.serialHex)) {
    errors.push("serialHex must be valid hex");
  }
  if (entry.allowInsecureFallback) {
    errors.push("silent insecure or self-signed TLS fallback is forbidden by policy");
  }
  if (entry.boundary === "node_mtls" && !entry.domainOrSan.startsWith("spiffe://omnipanel/node/")) {
    errors.push("node_mtls certificates must carry a spiffe://omnipanel/node/<uuid> URI SAN");
  }
  if (entry.boundary === "reality_decoy" && entry.autoRenewEnabled) {
    errors.push("reality_decoy targets use X25519 keypairs and external SNI; ACME auto-renewal must not run on decoy domains");
  }

  const notBeforeMs = Date.parse(entry.notBefore);
  const notAfterMs = Date.parse(entry.notAfter);
  const nowMs = now.getTime();

  if (!Number.isFinite(notBeforeMs) || !Number.isFinite(notAfterMs) || notAfterMs <= notBeforeMs) {
    errors.push("invalid certificate validity window (notBefore / notAfter)");
  }

  if (!Number.isSafeInteger(entry.failedRenewalAttempts) || entry.failedRenewalAttempts < 0) {
    errors.push("failedRenewalAttempts must be a non-negative integer");
  }

  const daysRemaining = Number.isFinite(notAfterMs)
    ? Math.floor((notAfterMs - nowMs) / (1000 * 60 * 60 * 24))
    : -1;

  const recommendedBackoffSeconds =
    entry.failedRenewalAttempts === 0
      ? 0
      : Math.min(MAX_BACKOFF_SECONDS, 60 * Math.pow(2, Math.min(10, entry.failedRenewalAttempts - 1)));

  let state: CertificateLifecycleState = "healthy";
  if (entry.revokedAt) {
    state = "revoked";
  } else if (nowMs >= notAfterMs) {
    state = "expired";
  } else if (entry.failedRenewalAttempts > 0) {
    state = "rate_limited_backoff";
  } else if (daysRemaining <= RENEWAL_WINDOW_DAYS && entry.boundary !== "reality_decoy") {
    state = "renewal_due";
  }

  return {
    certId: entry.certId,
    boundary: entry.boundary,
    state,
    daysRemaining,
    recommendedBackoffSeconds,
    boundaryIsolated: errors.length === 0,
    errors,
  };
}

export function evaluateCertificateInventory(
  entries: CertificateInventoryEntry[],
  now: Date = new Date()
): CertificateInventoryReport {
  const counts: Record<CertificateLifecycleState, number> = {
    healthy: 0,
    renewal_due: 0,
    rate_limited_backoff: 0,
    expired: 0,
    revoked: 0,
  };
  const errors: string[] = [];
  const seenIds = new Set<string>();
  const evaluations: CertificateEvaluation[] = [];

  for (const entry of entries) {
    if (seenIds.has(entry.certId)) {
      errors.push(`duplicate certId: ${entry.certId}`);
    }
    seenIds.add(entry.certId);
    const ev = evaluateCertificateEntry(entry, now);
    evaluations.push(ev);
    counts[ev.state] += 1;
    for (const err of ev.errors) {
      errors.push(`${entry.certId}: ${err}`);
    }
  }

  const canonical = JSON.stringify(
    entries.map((e) => ({
      certId: e.certId,
      boundary: e.boundary,
      domainOrSan: e.domainOrSan,
      serialHex: e.serialHex.toLowerCase(),
      sha256Fingerprint: e.sha256Fingerprint,
      notAfter: e.notAfter,
      revokedAt: e.revokedAt ?? null,
    }))
  );
  const inventoryDigest = createHash("sha256").update(canonical).digest("hex");

  return {
    valid: errors.length === 0,
    inventoryDigest,
    counts,
    evaluations,
    errors,
  };
}
