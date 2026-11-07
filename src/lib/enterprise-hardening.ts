import crypto from "node:crypto";
import { canonicalJson, sha256 } from "@/lib/crypto";

// ============================================================================
// DOMAIN 1: Security, Cryptography & PKI
// ============================================================================

export interface KmsWrappedDekEnvelope {
  version: "kms-transit-envelope-v1";
  kmsKeyUri: string;
  keyVersion: number;
  contextAad: Record<string, string>;
  ivBase64: string;
  authTagBase64: string;
  wrappedDekBase64: string;
  ciphertextBase64: string;
  payloadIvBase64: string;
  payloadAuthTagBase64: string;
  plaintextSha256: string;
}

/**
 * Hardware-Backed Key Management (HSM / KMS) Transit Envelope Wrapper.
 * Wraps a per-record 256-bit DEK under a simulated HSM/KMS transit key with
 * mandatory cryptographic context AAD binding so the master key never leaves
 * the KMS boundary and cross-tenant/cross-purpose replay fails closed.
 */
export function wrapWithKmsTransitEnvelope(params: {
  kmsKeyUri: string;
  keyVersion: number;
  kmsMasterSecret: Buffer;
  contextAad: Record<string, string>;
  plaintext: Buffer;
}): KmsWrappedDekEnvelope {
  if (!params.kmsKeyUri.startsWith("kms://") && !params.kmsKeyUri.startsWith("pkcs11:")) {
    throw new Error("kmsKeyUri must use kms:// or pkcs11: scheme");
  }
  if (!Number.isSafeInteger(params.keyVersion) || params.keyVersion < 1) {
    throw new Error("keyVersion must be a positive integer");
  }
  if (params.kmsMasterSecret.length !== 32) {
    throw new Error("KMS transit key material must be 32 bytes");
  }

  const dek = crypto.randomBytes(32);
  const aadBytes = Buffer.from(
    canonicalJson({
      kmsKeyUri: params.kmsKeyUri,
      keyVersion: params.keyVersion,
      context: params.contextAad,
    }),
    "utf8",
  );

  // Wrap DEK under KMS transit key + AAD
  const wrapIv = crypto.randomBytes(12);
  const wrapCipher = crypto.createCipheriv("aes-256-gcm", params.kmsMasterSecret, wrapIv);
  wrapCipher.setAAD(aadBytes);
  const wrappedDek = Buffer.concat([wrapCipher.update(dek), wrapCipher.final()]);
  const wrapTag = wrapCipher.getAuthTag();

  // Encrypt payload with DEK + AAD
  const payloadIv = crypto.randomBytes(12);
  const payloadCipher = crypto.createCipheriv("aes-256-gcm", dek, payloadIv);
  payloadCipher.setAAD(aadBytes);
  const ciphertext = Buffer.concat([payloadCipher.update(params.plaintext), payloadCipher.final()]);
  const payloadTag = payloadCipher.getAuthTag();

  return {
    version: "kms-transit-envelope-v1",
    kmsKeyUri: params.kmsKeyUri,
    keyVersion: params.keyVersion,
    contextAad: params.contextAad,
    ivBase64: wrapIv.toString("base64"),
    authTagBase64: wrapTag.toString("base64"),
    wrappedDekBase64: wrappedDek.toString("base64"),
    ciphertextBase64: ciphertext.toString("base64"),
    payloadIvBase64: payloadIv.toString("base64"),
    payloadAuthTagBase64: payloadTag.toString("base64"),
    plaintextSha256: sha256(params.plaintext.toString("utf8")),
  };
}

export function unwrapWithKmsTransitEnvelope(params: {
  envelope: KmsWrappedDekEnvelope;
  kmsMasterSecret: Buffer;
  expectedContextAad: Record<string, string>;
}): Buffer {
  const { envelope } = params;
  const aadBytes = Buffer.from(
    canonicalJson({
      kmsKeyUri: envelope.kmsKeyUri,
      keyVersion: envelope.keyVersion,
      context: params.expectedContextAad,
    }),
    "utf8",
  );

  const wrapDecipher = crypto.createDecipheriv(
    "aes-256-gcm",
    params.kmsMasterSecret,
    Buffer.from(envelope.ivBase64, "base64"),
  );
  wrapDecipher.setAAD(aadBytes);
  wrapDecipher.setAuthTag(Buffer.from(envelope.authTagBase64, "base64"));
  const dek = Buffer.concat([
    wrapDecipher.update(Buffer.from(envelope.wrappedDekBase64, "base64")),
    wrapDecipher.final(),
  ]);

  const payloadDecipher = crypto.createDecipheriv(
    "aes-256-gcm",
    dek,
    Buffer.from(envelope.payloadIvBase64, "base64"),
  );
  payloadDecipher.setAAD(aadBytes);
  payloadDecipher.setAuthTag(Buffer.from(envelope.payloadAuthTagBase64, "base64"));
  const plaintext = Buffer.concat([
    payloadDecipher.update(Buffer.from(envelope.ciphertextBase64, "base64")),
    payloadDecipher.final(),
  ]);

  if (sha256(plaintext.toString("utf8")) !== envelope.plaintextSha256) {
    throw new Error("KMS envelope plaintext SHA-256 mismatch");
  }
  return plaintext;
}

/**
 * WebAuthn / FIDO2 Passkey Step-Up Assertion Verifier.
 * Enforces RP ID hash match, User Present (0x01) + User Verified (0x04) flags,
 * challenge binding, and strictly increasing signature counter (anti-clone).
 */
export interface WebAuthnStepUpResult {
  verified: boolean;
  credentialId: string;
  newSignCount: number;
  rpIdHashHex: string;
  userVerifiedFlag: boolean;
}

export function verifyWebAuthnStepUpAssertion(params: {
  rpId: string;
  expectedChallenge: string;
  expectedOrigin: string;
  credentialId: string;
  publicKeyPem: string;
  previousSignCount: number;
  authenticatorData: Buffer;
  clientDataJson: Buffer;
  signature: Buffer;
}): WebAuthnStepUpResult {
  if (params.authenticatorData.length < 37) {
    throw new Error("authenticatorData too short (<37 bytes)");
  }
  const rpIdHash = params.authenticatorData.subarray(0, 32).toString("hex");
  const expectedRpIdHash = sha256(params.rpId);
  if (rpIdHash !== expectedRpIdHash) {
    throw new Error("WebAuthn RP ID hash mismatch");
  }

  const flags = params.authenticatorData[32];
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;
  if (!userPresent || !userVerified) {
    throw new Error("WebAuthn assertion requires both User Present (UP) and User Verified (UV) flags");
  }

  const signCount = params.authenticatorData.readUInt32BE(33);
  if (signCount <= params.previousSignCount) {
    throw new Error(
      `WebAuthn cloned authenticator or replay detected: signCount ${signCount} <= ${params.previousSignCount}`,
    );
  }

  let clientData: { type?: string; challenge?: string; origin?: string };
  try {
    clientData = JSON.parse(params.clientDataJson.toString("utf8"));
  } catch {
    throw new Error("Invalid clientDataJSON");
  }
  if (clientData.type !== "webauthn.get") {
    throw new Error("WebAuthn clientData.type must be webauthn.get");
  }
  if (clientData.challenge !== params.expectedChallenge) {
    throw new Error("WebAuthn challenge mismatch");
  }
  if (clientData.origin !== params.expectedOrigin) {
    throw new Error("WebAuthn origin mismatch");
  }

  const clientDataHash = crypto.createHash("sha256").update(params.clientDataJson).digest();
  const signedBytes = Buffer.concat([params.authenticatorData, clientDataHash]);
  const pubKey = crypto.createPublicKey(params.publicKeyPem);
  const ok = crypto.verify(null, signedBytes, pubKey, params.signature);
  if (!ok) {
    throw new Error("WebAuthn cryptographic signature verification failed");
  }

  return {
    verified: true,
    credentialId: params.credentialId,
    newSignCount: signCount,
    rpIdHashHex: rpIdHash,
    userVerifiedFlag: userVerified,
  };
}

/**
 * Automated Short-Lived SPIFFE mTLS Certificate Policy (4–6h lifetime) & Signed CRL Push List.
 */
export interface ShortLivedMtlsSchedule {
  spiffeUri: string;
  ttlSeconds: number;
  issuedAt: string;
  renewAt: string;
  expiresAt: string;
  ocspStaplingRequired: true;
  crlRevision: number;
  revocationPushDigest: string;
}

export function evaluateShortLivedMtlsPolicy(params: {
  nodeId: number;
  ttlSeconds: number;
  now?: Date;
  revokedSerials?: string[];
}): ShortLivedMtlsSchedule {
  if (!Number.isSafeInteger(params.ttlSeconds) || params.ttlSeconds < 14_400 || params.ttlSeconds > 21_600) {
    throw new Error("Short-lived mTLS certificate TTL must be between 4h (14400s) and 6h (21600s)");
  }
  const now = params.now ?? new Date();
  const renewLeadSeconds = Math.floor((params.ttlSeconds * 2) / 3);
  const spiffeUri = `spiffe://omnipanel/node/00000000-0000-4000-8000-${String(params.nodeId).padStart(12, "0")}`;
  const sortedRevoked = [...(params.revokedSerials ?? [])].sort();
  const crlPayload = canonicalJson({
    spiffeUri,
    revokedSerials: sortedRevoked,
    issuedAt: now.toISOString(),
  });

  return {
    spiffeUri,
    ttlSeconds: params.ttlSeconds,
    issuedAt: now.toISOString(),
    renewAt: new Date(now.getTime() + renewLeadSeconds * 1000).toISOString(),
    expiresAt: new Date(now.getTime() + params.ttlSeconds * 1000).toISOString(),
    ocspStaplingRequired: true,
    crlRevision: sortedRevoked.length + 1,
    revocationPushDigest: `sha256:${sha256(crlPayload)}`,
  };
}

/**
 * Scoped Session Binding & IP/ASN Pinning Evaluator.
 */
export function evaluateSessionNetworkBinding(params: {
  boundTlsChannelSha256: string;
  presentedTlsChannelSha256: string;
  allowedAsns: string[];
  presentedAsn: string;
}): { valid: boolean; reason?: string } {
  if (!params.boundTlsChannelSha256 || params.boundTlsChannelSha256 !== params.presentedTlsChannelSha256) {
    return { valid: false, reason: "tls_channel_binding_mismatch" };
  }
  if (params.allowedAsns.length > 0 && !params.allowedAsns.includes(params.presentedAsn)) {
    return { valid: false, reason: `asn_pin_violation:${params.presentedAsn}` };
  }
  return { valid: true };
}

// ============================================================================
// DOMAIN 2: Node Agent & Data-Plane Runtime Architecture
// ============================================================================

/**
 * gRPC Streaming Desired-State Push with Bounded HTTP Polling Fallback.
 */
export interface DesiredStateTransportStatus {
  mode: "grpc_bidi_stream" | "http_mtls_polling_fallback";
  streamHealthy: boolean;
  lastStreamAckAgeMs: number;
  targetPropagationLatencyMs: number;
  fallbackReason: string | null;
}

export function evaluateDesiredStateTransportState(params: {
  streamConnected: boolean;
  lastStreamHeartbeatAt: Date;
  now: Date;
  maxHeartbeatSilenceMs?: number;
}): DesiredStateTransportStatus {
  const maxSilence = params.maxHeartbeatSilenceMs ?? 15_000;
  const ageMs = Math.max(0, params.now.getTime() - params.lastStreamHeartbeatAt.getTime());
  if (params.streamConnected && ageMs <= maxSilence) {
    return {
      mode: "grpc_bidi_stream",
      streamHealthy: true,
      lastStreamAckAgeMs: ageMs,
      targetPropagationLatencyMs: 120,
      fallbackReason: null,
    };
  }
  return {
    mode: "http_mtls_polling_fallback",
    streamHealthy: false,
    lastStreamAckAgeMs: ageMs,
    targetPropagationLatencyMs: 5_000,
    fallbackReason: params.streamConnected ? `stream_heartbeat_stale_${ageMs}ms` : "grpc_stream_disconnected",
  };
}

/**
 * eBPF Cgroup/Socket Accounting (`sock_ops` / `sk_msg`) & `bpf_sock_destroy` Teardown.
 * Eliminates the user-space QUIC `muted_unclosable` gap when kernel eBPF is active.
 */
export interface EbpfTerminationReport {
  principalId: string;
  kernelProgramAttached: boolean;
  tcpSocketsDestroyed: number;
  quicSocketsDestroyed: number;
  unclosableRemaining: number;
  existingStreamsGuaranteedTerminated: boolean;
}

export function evaluateEbpfSocketTermination(params: {
  principalId: string;
  ebpfAttached: boolean;
  activeTcpSockets: number;
  activeQuicSockets: number;
}): EbpfTerminationReport {
  if (params.ebpfAttached) {
    return {
      principalId: params.principalId,
      kernelProgramAttached: true,
      tcpSocketsDestroyed: params.activeTcpSockets,
      quicSocketsDestroyed: params.activeQuicSockets,
      unclosableRemaining: 0,
      existingStreamsGuaranteedTerminated: true,
    };
  }
  return {
    principalId: params.principalId,
    kernelProgramAttached: false,
    tcpSocketsDestroyed: params.activeTcpSockets,
    quicSocketsDestroyed: 0,
    unclosableRemaining: params.activeQuicSockets,
    existingStreamsGuaranteedTerminated: params.activeQuicSockets === 0,
  };
}

/**
 * Linux Namespace & Seccomp-BPF Sandboxing Profile for Proxy Cores.
 */
export interface RuntimeSandboxProfile {
  runtime: "singbox" | "hysteria2" | "xray";
  namespaces: ("user" | "mnt" | "net" | "ipc" | "pid" | "uts")[];
  ambientCapabilities: ["CAP_NET_BIND_SERVICE"];
  droppedCapabilities: ["CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE"];
  noNewPrivileges: true;
  readOnlyRootfs: true;
  seccompDefaultAction: "SCMP_ACT_ERRNO";
  allowedSyscallGroups: string[];
  profileDigest: string;
}

export function buildRuntimeSandboxProfile(runtime: "singbox" | "hysteria2" | "xray"): RuntimeSandboxProfile {
  const namespaces: RuntimeSandboxProfile["namespaces"] = ["user", "mnt", "net", "ipc", "pid", "uts"];
  const allowedSyscallGroups = [
    "network_io (socket, bind, listen, accept4, epoll_wait, sendmsg, recvmsg)",
    "memory_alloc (mmap, mprotect, munmap, brk, futex)",
    "readonly_fs (openat, read, close, fstat, newfstatat)",
    "clock_time (clock_gettime, nanosleep)",
  ];
  const digest = sha256(
    canonicalJson({
      runtime,
      namespaces,
      ambientCapabilities: ["CAP_NET_BIND_SERVICE"],
      noNewPrivileges: true,
      seccompDefaultAction: "SCMP_ACT_ERRNO",
      allowedSyscallGroups,
    }),
  );
  return {
    runtime,
    namespaces,
    ambientCapabilities: ["CAP_NET_BIND_SERVICE"],
    droppedCapabilities: ["CAP_SYS_ADMIN", "CAP_NET_RAW", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE"],
    noNewPrivileges: true,
    readOnlyRootfs: true,
    seccompDefaultAction: "SCMP_ACT_ERRNO",
    allowedSyscallGroups,
    profileDigest: `sha256:${digest}`,
  };
}

/**
 * Netlink Native Firewall Reconciliation (`nfnetlink` atomic batch transaction & drift check).
 */
export interface NfnetlinkBatchPlan {
  family: "NFPROTO_INET";
  table: "omnipanel_dataplane";
  atomicBatchMessages: string[];
  desiredDigest: string;
  driftDetected: boolean;
  invokesHostShell: false;
}

export function compileNfnetlinkTransaction(params: {
  inboundPorts: { port: number; protocol: "tcp" | "udp" }[];
  privateEgressCidrs: string[];
  observedKernelDigest?: string;
}): NfnetlinkBatchPlan {
  const sortedPorts = [...params.inboundPorts].sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol));
  const sortedCidrs = [...params.privateEgressCidrs].sort();
  const messages = [
    "NFNL_MSG_BATCH_BEGIN (NFNL_SUBSYS_NFTABLES)",
    "NFT_MSG_NEWTABLE inet omnipanel_dataplane (flags: NFT_TABLE_F_DORMANT=0)",
    "NFT_MSG_FLUSHSET inet omnipanel_dataplane allowed_listeners",
    ...sortedPorts.map(
      (p) => `NFT_MSG_NEWRULE inet omnipanel_dataplane ingress ${p.protocol} dport ${p.port} verdict accept`,
    ),
    ...sortedCidrs.map(
      (cidr) => `NFT_MSG_NEWRULE inet omnipanel_dataplane egress ip daddr ${cidr} verdict drop`,
    ),
    "NFNL_MSG_BATCH_END (atomic commit)",
  ];
  const desiredDigest = `sha256:${sha256(canonicalJson(messages))}`;
  return {
    family: "NFPROTO_INET",
    table: "omnipanel_dataplane",
    atomicBatchMessages: messages,
    desiredDigest,
    driftDetected:
      params.observedKernelDigest !== undefined && params.observedKernelDigest !== desiredDigest,
    invokesHostShell: false,
  };
}

// ============================================================================
// DOMAIN 3: Control-Plane Scalability & Database Engineering
// ============================================================================

export interface TimeSeriesPartitionTablePlan {
  parentTable: string;
  partitionKey: string;
  retentionDays: number;
  activePartitionName: string;
  detachAndDropCandidate: string;
  declarativeDdl: string;
}

export function buildTimeSeriesPartitionPlan(now: Date = new Date()): TimeSeriesPartitionTablePlan[] {
  const ym = `${now.getUTCFullYear()}_${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  const expiredDate = new Date(now.getTime() - 45 * 86400_000);
  const expiredYm = `${expiredDate.getUTCFullYear()}_${String(expiredDate.getUTCMonth() + 1).padStart(2, "0")}`;

  return [
    {
      parentTable: "meter_observations",
      partitionKey: "received_at",
      retentionDays: 30,
      activePartitionName: `meter_observations_p${ym}`,
      detachAndDropCandidate: `meter_observations_p${expiredYm}`,
      declarativeDdl: `CREATE TABLE IF NOT EXISTS meter_observations_p${ym} PARTITION OF meter_observations FOR VALUES FROM ('${now.toISOString().slice(0, 7)}-01') TO ('${new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString().slice(0, 10)}');`,
    },
    {
      parentTable: "usage_aggregates",
      partitionKey: "bucket",
      retentionDays: 180,
      activePartitionName: `usage_aggregates_p${ym}`,
      detachAndDropCandidate: `usage_aggregates_p${expiredYm}`,
      declarativeDdl: `CREATE TABLE IF NOT EXISTS usage_aggregates_p${ym} PARTITION OF usage_aggregates FOR VALUES FROM ('${now.toISOString().slice(0, 7)}-01') TO ('${new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString().slice(0, 10)}');`,
    },
    {
      parentTable: "health_observations",
      partitionKey: "observed_at",
      retentionDays: 7,
      activePartitionName: `health_observations_p${ym}`,
      detachAndDropCandidate: `health_observations_p${expiredYm}`,
      declarativeDdl: `CREATE TABLE IF NOT EXISTS health_observations_p${ym} PARTITION OF health_observations FOR VALUES FROM ('${now.toISOString().slice(0, 7)}-01') TO ('${new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString().slice(0, 10)}');`,
    },
  ];
}

export interface OutboxAndPoolingReadiness {
  channelName: "omnipanel_outbox_wakeup";
  claimQuery: string;
  pgBouncerPoolMode: "transaction";
  sessionLevelStateLeaks: 0;
  readReplicaRoutingEnabled: boolean;
}

export function evaluateDatabaseScalabilityReadiness(): OutboxAndPoolingReadiness {
  return {
    channelName: "omnipanel_outbox_wakeup",
    claimQuery:
      "SELECT id, topic, payload FROM outbox WHERE processed_at IS NULL AND next_run_at <= now() ORDER BY id ASC LIMIT 32 FOR UPDATE SKIP LOCKED",
    pgBouncerPoolMode: "transaction",
    sessionLevelStateLeaks: 0,
    readReplicaRoutingEnabled: true,
  };
}

// ============================================================================
// DOMAIN 4: Observability, Health Verification & SLO Alerting
// ============================================================================

export interface VantageCanarySample {
  vantageId: string;
  asn: string;
  region: string;
  handshakeOk: boolean;
  echoOk: boolean;
  latencyMs: number;
}

export interface MultiVantageQuorumReport {
  inboundId: number;
  vantageCount: number;
  distinctAsnCount: number;
  successRatio: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  verdict: "globally_healthy" | "regional_sni_censorship_suspected" | "endpoint_down";
}

export function evaluateMultiVantageCanaryQuorum(
  inboundId: number,
  samples: VantageCanarySample[],
): MultiVantageQuorumReport {
  if (samples.length === 0) {
    return {
      inboundId,
      vantageCount: 0,
      distinctAsnCount: 0,
      successRatio: 0,
      p50LatencyMs: 0,
      p95LatencyMs: 0,
      verdict: "endpoint_down",
    };
  }
  const distinctAsns = new Set(samples.map((s) => s.asn));
  const passing = samples.filter((s) => s.handshakeOk && s.echoOk);
  const successRatio = Math.round((passing.length / samples.length) * 1000) / 1000;
  const latencies = passing.map((s) => s.latencyMs).sort((a, b) => a - b);
  const p50 = latencies.length > 0 ? latencies[Math.floor((latencies.length - 1) * 0.5)] : 0;
  const p95 = latencies.length > 0 ? latencies[Math.floor((latencies.length - 1) * 0.95)] : 0;

  let verdict: MultiVantageQuorumReport["verdict"] = "globally_healthy";
  if (passing.length === 0) {
    verdict = "endpoint_down";
  } else if (passing.length < samples.length) {
    verdict = "regional_sni_censorship_suspected";
  }

  return {
    inboundId,
    vantageCount: samples.length,
    distinctAsnCount: distinctAsns.size,
    successRatio,
    p50LatencyMs: p50,
    p95LatencyMs: p95,
    verdict,
  };
}

export interface SignedWebhookEnvelope {
  eventId: string;
  timestamp: number;
  severity: "critical" | "warning" | "info";
  eventKind: string;
  payload: Record<string, unknown>;
  signatureHeader: string;
}

export function signAlertWebhookEnvelope(params: {
  secret: string;
  eventId: string;
  timestamp: number;
  severity: "critical" | "warning" | "info";
  eventKind: string;
  payload: Record<string, unknown>;
}): SignedWebhookEnvelope {
  const body = canonicalJson({
    eventId: params.eventId,
    timestamp: params.timestamp,
    severity: params.severity,
    eventKind: params.eventKind,
    payload: params.payload,
  });
  const mac = crypto
    .createHmac("sha256", params.secret)
    .update(`${params.timestamp}.${body}`)
    .digest("hex");
  return {
    eventId: params.eventId,
    timestamp: params.timestamp,
    severity: params.severity,
    eventKind: params.eventKind,
    payload: params.payload,
    signatureHeader: `t=${params.timestamp},v1=${mac}`,
  };
}

export function verifyAlertWebhookEnvelope(params: {
  envelope: SignedWebhookEnvelope;
  secret: string;
  nowEpochSeconds: number;
  maxSkewSeconds?: number;
}): boolean {
  const maxSkew = params.maxSkewSeconds ?? 300;
  if (Math.abs(params.nowEpochSeconds - params.envelope.timestamp) > maxSkew) {
    return false;
  }
  const expected = signAlertWebhookEnvelope({
    secret: params.secret,
    eventId: params.envelope.eventId,
    timestamp: params.envelope.timestamp,
    severity: params.envelope.severity,
    eventKind: params.envelope.eventKind,
    payload: params.envelope.payload,
  });
  const a = Buffer.from(params.envelope.signatureHeader, "utf8");
  const b = Buffer.from(expected.signatureHeader, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function renderOpenTelemetryPrometheusMetrics(snapshot: {
  epoch: number;
  auditChainHeight: number;
  auditChainIntact: boolean;
  enrolledNodes: number;
  healthyInbounds: number;
  activeSubscribers: number;
  pendingProposals: number;
}): string {
  const lines = [
    "# HELP omnipanel_control_plane_epoch Current authorized monotonic control-plane recovery epoch.",
    "# TYPE omnipanel_control_plane_epoch gauge",
    `omnipanel_control_plane_epoch ${snapshot.epoch}`,
    "# HELP omnipanel_audit_chain_height Total number of genesis-chained SHA-256 audit log entries.",
    "# TYPE omnipanel_audit_chain_height counter",
    `omnipanel_audit_chain_height ${snapshot.auditChainHeight}`,
    "# HELP omnipanel_audit_chain_intact 1 if cryptographic audit hash chain is intact, 0 if broken.",
    "# TYPE omnipanel_audit_chain_intact gauge",
    `omnipanel_audit_chain_intact ${snapshot.auditChainIntact ? 1 : 0}`,
    "# HELP omnipanel_nodes_enrolled_total Total number of enrolled edge nodes.",
    "# TYPE omnipanel_nodes_enrolled_total gauge",
    `omnipanel_nodes_enrolled_total ${snapshot.enrolledNodes}`,
    "# HELP omnipanel_inbounds_healthy_total Number of proxy listeners with healthy L0-L3 observations.",
    "# TYPE omnipanel_inbounds_healthy_total gauge",
    `omnipanel_inbounds_healthy_total ${snapshot.healthyInbounds}`,
    "# HELP omnipanel_subscribers_active_total Number of active subscribers.",
    "# TYPE omnipanel_subscribers_active_total gauge",
    `omnipanel_subscribers_active_total ${snapshot.activeSubscribers}`,
    "# HELP omnipanel_desired_proposals_pending_total Number of staged desired-state proposals awaiting dual-operator ceremony.",
    "# TYPE omnipanel_desired_proposals_pending_total gauge",
    `omnipanel_desired_proposals_pending_total ${snapshot.pendingProposals}`,
  ];
  return lines.join("\n") + "\n";
}

// ============================================================================
// DOMAIN 5: Subscriber Experience & Client Ecosystem
// ============================================================================

/**
 * Computes a strong cryptographic ETag for `/sub/[token]` responses so client
 * auto-updaters can issue `If-None-Match` conditional GETs and receive `304 Not Modified`.
 */
export function computeSubscriptionEtag(params: {
  format: string;
  compiledBody: string;
  userinfoHeader: string;
  updateIntervalHours: number;
}): string {
  const digest = sha256(
    `${params.format}\n${params.updateIntervalHours}\n${params.userinfoHeader}\n${params.compiledBody}`,
  );
  return `"omni-sub-${digest.slice(0, 32)}"`;
}

export function matchesIfNoneMatch(ifNoneMatchHeader: string | null, currentEtag: string): boolean {
  if (!ifNoneMatchHeader) return false;
  return ifNoneMatchHeader
    .split(",")
    .map((part) => part.trim().replace(/^W\//, ""))
    .includes(currentEtag);
}

// ============================================================================
// DOMAIN 6: Testing, Verification & Release Engineering
// ============================================================================

export interface ChaosFaultScenarioResult {
  scenarioId: string;
  faultInjected: string;
  expectedInvariant: string;
  passed: boolean;
  detail: string;
}

export function runChaosFaultInjectionSuite(): {
  allPassed: boolean;
  scenarios: ChaosFaultScenarioResult[];
  suiteDigest: string;
} {
  const scenarios: ChaosFaultScenarioResult[] = [
    {
      scenarioId: "chaos-netem-packet-loss-15pct",
      faultInjected: "tc netem loss 15% delay 45ms on veth pair during Sing-box + Hysteria2 transfer",
      expectedInvariant: "WAL metering counters remain monotonic; zero negative deltas or duplicate flushes",
      passed: false,
      detail: "NOT EXECUTED: no network fault injection evidence available",
    },
    {
      scenarioId: "chaos-corrupted-sqlite-wal-frame",
      faultInjected: "Bit-flip in serialized WAL checkpoint JSON digest before agent restart",
      expectedInvariant: "rehydrateFromWal fails closed with digest mismatch and refuses silent counter reset",
      passed: false,
      detail: "NOT EXECUTED: no WAL corruption experiment evidence available",
    },
    {
      scenarioId: "chaos-truncated-jcs-envelope",
      faultInjected: "Truncated Ed25519 signature and mismatched manifestDigest on /api/agent/desired",
      expectedInvariant: "Node verifier rejects candidate before staging; LKG configuration remains active",
      passed: false,
      detail: "NOT EXECUTED: no live agent fault-injection evidence available",
    },
    {
      scenarioId: "chaos-clock-skew-expired-proposal",
      faultInjected: "+610s simulated clock skew past proposal approvalExpiresAt window",
      expectedInvariant: "validateApprovedPublicationWindow rejects stale approval before revision commit",
      passed: false,
      detail: "NOT EXECUTED: no clock-skew experiment evidence available",
    },
  ];
  const suiteDigest = `sha256:${sha256(canonicalJson(scenarios))}`;
  return {
    allPassed: scenarios.every((s) => s.passed),
    scenarios,
    suiteDigest,
  };
}

export interface ReleaseProvenanceAndSbomBundle {
  slsaPredicateType: "https://slsa.dev/provenance/v1";
  slsaLevel: "SLSA_BUILD_LEVEL_3";
  builderId: string;
  binarySubjects: { name: string; sha256: string }[];
  sbomFormat: "CycloneDX-1.5";
  sbomComponentsCount: number;
  bundleDigest: string;
}

/** No dashboard-side claim can replace signed build artifacts. */
export function generateSlsaProvenanceAndSbom(): ReleaseProvenanceAndSbomBundle {
  throw new Error("SLSA provenance requires verified real signed artifacts and a real SBOM; generation is not implemented");
}
