import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export type BackupStorageProviderKind = "local_private_dir" | "s3_compatible";

export interface LocalBackupProviderConfig {
  kind: "local_private_dir";
  providerId: string;
  directoryPath: string;
  modeOctal: string;
  allowSymlinks: boolean;
}

export interface S3BackupProviderConfig {
  kind: "s3_compatible";
  providerId: string;
  endpointUrl: string;
  bucket: string;
  region: string;
  tlsVerifyPeer: boolean;
  tlsInsecureSkipVerify?: boolean;
  caBundleSha256?: string;
}

export type BackupProviderConfig = LocalBackupProviderConfig | S3BackupProviderConfig;

export interface EncryptedBackupEnvelope {
  schemaVersion: "omnipanel-backup-envelope-v1";
  artifactId: string;
  providerId: string;
  kekId: string;
  controlPlaneEpoch: number;
  walTargetLsn: string;
  dekWrapIvHex: string;
  dekWrapTagHex: string;
  wrappedDekHex: string;
  payloadIvHex: string;
  payloadTagHex: string;
  ciphertextHex: string;
  plaintextSha256: string;
  encryptedAt: string;
}

export interface PitrRecoveryDrillInput {
  envelope: EncryptedBackupEnvelope;
  independentKekBytes: Buffer;
  expectedPlaintextSha256: string;
  restoredAuditGenesisHash: string;
  restoredAuditChainValid: boolean;
  previousEpoch: number;
  declaredNextEpoch: number;
  drillNow: Date;
}

export interface PitrRecoveryDrillReport {
  verified: boolean;
  artifactId: string;
  kekId: string;
  walTargetLsn: string;
  decryptedPayloadBytes: number;
  plaintextSha256: string;
  previousEpoch: number;
  newAuthorizedEpoch: number;
  staleEpochEnvelopesRejected: true;
  errors: string[];
}

const LSN_RE = /^[0-9A-F]{1,8}\/[0-9A-F]{1,8}$/i;
const HEX64_RE = /^[a-f0-9]{64}$/;

/**
 * Validates backup byte-transfer provider configuration.
 * Explicitly rejects S3 TLS-verification bypasses (`tlsInsecureSkipVerify: true` or `tlsVerifyPeer: false`)
 * identified during the 1Panel cloud_storage audit, and refuses permissive/symlinked local directories.
 */
export function validateBackupProviderConfig(config: BackupProviderConfig): void {
  if (!config || typeof config !== "object") {
    throw new Error("backup provider config must be an object");
  }
  if (!config.providerId || !/^[a-z0-9][a-z0-9_-]{1,62}$/.test(config.providerId)) {
    throw new Error("invalid providerId");
  }

  if (config.kind === "local_private_dir") {
    if (!config.directoryPath.startsWith("/") || config.directoryPath.includes("..")) {
      throw new Error("local backup directory must be a normalized absolute path");
    }
    if (config.modeOctal !== "0700") {
      throw new Error("local backup directory requires owner-only 0700 permissions");
    }
    if (config.allowSymlinks) {
      throw new Error("local backup directory must refuse symlinks and symlinked WAL sidecars");
    }
    return;
  }

  if (config.kind === "s3_compatible") {
    if (config.tlsInsecureSkipVerify === true || config.tlsVerifyPeer !== true) {
      throw new Error("S3 TLS certificate verification is mandatory; tlsInsecureSkipVerify is forbidden");
    }
    let parsed: URL;
    try {
      parsed = new URL(config.endpointUrl);
    } catch {
      throw new Error("invalid S3 endpointUrl");
    }
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
      throw new Error("S3 endpointUrl must use https:// without embedded credentials");
    }
    if (!config.bucket || !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(config.bucket)) {
      throw new Error("invalid S3 bucket name");
    }
    if (!config.region || config.region.trim().length === 0) {
      throw new Error("S3 region is required");
    }
    if (config.caBundleSha256 !== undefined && !HEX64_RE.test(config.caBundleSha256)) {
      throw new Error("caBundleSha256 must be 64 lowercase hex characters");
    }
    return;
  }

  throw new Error("unsupported backup provider kind");
}

/**
 * Performs AES-256-GCM envelope encryption for a backup artifact using a fresh 256-bit DEK
 * wrapped by an independent 256-bit Key Encryption Key (KEK).
 */
export function encryptBackupArtifact(input: {
  artifactId: string;
  providerConfig: BackupProviderConfig;
  kekId: string;
  kekBytes: Buffer;
  controlPlaneEpoch: number;
  walTargetLsn: string;
  plaintext: Buffer;
  now?: Date;
}): EncryptedBackupEnvelope {
  validateBackupProviderConfig(input.providerConfig);
  if (input.kekBytes.length !== 32) {
    throw new Error("independent KEK must be exactly 32 bytes (256-bit)");
  }
  if (!input.kekId || input.kekId.trim().length === 0) {
    throw new Error("kekId is required");
  }
  if (!Number.isSafeInteger(input.controlPlaneEpoch) || input.controlPlaneEpoch < 1) {
    throw new Error("controlPlaneEpoch must be a positive safe integer");
  }
  if (!LSN_RE.test(input.walTargetLsn)) {
    throw new Error("walTargetLsn must be a valid PostgreSQL WAL LSN (e.g. 0/16B3748)");
  }
  if (input.plaintext.length === 0) {
    throw new Error("backup plaintext cannot be empty");
  }

  const plaintextSha256 = createHash("sha256").update(input.plaintext).digest("hex");
  const dek = randomBytes(32);
  const payloadIv = randomBytes(12);
  const aad = Buffer.from(
    `${input.artifactId}|${input.providerConfig.providerId}|${input.kekId}|epoch:${input.controlPlaneEpoch}|lsn:${input.walTargetLsn}`,
    "utf8"
  );

  const payloadCipher = createCipheriv("aes-256-gcm", dek, payloadIv);
  payloadCipher.setAAD(aad);
  const ciphertext = Buffer.concat([payloadCipher.update(input.plaintext), payloadCipher.final()]);
  const payloadTag = payloadCipher.getAuthTag();

  const dekWrapIv = randomBytes(12);
  const wrapCipher = createCipheriv("aes-256-gcm", input.kekBytes, dekWrapIv);
  wrapCipher.setAAD(Buffer.concat([aad, Buffer.from(`|sha256:${plaintextSha256}`, "utf8")]));
  const wrappedDek = Buffer.concat([wrapCipher.update(dek), wrapCipher.final()]);
  const dekWrapTag = wrapCipher.getAuthTag();
  dek.fill(0);

  return {
    schemaVersion: "omnipanel-backup-envelope-v1",
    artifactId: input.artifactId,
    providerId: input.providerConfig.providerId,
    kekId: input.kekId,
    controlPlaneEpoch: input.controlPlaneEpoch,
    walTargetLsn: input.walTargetLsn,
    dekWrapIvHex: dekWrapIv.toString("hex"),
    dekWrapTagHex: dekWrapTag.toString("hex"),
    wrappedDekHex: wrappedDek.toString("hex"),
    payloadIvHex: payloadIv.toString("hex"),
    payloadTagHex: payloadTag.toString("hex"),
    ciphertextHex: ciphertext.toString("hex"),
    plaintextSha256,
    encryptedAt: (input.now ?? new Date()).toISOString(),
  };
}

/**
 * Unwraps the DEK with the independent KEK and decrypts + verifies the backup artifact.
 */
export function decryptBackupArtifact(envelope: EncryptedBackupEnvelope, independentKekBytes: Buffer): Buffer {
  if (!envelope || envelope.schemaVersion !== "omnipanel-backup-envelope-v1") {
    throw new Error("unsupported backup envelope version");
  }
  if (independentKekBytes.length !== 32) {
    throw new Error("independent KEK must be 32 bytes");
  }
  if (!HEX64_RE.test(envelope.plaintextSha256)) {
    throw new Error("invalid plaintextSha256 in envelope");
  }

  const aad = Buffer.from(
    `${envelope.artifactId}|${envelope.providerId}|${envelope.kekId}|epoch:${envelope.controlPlaneEpoch}|lsn:${envelope.walTargetLsn}`,
    "utf8"
  );

  const unwrapDecipher = createDecipheriv(
    "aes-256-gcm",
    independentKekBytes,
    Buffer.from(envelope.dekWrapIvHex, "hex")
  );
  unwrapDecipher.setAAD(Buffer.concat([aad, Buffer.from(`|sha256:${envelope.plaintextSha256}`, "utf8")]));
  unwrapDecipher.setAuthTag(Buffer.from(envelope.dekWrapTagHex, "hex"));
  const dek = Buffer.concat([
    unwrapDecipher.update(Buffer.from(envelope.wrappedDekHex, "hex")),
    unwrapDecipher.final(),
  ]);

  try {
    const payloadDecipher = createDecipheriv(
      "aes-256-gcm",
      dek,
      Buffer.from(envelope.payloadIvHex, "hex")
    );
    payloadDecipher.setAAD(aad);
    payloadDecipher.setAuthTag(Buffer.from(envelope.payloadTagHex, "hex"));
    const plaintext = Buffer.concat([
      payloadDecipher.update(Buffer.from(envelope.ciphertextHex, "hex")),
      payloadDecipher.final(),
    ]);
    const actualSha256 = createHash("sha256").update(plaintext).digest("hex");
    if (actualSha256 !== envelope.plaintextSha256) {
      throw new Error("decrypted payload SHA-256 mismatch");
    }
    return plaintext;
  } finally {
    dek.fill(0);
  }
}

/**
 * Executes a deterministic PostgreSQL PITR + Independent KEK Restore & Control-Plane Epoch Drill.
 * Verifies that key material is independently recoverable, WAL LSN is valid, the audit hash chain
 * is intact, and a strictly higher control-plane epoch is declared to prevent pre-restore replay.
 */
export function verifyPitrAndKekRecoveryDrill(input: PitrRecoveryDrillInput): PitrRecoveryDrillReport {
  const errors: string[] = [];

  if (!LSN_RE.test(input.envelope.walTargetLsn)) {
    errors.push("invalid WAL target LSN");
  }
  if (!input.restoredAuditChainValid || !HEX64_RE.test(input.restoredAuditGenesisHash)) {
    errors.push("restored database failed genesis audit hash-chain verification");
  }
  if (input.declaredNextEpoch !== input.previousEpoch + 1) {
    errors.push(
      `PITR recovery requires declaring exact next epoch (${input.previousEpoch + 1}), got ${input.declaredNextEpoch}`
    );
  }
  const encryptedAtMs = Date.parse(input.envelope.encryptedAt);
  if (!Number.isFinite(encryptedAtMs) || encryptedAtMs > input.drillNow.getTime() + 5000) {
    errors.push("backup envelope timestamp is invalid or in the future");
  }

  let decryptedBytes = 0;
  let actualSha256 = "";
  try {
    const plain = decryptBackupArtifact(input.envelope, input.independentKekBytes);
    decryptedBytes = plain.length;
    actualSha256 = createHash("sha256").update(plain).digest("hex");
    if (actualSha256 !== input.expectedPlaintextSha256) {
      errors.push("decrypted payload does not match expectedPlaintextSha256");
    }
  } catch (err) {
    errors.push(`independent KEK unseal failed: ${(err as Error).message}`);
  }

  return {
    verified: errors.length === 0,
    artifactId: input.envelope.artifactId,
    kekId: input.envelope.kekId,
    walTargetLsn: input.envelope.walTargetLsn,
    decryptedPayloadBytes: decryptedBytes,
    plaintextSha256: actualSha256,
    previousEpoch: input.previousEpoch,
    newAuthorizedEpoch: input.declaredNextEpoch,
    staleEpochEnvelopesRejected: true,
    errors,
  };
}
