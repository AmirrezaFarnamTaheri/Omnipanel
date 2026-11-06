/**
 * Bounded cursor/tombstone page validation for node inventory synchronization (mirrors internal/agent/syncfeed/page.go).
 * Validates feed structure, contiguous sequence ordering, tombstone semantics, and length-prefixed SHA-256 digests.
 */

import crypto from "node:crypto";

export const MAX_PAGE_RECORDS = 512;
export const MAX_RECORD_ID_BYTES = 256;
export const MAX_RECORD_PAYLOAD_BYTES = 1 << 20; // 1 MiB
export const MAX_PAGE_PAYLOAD_BYTES = 8 << 20; // 8 MiB

export type SyncRecord = {
  sequence: number;
  id: string;
  tombstone: boolean;
  payload: Uint8Array | Buffer;
};

export type SyncPage = {
  baseCursor: number;
  nextCursor: number;
  records: SyncRecord[];
  digest: string;
};

export class SyncFeedError extends Error {
  code: "INVALID_PAGE" | "CURSOR_MISMATCH" | "RESYNC_REQUIRED";
  constructor(code: "INVALID_PAGE" | "CURSOR_MISMATCH" | "RESYNC_REQUIRED", message: string) {
    super(message);
    this.name = "SyncFeedError";
    this.code = code;
  }
}

function writeUint64BE(value: number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(value));
  return buf;
}

/**
 * Hashes each ordered record using unambiguous 64-bit big-endian length-prefixed fields.
 * Byte-identical to internal/agent/syncfeed.Digest in Go.
 */
export function computeSyncPageDigest(records: SyncRecord[]): string {
  const h = crypto.createHash("sha256");
  for (const record of records) {
    const idBuf = Buffer.from(record.id, "utf8");
    const payloadBuf = Buffer.from(record.payload);
    h.update(writeUint64BE(record.sequence));
    h.update(writeUint64BE(idBuf.byteLength));
    h.update(idBuf);
    h.update(Buffer.from([record.tombstone ? 1 : 0]));
    h.update(writeUint64BE(payloadBuf.byteLength));
    h.update(payloadBuf);
  }
  return h.digest("hex");
}

const isNonNegSafeInt = (n: unknown): n is number =>
  typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * Validates a sync feed page against the node's current cursor and returns the new cursor.
 */
export function validateSyncPage(currentCursor: number, page: SyncPage): number {
  if (!isNonNegSafeInt(currentCursor) || !page || !isNonNegSafeInt(page.baseCursor) || !isNonNegSafeInt(page.nextCursor)) {
    throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
  }
  if (currentCursor !== page.baseCursor) {
    throw new SyncFeedError("CURSOR_MISMATCH", "sync feed cursor mismatch");
  }
  if (!Array.isArray(page.records) || page.records.length > MAX_PAGE_RECORDS || page.nextCursor < page.baseCursor) {
    throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
  }
  const expectedNext = page.baseCursor + page.records.length;
  if (!Number.isSafeInteger(expectedNext) || page.nextCursor !== expectedNext) {
    throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
  }

  const seenIds = new Set<string>();
  let totalPayloadBytes = 0;

  for (let i = 0; i < page.records.length; i++) {
    const rec = page.records[i];
    if (!rec || !isNonNegSafeInt(rec.sequence)) {
      throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
    }
    if (rec.sequence !== page.baseCursor + i + 1) {
      throw new SyncFeedError("RESYNC_REQUIRED", "sync feed gap requires full resynchronization");
    }
    const idBytes = Buffer.byteLength(rec.id ?? "", "utf8");
    if (typeof rec.id !== "string" || rec.id.trim() === "" || idBytes > MAX_RECORD_ID_BYTES) {
      throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
    }
    if (seenIds.has(rec.id)) {
      throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
    }
    seenIds.add(rec.id);

    const payloadBytes = rec.payload ? rec.payload.byteLength : 0;
    if (rec.tombstone && payloadBytes !== 0) {
      throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
    }
    if (payloadBytes > MAX_RECORD_PAYLOAD_BYTES) {
      throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
    }
    totalPayloadBytes += payloadBytes;
    if (totalPayloadBytes > MAX_PAGE_PAYLOAD_BYTES) {
      throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page");
    }
  }

  if (page.digest !== computeSyncPageDigest(page.records)) {
    throw new SyncFeedError("INVALID_PAGE", "invalid sync feed page: digest mismatch");
  }

  return page.nextCursor;
}
