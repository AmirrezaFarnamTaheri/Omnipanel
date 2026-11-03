import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { eq } from "drizzle-orm";
import { db } from "@/db";
import { settings } from "@/db/schema";

/* ---------- Key-encryption key (envelope encryption of stored secrets) ---------- */

let kekCache: Buffer | null = null;

function getKek(): Buffer {
  if (kekCache) return kekCache;
  const fromEnv = process.env.OMNI_KEK;
  if (fromEnv) {
    const buf = Buffer.from(fromEnv, "base64");
    if (buf.length !== 32) throw new Error("OMNI_KEK must be 32 bytes, base64 encoded");
    kekCache = buf;
    return buf;
  }
  // Development fallback: a KEK kept outside the database, in a separate file.
  const dir = path.join(process.cwd(), ".data");
  const file = path.join(dir, "kek");
  if (fs.existsSync(file)) {
    kekCache = Buffer.from(fs.readFileSync(file, "utf8").trim(), "base64");
  } else {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const k = crypto.randomBytes(32);
    fs.writeFileSync(file, k.toString("base64"), { mode: 0o600 });
    kekCache = k;
  }
  return kekCache;
}

export function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getKek(), iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64"), cipher.getAuthTag().toString("base64"), ct.toString("base64")].join(".");
}

export function decryptSecret(enc: string): string {
  const [v, iv, tag, ct] = enc.split(".");
  if (v !== "v1") throw new Error("Unsupported secret envelope");
  const d = crypto.createDecipheriv("aes-256-gcm", getKek(), Buffer.from(iv, "base64"));
  d.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(ct, "base64")), d.final()]).toString("utf8");
}

/* ---------- Hashing, tokens, passwords ---------- */

export const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");

export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return `scrypt$${salt.toString("base64")}$${dk.toString("base64")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [alg, salt, hash] = stored.split("$");
  if (alg !== "scrypt") return false;
  const dk = crypto.scryptSync(password, Buffer.from(salt, "base64"), 64, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 128 * 1024 * 1024,
  });
  return safeEqual(dk.toString("base64"), hash);
}

/* ---------- Canonical JSON + manifest signing (Ed25519) ---------- */

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",")}}`;
}

export const digestOf = (value: unknown) => sha256(canonicalJson(value));

async function getSetting(key: string) {
  const [row] = await db.select().from(settings).where(eq(settings.key, key));
  return row?.value;
}

export async function getSigner() {
  let priv = await getSetting("signing_key_enc");
  let pub = await getSetting("signing_key_pub");
  if (!priv || !pub) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    await db
      .insert(settings)
      .values([
        { key: "signing_key_enc", value: encryptSecret(privPem) },
        { key: "signing_key_pub", value: pubPem },
      ])
      .onConflictDoNothing();
    priv = await getSetting("signing_key_enc");
    pub = await getSetting("signing_key_pub");
  }
  const privateKey = crypto.createPrivateKey(decryptSecret(priv!));
  return {
    publicKeyPem: pub!,
    keyId: sha256(pub!).slice(0, 16),
    sign: (payload: unknown) => crypto.sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString("base64"),
  };
}

/* ---------- Credential generators ---------- */

export const newUuid = () => crypto.randomUUID();

export function newRealityKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("x25519");
  const priv = privateKey.export({ format: "jwk" }) as { d: string };
  const pub = publicKey.export({ format: "jwk" }) as { x: string };
  return { privateKey: priv.d, publicKey: pub.x, shortId: crypto.randomBytes(8).toString("hex") };
}
