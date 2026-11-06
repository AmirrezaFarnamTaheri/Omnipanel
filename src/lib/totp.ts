import crypto from "node:crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) continue;
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export const newTotpSecret = () => base32Encode(crypto.randomBytes(20));
export const generateTotpSecret = newTotpSecret;

export function hotp(secret: string, counter: number) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", base32Decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 15;
  const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

export function generateTotp(secret: string, now = Date.now()): string {
  return hotp(secret, Math.floor(now / 30_000));
}

export function verifyTotpMatchedStep(secret: string, code: string, now = Date.now()): number | null {
  const c = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(c)) return null;
  const step = Math.floor(now / 30_000);
  for (const d of [-1, 0, 1]) {
    const candidateStep = step + d;
    if (crypto.timingSafeEqual(Buffer.from(hotp(secret, candidateStep)), Buffer.from(c))) {
      return candidateStep;
    }
  }
  return null;
}

export function verifyTotp(secret: string, code: string, now = Date.now()): boolean {
  return verifyTotpMatchedStep(secret, code, now) !== null;
}

export const otpauthUri = (email: string, secret: string) =>
  `otpauth://totp/OmniPanel:${encodeURIComponent(email)}?secret=${secret}&issuer=OmniPanel`;
