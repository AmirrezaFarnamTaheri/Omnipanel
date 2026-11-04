export type ProfileMetadata = {
  title: string;
  supportUrl?: string;
  profileUrl?: string;
  announce?: string;
};

export type ExpiryPresentation = "exclusive" | "inclusive";

const HEADER_CONTROL = /[\u0000-\u001f\u007f]/;

function validHeaderText(value: string, maxLength: number, field: string): string {
  if (value.length === 0 || value.length > maxLength || HEADER_CONTROL.test(value)) {
    throw new TypeError(`invalid ${field}`);
  }
  return value;
}

function validHttpsUrl(value: string, field: string): string {
  validHeaderText(value, 2048, field);
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new TypeError(`invalid ${field}`); }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
    throw new TypeError(`invalid ${field}`);
  }
  return parsed.toString();
}

function base64Utf8(value: string): string {
  return `base64:${Buffer.from(value, "utf8").toString("base64")}`;
}

/** Builds validated, client-facing profile metadata headers without mutating IR. */
export function profileMetadataHeaders(metadata: ProfileMetadata): Record<string, string> {
  const title = validHeaderText(metadata.title, 256, "profile title");
  const headers: Record<string, string> = { "profile-title": base64Utf8(title) };
  if (metadata.supportUrl !== undefined) headers["support-url"] = validHttpsUrl(metadata.supportUrl, "support URL");
  if (metadata.profileUrl !== undefined) headers["profile-web-page-url"] = validHttpsUrl(metadata.profileUrl, "profile URL");
  if (metadata.announce !== undefined) headers.announce = base64Utf8(validHeaderText(metadata.announce, 512, "announce"));
  return headers;
}

/**
 * Formats Subscription-Userinfo for display. The stored expiry remains canonical;
 * the optional inclusive mode only shifts the presented epoch by one second.
 */
export function subscriptionUserinfo(input: {
  uploadBytes: number;
  downloadBytes: number;
  quotaBytes: number | null;
  expiresAt: Date | null;
  expiryPresentation?: ExpiryPresentation;
}): string {
  for (const value of [input.uploadBytes, input.downloadBytes, input.quotaBytes ?? 0]) {
    if (!Number.isFinite(value) || value < 0) throw new TypeError("invalid subscription usage");
  }
  const parts = [
    `upload=${Math.round(input.uploadBytes)}`,
    `download=${Math.round(input.downloadBytes)}`,
    `total=${input.quotaBytes ?? 0}`,
  ];
  if (input.expiresAt !== null) {
    const millis = input.expiresAt.getTime();
    if (!Number.isFinite(millis)) throw new TypeError("invalid subscription expiry");
    const presentation = input.expiryPresentation ?? "exclusive";
    if (presentation !== "exclusive" && presentation !== "inclusive") throw new TypeError("invalid expiry presentation");
    const epochSeconds = Math.floor(millis / 1000) - (presentation === "inclusive" ? 1 : 0);
    parts.push(`expire=${epochSeconds}`);
  }
  return parts.join("; ");
}
