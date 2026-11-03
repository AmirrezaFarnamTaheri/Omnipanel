import dns from "node:dns/promises";
import net from "node:net";

/** Immutable base egress policy shipped to every node: user proxy traffic may never reach these. */
export const DENY_CIDRS = [
  "127.0.0.0/8",
  "::1/128",
  "169.254.0.0/16", // link-local + cloud metadata (169.254.169.254)
  "fe80::/10",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
  "fc00::/7",
  "0.0.0.0/8",
];

function ipv4ToInt(ip: string) {
  return ip.split(".").reduce((a, o) => (a << 8) + Number(o), 0) >>> 0;
}

function inCidr4(ip: string, cidr: string) {
  const [base, bits] = cidr.split("/");
  const mask = bits === "0" ? 0 : (~0 << (32 - Number(bits))) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

export function isForbiddenIp(ip: string): boolean {
  if (net.isIPv4(ip)) return DENY_CIDRS.filter((c) => !c.includes(":")).some((c) => inCidr4(ip, c));
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === "::1" || l === "::") return true;
    if (l.startsWith("::ffff:")) return isForbiddenIp(l.slice(7));
    return l.startsWith("fe8") || l.startsWith("fe9") || l.startsWith("fea") || l.startsWith("feb") || /^f[cd]/.test(l);
  }
  return true;
}

/** Validates a node address (IP or hostname) is a public destination. Resolves hostnames. */
export async function resolvePublicAddress(address: string): Promise<string[]> {
  const a = address.trim();
  if (!a || a.length > 253 || /[\s/@?#]/.test(a)) throw new Error("Address must be a bare IP or hostname");
  if (net.isIP(a)) {
    if (isForbiddenIp(a)) throw new Error("Address is loopback, private, link-local or otherwise restricted");
    return [a];
  }
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(a)) {
    throw new Error("Address is not a valid hostname");
  }
  let results: { address: string }[];
  try {
    results = await dns.lookup(a, { all: true });
  } catch {
    // Unresolvable hostnames are allowed to be registered ahead of DNS setup; probing will fail.
    return [];
  }
  if (results.some((r) => isForbiddenIp(r.address))) throw new Error("Hostname resolves to a restricted address");
  return results.map((r) => r.address);
}
