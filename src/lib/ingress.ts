import ipaddr from "ipaddr.js";

/** Planning only: allocation must also be serialized in PostgreSQL and preflighted on-host. */
export type Listener = {
  nodeId: string;
  owner: string;
  address: string;
  transport: "tcp" | "udp";
  port: number;
  // Required explicitly; never infer the host's net.ipv6.bindv6only setting.
  ipv6Only: boolean;
};

function parse(listener: Listener) {
  if (!listener.nodeId || !listener.owner || !Number.isInteger(listener.port) || listener.port < 1 || listener.port > 65535 ||
      !["tcp", "udp"].includes(listener.transport) || typeof listener.ipv6Only !== "boolean" ||
      listener.address.includes("%") || !ipaddr.isValid(listener.address)) {
    throw new Error("Invalid listener: explicit literal IP, node, owner, transport, port and IPv6 policy required");
  }
  const ip = ipaddr.parse(listener.address);
  // Mapped addresses inherit IPv4 conflicts. v6-only cannot bind a mapped address.
  if (ip.kind() === "ipv6" && (ip as ipaddr.IPv6).isIPv4MappedAddress()) {
    if (listener.ipv6Only) throw new Error("IPv4-mapped binding cannot be IPv6-only");
    return (ip as ipaddr.IPv6).toIPv4Address();
  }
  if (ip.kind() === "ipv4" && listener.ipv6Only) throw new Error("IPv4 binding cannot be IPv6-only");
  return ip;
}

export function listenersConflict(a: Listener, b: Listener): boolean {
  const left = parse(a), right = parse(b);
  if (a.nodeId !== b.nodeId || a.transport !== b.transport || a.port !== b.port) return false;
  const any = (ip: ipaddr.IPv4 | ipaddr.IPv6) => ip.toByteArray().every((byte) => byte === 0);
  if (left.kind() === right.kind()) {
    return any(left) || any(right) || left.toNormalizedString() === right.toNormalizedString();
  }
  // An IPv6 wildcard with IPV6_V6ONLY=0 also owns all IPv4 bindings.
  return (left.kind() === "ipv6" && any(left) && !a.ipv6Only) ||
    (right.kind() === "ipv6" && any(right) && !b.ipv6Only);
}

export function planIngress(listeners: Listener[]) {
  listeners.forEach(parse);
  const conflicts: { first: string; second: string; reason: string }[] = [];
  for (let i = 0; i < listeners.length; i++) {
    for (let j = i + 1; j < listeners.length; j++) {
      if (listenersConflict(listeners[i], listeners[j])) {
        conflicts.push({ first: listeners[i].owner, second: listeners[j].owner, reason: "effective_socket_overlap" });
      }
    }
  }
  return { valid: conflicts.length === 0, conflicts };
}
