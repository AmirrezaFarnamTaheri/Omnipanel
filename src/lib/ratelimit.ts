type Bucket = { tokens: number; at: number };
const buckets = new Map<string, Bucket>();

/** In-memory token bucket. Separate key namespaces keep public traffic from starving agent traffic. */
export function rateLimit(key: string, capacity: number, refillPerSec: number): boolean {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b) {
    if (buckets.size > 20_000) {
      for (const [k, v] of buckets) if (now - v.at > 60_000) buckets.delete(k);
    }
    b = { tokens: capacity, at: now };
    buckets.set(key, b);
  }
  b.tokens = Math.min(capacity, b.tokens + ((now - b.at) / 1000) * refillPerSec);
  b.at = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}
