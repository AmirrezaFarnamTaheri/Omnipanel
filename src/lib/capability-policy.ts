/** Legacy note-only evidence is not sufficient to activate a production runtime. */
export type Claim = "admission" | "metering" | "revocation" | "hardQuota";
export type EvidenceMap = Map<string, "verified" | "failed">;
export type CapabilityPolicy = { key: string; gated: boolean; hardQuotaCandidate: boolean };

// Populated only by a reviewed, pinned runtime integration after its lab gate passes.
// No driver in this checkout currently has that qualification. UI notes cannot bypass it.
const QUALIFIED_BUILDS: ReadonlyMap<string, string> = new Map();

export const hasEvidence = (m: EvidenceMap, key: string, claim: Claim) => m.get(`${key}|${claim}`) === "verified";
export function isAdmissible(cap: CapabilityPolicy, ev: EvidenceMap): boolean {
  return QUALIFIED_BUILDS.has(cap.key) && hasEvidence(ev, cap.key, "admission");
}
export function isHardQuotaCapable(cap: CapabilityPolicy, ev: EvidenceMap): boolean {
  return isAdmissible(cap, ev) && cap.hardQuotaCandidate &&
    (["metering", "revocation", "hardQuota"] as const).every((claim) => hasEvidence(ev, cap.key, claim));
}
