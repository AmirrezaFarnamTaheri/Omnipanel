export type RuntimeSessionDisposition = "active" | "closed" | "muted_unclosable";

export interface RuntimeSessionRecord {
  sessionId: string;
  principalId: string;
  credentialGeneration: number;
  protocol: "vless-reality-vision" | "hysteria2";
  hasRuntimeCloser: boolean;
  disposition: RuntimeSessionDisposition;
  establishedAt: string;
  lastActivityAt: string;
  revokedAt: string | null;
  revocationReason: string | null;
}

export interface SessionRevocationSummary {
  principalId: string;
  closedCount: number;
  mutedUnclosableCount: number;
  existingStreamsGuaranteedTerminated: boolean;
  newAuthenticationBlocked: true;
  newRoutedFlowsBlocked: true;
  sessionIds: string[];
}

/**
 * Runtime-neutral live session registry (S-UI usersession/registry.go lesson).
 * Distinguishes sessions where the runtime exposes a direct closer (`closed`) from
 * sessions (e.g. multiplexed QUIC/AnyTLS) where existing connections cannot be
 * forcibly terminated without restarting the listener (`muted_unclosable`).
 * Never claims an established stream was terminated when the runtime cannot prove it.
 */
export class LiveSessionRegistry {
  private readonly authorizedGenerations = new Map<string, number>();
  private readonly sessions = new Map<string, RuntimeSessionRecord>();
  private readonly blockedSessionIds = new Set<string>();

  public authorizePrincipal(principalId: string, credentialGeneration: number): void {
    if (!principalId || typeof principalId !== "string") {
      throw new Error("principalId is required");
    }
    if (!Number.isSafeInteger(credentialGeneration) || credentialGeneration < 1) {
      throw new Error("credentialGeneration must be a positive safe integer");
    }
    const prev = this.authorizedGenerations.get(principalId);
    if (prev !== undefined && credentialGeneration < prev) {
      throw new Error("credentialGeneration cannot regress");
    }
    this.authorizedGenerations.set(principalId, credentialGeneration);

    if (prev !== undefined && credentialGeneration > prev) {
      this.revokePrincipal(principalId, `credential_generation_rotated_to_${credentialGeneration}`);
    }
  }

  public registerSession(input: {
    sessionId: string;
    principalId: string;
    credentialGeneration: number;
    protocol: "vless-reality-vision" | "hysteria2";
    hasRuntimeCloser: boolean;
    now?: Date;
  }): RuntimeSessionRecord {
    if (!input.sessionId || typeof input.sessionId !== "string") {
      throw new Error("sessionId is required");
    }
    if (this.blockedSessionIds.has(input.sessionId)) {
      throw new Error("revoked or blocked sessionId cannot be re-admitted; client must re-authenticate");
    }
    const authorizedGen = this.authorizedGenerations.get(input.principalId);
    if (authorizedGen === undefined) {
      throw new Error(`principal ${input.principalId} is not authorized in current membership snapshot`);
    }
    if (input.credentialGeneration !== authorizedGen) {
      throw new Error(
        `stale credentialGeneration ${input.credentialGeneration} (expected ${authorizedGen})`
      );
    }

    const ts = (input.now ?? new Date()).toISOString();
    const record: RuntimeSessionRecord = {
      sessionId: input.sessionId,
      principalId: input.principalId,
      credentialGeneration: input.credentialGeneration,
      protocol: input.protocol,
      hasRuntimeCloser: input.hasRuntimeCloser,
      disposition: "active",
      establishedAt: ts,
      lastActivityAt: ts,
      revokedAt: null,
      revocationReason: null,
    };
    this.sessions.set(input.sessionId, record);
    return { ...record };
  }

  public canOpenNewFlow(sessionId: string): boolean {
    if (this.blockedSessionIds.has(sessionId)) return false;
    const s = this.sessions.get(sessionId);
    if (!s || s.disposition !== "active") return false;
    const gen = this.authorizedGenerations.get(s.principalId);
    return gen === s.credentialGeneration;
  }

  public revokePrincipal(
    principalId: string,
    reason = "membership_revoked",
    now: Date = new Date()
  ): SessionRevocationSummary {
    this.authorizedGenerations.delete(principalId);
    let closedCount = 0;
    let mutedUnclosableCount = 0;
    const sessionIds: string[] = [];
    const ts = now.toISOString();

    for (const s of this.sessions.values()) {
      if (s.principalId !== principalId) continue;
      this.blockedSessionIds.add(s.sessionId);
      sessionIds.push(s.sessionId);
      if (s.disposition === "active") {
        s.revokedAt = ts;
        s.revocationReason = reason;
        if (s.hasRuntimeCloser) {
          s.disposition = "closed";
          closedCount += 1;
        } else {
          s.disposition = "muted_unclosable";
          mutedUnclosableCount += 1;
        }
      }
    }

    return {
      principalId,
      closedCount,
      mutedUnclosableCount,
      existingStreamsGuaranteedTerminated: mutedUnclosableCount === 0,
      newAuthenticationBlocked: true,
      newRoutedFlowsBlocked: true,
      sessionIds,
    };
  }

  public pruneIdleSessions(maxIdleMs: number, now: Date = new Date()): number {
    if (!Number.isFinite(maxIdleMs) || maxIdleMs < 0) {
      throw new Error("maxIdleMs must be non-negative");
    }
    let pruned = 0;
    const cutoff = now.getTime() - maxIdleMs;
    for (const [id, s] of this.sessions.entries()) {
      if (Date.parse(s.lastActivityAt) < cutoff) {
        this.sessions.delete(id);
        pruned += 1;
      }
    }
    return pruned;
  }

  public snapshot(): RuntimeSessionRecord[] {
    return [...this.sessions.values()].map((s) => ({ ...s }));
  }
}
