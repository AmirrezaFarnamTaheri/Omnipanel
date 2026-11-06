export type ReconcileStage =
  | "RECEIVED"
  | "SIGNATURE_VERIFIED"
  | "VALIDATED"
  | "STAGED"
  | "PREFLIGHTED"
  | "APPLYING"
  | "APPLIED_UNVERIFIED"
  | "VERIFIED"
  | "FAILED"
  | "ROLLING_BACK"
  | "ROLLED_BACK"
  | "DEGRADED_REQUIRES_OPERATOR";

export interface ReconcileJournalState {
  nodeId: string;
  authorizedEpoch: number;
  receivedStructuralSequence: number;
  appliedStructuralSequence: number;
  receivedMembershipSequence: number;
  appliedMembershipSequence: number;
  stage: ReconcileStage;
  candidateDigest: string;
  lastKnownGoodDigest: string | null;
  lastKnownGoodSequence: number;
  watchdogArmed: boolean;
  watchdogDeadlineIso: string | null;
  lastTransitionReason: string;
  updatedAt: string;
}

const ALLOWED_TRANSITIONS: Record<ReconcileStage, ReconcileStage[]> = {
  RECEIVED: ["SIGNATURE_VERIFIED", "FAILED"],
  SIGNATURE_VERIFIED: ["VALIDATED", "FAILED"],
  VALIDATED: ["STAGED", "FAILED"],
  STAGED: ["PREFLIGHTED", "FAILED"],
  PREFLIGHTED: ["APPLYING", "FAILED"],
  APPLYING: ["APPLIED_UNVERIFIED", "FAILED", "ROLLING_BACK"],
  APPLIED_UNVERIFIED: ["VERIFIED", "ROLLING_BACK", "FAILED"],
  VERIFIED: ["RECEIVED"],
  FAILED: ["ROLLING_BACK", "ROLLED_BACK", "DEGRADED_REQUIRES_OPERATOR", "RECEIVED"],
  ROLLING_BACK: ["ROLLED_BACK", "DEGRADED_REQUIRES_OPERATOR"],
  ROLLED_BACK: ["RECEIVED"],
  DEGRADED_REQUIRES_OPERATOR: ["RECEIVED"],
};

/**
 * Journaled Agent Reconciler & Independent Commit-Confirm Watchdog (Task 4 contract).
 * Ensures that:
 * 1. Recording a received/verified manifest never advances `appliedStructuralSequence` or `lastKnownGoodDigest`
 *    until commit-confirm verification completes (`VERIFIED`).
 * 2. Network-affecting transitions arm an independent watchdog deadline (`APPLIED_UNVERIFIED`).
 * 3. If the watchdog deadline expires before management reachability is confirmed, the watchdog
 *    autonomously rolls back to `lastKnownGoodDigest` (`ROLLING_BACK -> ROLLED_BACK`).
 */
export class JournaledReconcileWatchdog {
  private state: ReconcileJournalState;

  public constructor(init: {
    nodeId: string;
    authorizedEpoch: number;
    initialLastKnownGoodDigest?: string | null;
    initialAppliedSequence?: number;
    now?: Date;
  }) {
    if (!init.nodeId) throw new Error("nodeId is required");
    if (!Number.isSafeInteger(init.authorizedEpoch) || init.authorizedEpoch < 1) {
      throw new Error("authorizedEpoch must be a positive safe integer");
    }
    const seq = init.initialAppliedSequence ?? 0;
    const lkg = init.initialLastKnownGoodDigest ?? null;
    this.state = {
      nodeId: init.nodeId,
      authorizedEpoch: init.authorizedEpoch,
      receivedStructuralSequence: seq,
      appliedStructuralSequence: seq,
      receivedMembershipSequence: 0,
      appliedMembershipSequence: 0,
      stage: "VERIFIED",
      candidateDigest: lkg ?? "0".repeat(64),
      lastKnownGoodDigest: lkg,
      lastKnownGoodSequence: seq,
      watchdogArmed: false,
      watchdogDeadlineIso: null,
      lastTransitionReason: "journal_initialized",
      updatedAt: (init.now ?? new Date()).toISOString(),
    };
  }

  public recordReceivedManifest(input: {
    epoch: number;
    structuralSequence: number;
    membershipSequence: number;
    manifestDigest: string;
    now?: Date;
  }): ReconcileJournalState {
    if (input.epoch !== this.state.authorizedEpoch) {
      throw new Error(
        `epoch mismatch: manifest epoch ${input.epoch} !== authorizedEpoch ${this.state.authorizedEpoch}`
      );
    }
    if (input.structuralSequence < this.state.receivedStructuralSequence) {
      throw new Error(
        `structuralSequence regression (${input.structuralSequence} < ${this.state.receivedStructuralSequence})`
      );
    }
    if (
      input.structuralSequence === this.state.receivedStructuralSequence &&
      input.manifestDigest === this.state.candidateDigest
    ) {
      return this.snapshot();
    }
    if (
      input.structuralSequence === this.state.receivedStructuralSequence &&
      input.manifestDigest !== this.state.candidateDigest
    ) {
      throw new Error("conflicting manifest digest for already-recorded structuralSequence");
    }

    this.state = {
      ...this.state,
      receivedStructuralSequence: input.structuralSequence,
      receivedMembershipSequence: Math.max(
        this.state.receivedMembershipSequence,
        input.membershipSequence
      ),
      stage: "SIGNATURE_VERIFIED",
      candidateDigest: input.manifestDigest,
      watchdogArmed: false,
      watchdogDeadlineIso: null,
      lastTransitionReason: `verified_manifest_seq_${input.structuralSequence}`,
      updatedAt: (input.now ?? new Date()).toISOString(),
    };
    return this.snapshot();
  }

  public transitionStage(
    nextStage: ReconcileStage,
    opts?: { reason?: string; watchdogTimeoutSeconds?: number; now?: Date }
  ): ReconcileJournalState {
    const allowed = ALLOWED_TRANSITIONS[this.state.stage] ?? [];
    if (!allowed.includes(nextStage)) {
      throw new Error(`illegal reconcile transition: ${this.state.stage} -> ${nextStage}`);
    }
    const now = opts?.now ?? new Date();
    let watchdogArmed = this.state.watchdogArmed;
    let watchdogDeadlineIso = this.state.watchdogDeadlineIso;
    let appliedStructuralSequence = this.state.appliedStructuralSequence;
    let appliedMembershipSequence = this.state.appliedMembershipSequence;
    let lastKnownGoodDigest = this.state.lastKnownGoodDigest;
    let lastKnownGoodSequence = this.state.lastKnownGoodSequence;

    if (nextStage === "APPLIED_UNVERIFIED") {
      const timeoutSec = opts?.watchdogTimeoutSeconds ?? 60;
      watchdogArmed = true;
      watchdogDeadlineIso = new Date(now.getTime() + timeoutSec * 1000).toISOString();
    } else if (nextStage === "VERIFIED") {
      watchdogArmed = false;
      watchdogDeadlineIso = null;
      appliedStructuralSequence = this.state.receivedStructuralSequence;
      appliedMembershipSequence = this.state.receivedMembershipSequence;
      lastKnownGoodDigest = this.state.candidateDigest;
      lastKnownGoodSequence = this.state.receivedStructuralSequence;
    } else if (nextStage === "ROLLED_BACK") {
      watchdogArmed = false;
      watchdogDeadlineIso = null;
      appliedStructuralSequence = this.state.lastKnownGoodSequence;
    }

    this.state = {
      ...this.state,
      stage: nextStage,
      appliedStructuralSequence,
      appliedMembershipSequence,
      lastKnownGoodDigest,
      lastKnownGoodSequence,
      watchdogArmed,
      watchdogDeadlineIso,
      lastTransitionReason: opts?.reason ?? `transition_to_${nextStage}`,
      updatedAt: now.toISOString(),
    };
    return this.snapshot();
  }

  /**
   * Simulates the independent commit-confirm watchdog process checking whether an
   * `APPLIED_UNVERIFIED` network/listener change timed out without management confirmation.
   */
  public evaluateIndependentWatchdogTick(now: Date = new Date()): {
    triggeredRollback: boolean;
    state: ReconcileJournalState;
  } {
    if (
      this.state.stage !== "APPLIED_UNVERIFIED" ||
      !this.state.watchdogArmed ||
      !this.state.watchdogDeadlineIso
    ) {
      return { triggeredRollback: false, state: this.snapshot() };
    }

    const deadlineMs = Date.parse(this.state.watchdogDeadlineIso);
    if (now.getTime() < deadlineMs) {
      return { triggeredRollback: false, state: this.snapshot() };
    }

    // Watchdog deadline expired without commit-confirm!
    this.transitionStage("ROLLING_BACK", {
      reason: "watchdog_commit_confirm_timeout",
      now,
    });

    if (this.state.lastKnownGoodDigest) {
      this.transitionStage("ROLLED_BACK", {
        reason: `restored_last_known_good_seq_${this.state.lastKnownGoodSequence}`,
        now,
      });
    } else {
      this.transitionStage("DEGRADED_REQUIRES_OPERATOR", {
        reason: "no_last_known_good_generation_available",
        now,
      });
    }

    return { triggeredRollback: true, state: this.snapshot() };
  }

  public snapshot(): ReconcileJournalState {
    return { ...this.state };
  }
}
