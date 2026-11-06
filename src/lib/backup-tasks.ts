/**
 * Provider-neutral backup and restore lifecycle contract (mirrors internal/backup/task.go).
 * Enforces explicit state transitions, monotonic timestamps, retry counters, and mandatory SHA-256 digests.
 */

export type BackupTaskState =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "verifying_restore"
  | "restored";

export type BackupTaskKind = "backup" | "restore";

export type BackupTask = {
  id: string;
  kind: BackupTaskKind;
  state: BackupTaskState;
  attempt: number;
  createdAt: Date;
  updatedAt: Date;
  artifactDigest: string;
  errorCode: string;
};

export class InvalidBackupTaskError extends Error {
  constructor(message = "invalid backup task") {
    super(message);
    this.name = "InvalidBackupTaskError";
  }
}

export class InvalidBackupTransitionError extends Error {
  constructor(message = "invalid backup task transition") {
    super(message);
    this.name = "InvalidBackupTransitionError";
  }
}

const VALID_STATES: ReadonlySet<BackupTaskState> = new Set([
  "queued",
  "running",
  "succeeded",
  "failed",
  "verifying_restore",
  "restored",
]);

export function validateBackupTask(t: BackupTask): void {
  if (
    !t ||
    typeof t.id !== "string" ||
    t.id.trim() === "" ||
    t.id.length > 128 ||
    (t.kind !== "backup" && t.kind !== "restore") ||
    !VALID_STATES.has(t.state) ||
    !Number.isInteger(t.attempt) ||
    t.attempt <= 0 ||
    !(t.createdAt instanceof Date) ||
    Number.isNaN(t.createdAt.getTime()) ||
    !(t.updatedAt instanceof Date) ||
    Number.isNaN(t.updatedAt.getTime()) ||
    t.updatedAt.getTime() < t.createdAt.getTime()
  ) {
    throw new InvalidBackupTaskError();
  }
  if (
    typeof t.artifactDigest !== "string" ||
    t.artifactDigest.length > 128 ||
    typeof t.errorCode !== "string" ||
    t.errorCode.length > 64 ||
    /[\r\n]/.test(t.errorCode)
  ) {
    throw new InvalidBackupTaskError();
  }
  if ((t.state === "succeeded" || t.state === "restored") && t.artifactDigest === "") {
    throw new InvalidBackupTaskError("invalid backup task: successful task requires artifact digest");
  }
  if (t.state === "failed" && t.errorCode === "") {
    throw new InvalidBackupTaskError("invalid backup task: failed task requires error code");
  }
}

export function createBackupTask(id: string, kind: BackupTaskKind, now: Date = new Date()): BackupTask {
  const ts = new Date(now.getTime());
  const task: BackupTask = {
    id,
    kind,
    state: "queued",
    attempt: 1,
    createdAt: ts,
    updatedAt: ts,
    artifactDigest: "",
    errorCode: "",
  };
  validateBackupTask(task);
  return task;
}

export function advanceBackupTask(
  task: BackupTask,
  next: BackupTaskState,
  now: Date = new Date(),
  artifactDigest = "",
  errorCode = "",
): BackupTask {
  validateBackupTask(task);
  if (!(now instanceof Date) || Number.isNaN(now.getTime()) || now.getTime() < task.updatedAt.getTime()) {
    throw new InvalidBackupTransitionError("invalid backup task transition: clock moved backwards");
  }

  let allowed = false;
  switch (task.state) {
    case "queued":
      allowed = next === "running";
      break;
    case "running":
      allowed =
        next === "succeeded" ||
        next === "failed" ||
        (task.kind === "restore" && next === "verifying_restore");
      break;
    case "failed":
      allowed = next === "queued";
      break;
    case "verifying_restore":
      allowed = next === "restored" || next === "failed";
      break;
    case "succeeded":
    case "restored":
      allowed = false;
      break;
  }

  if (!allowed) {
    throw new InvalidBackupTransitionError(`invalid backup task transition: ${task.state} to ${next}`);
  }

  const updated: BackupTask = {
    ...task,
    state: next,
    updatedAt: new Date(now.getTime()),
    artifactDigest: next === "queued" ? "" : artifactDigest,
    errorCode: next === "queued" ? "" : errorCode,
    attempt: next === "queued" ? task.attempt + 1 : task.attempt,
  };
  validateBackupTask(updated);
  return updated;
}
