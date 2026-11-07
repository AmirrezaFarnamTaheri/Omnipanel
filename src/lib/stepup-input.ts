import { ProblemError } from "@/lib/problem";

/** Parses mandatory fresh credential input for high-risk owner actions.
 * It never trims, transforms or logs the original secret. */
export function requireStepUpPassword(fd: FormData): string {
  const password = fd.get("password");
  if (typeof password !== "string" || password.length === 0) {
    throw new ProblemError(401, "Unauthorized", "Step-up required: current password is mandatory");
  }
  return password;
}
