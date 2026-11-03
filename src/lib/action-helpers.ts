import { ProblemError } from "@/lib/problem";

export type ActionState = {
  ok?: boolean;
  error?: string;
  message?: string;
  secret?: { label: string; value: string; hint?: string };
};

/** Runs a server-action body, converting problem errors into inline form feedback. */
export async function act(fn: () => Promise<ActionState | void>): Promise<ActionState> {
  try {
    const r = await fn();
    return { ok: true, ...(r ?? {}) };
  } catch (e) {
    // Next.js redirect/notFound signals must propagate
    if (e && typeof e === "object" && "digest" in e && String((e as { digest: unknown }).digest).startsWith("NEXT_")) throw e;
    if (e instanceof ProblemError) return { ok: false, error: e.message };
    const code = (e as { code?: string; constraint?: string })?.code;
    if (code === "23505") return { ok: false, error: "That value already exists (unique constraint)." };
    console.error("action failed", e instanceof Error ? e.message : e);
    return { ok: false, error: "The operation failed unexpectedly." };
  }
}

export const str = (fd: FormData, k: string) => String(fd.get(k) ?? "").trim();
export const int = (fd: FormData, k: string) => {
  const n = Number(fd.get(k));
  return Number.isFinite(n) ? Math.trunc(n) : NaN;
};
