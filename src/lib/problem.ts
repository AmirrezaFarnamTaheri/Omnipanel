import { randomUUID } from "node:crypto";

/** RFC 9457 problem details error. */
export class ProblemError extends Error {
  status: number;
  title: string;
  extra: Record<string, unknown>;
  constructor(status: number, title: string, detail?: string, extra: Record<string, unknown> = {}) {
    super(detail ?? title);
    this.status = status;
    this.title = title;
    this.extra = extra;
  }
}

export const notFound = (what: string) => new ProblemError(404, "Not found", `${what} was not found`);
export const conflict = (detail: string, extra?: Record<string, unknown>) =>
  new ProblemError(409, "Conflict", detail, extra);
export const invalid = (detail: string, extra?: Record<string, unknown>) =>
  new ProblemError(422, "Validation failed", detail, extra);
export const forbidden = (detail = "You do not have permission for this operation") =>
  new ProblemError(403, "Forbidden", detail);
export const unauthorized = (detail = "Authentication required") => new ProblemError(401, "Unauthorized", detail);

export function problemResponse(err: unknown, correlationId: string = randomUUID()): Response {
  const p =
    err instanceof ProblemError
      ? err
      : new ProblemError(500, "Internal error", "The request could not be completed");
  if (!(err instanceof ProblemError)) console.error(`[${correlationId}]`, err instanceof Error ? err.message : "error");
  return new Response(
    JSON.stringify({
      type: "about:blank",
      title: p.title,
      status: p.status,
      detail: p.message,
      correlationId,
      ...p.extra,
    }),
    {
      status: p.status,
      headers: {
        "content-type": "application/problem+json",
        "cache-control": "no-store",
        "x-correlation-id": correlationId,
      },
    },
  );
}

/** Wrap route handlers with correlation-id + RFC 9457 error handling. */
export function handle<A extends unknown[]>(fn: (req: Request, correlationId: string, ...rest: A) => Promise<Response>) {
  return async (req: Request, ...rest: A): Promise<Response> => {
    const cid = req.headers.get("x-correlation-id")?.slice(0, 64) || randomUUID();
    try {
      const res = await fn(req, cid, ...rest);
      res.headers.set("x-correlation-id", cid);
      return res;
    } catch (e) {
      return problemResponse(e, cid);
    }
  };
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
}
