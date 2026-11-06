import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { and, eq, gt } from "drizzle-orm";
import { db } from "@/db";
import { adminSessions, admins } from "@/db/schema";
import { randomToken, sha256 } from "@/lib/crypto";
import { forbidden, unauthorized } from "@/lib/problem";
import type { Actor } from "@/lib/tx";

const COOKIE = "omni_session";
const IDLE_MS = 2 * 60 * 60 * 1000;
const ABSOLUTE_MS = 12 * 60 * 60 * 1000;

export type Role = "viewer" | "operator" | "owner";
const RANK: Record<Role, number> = { viewer: 1, operator: 2, owner: 3 };

export type AdminSession = { id: number; email: string; role: Role };

const SIGNED_OUT_COOKIE = "omni_signed_out";

export async function createSession(adminId: number) {
  const token = randomToken(32);
  const now = Date.now();
  await db.insert(adminSessions).values({
    adminId,
    tokenHash: sha256(token),
    expiresAt: new Date(now + ABSOLUTE_MS),
  });
  const jar = await cookies();
  const isSecure = process.env.OMNI_INSECURE_COOKIES ? false : (await headers()).get("x-forwarded-proto") === "https";
  jar.delete(SIGNED_OUT_COOKIE);
  jar.set(COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isSecure,
    path: "/",
    maxAge: ABSOLUTE_MS / 1000,
  });
}

export async function destroySession() {
  const jar = await cookies();
  const token = jar.get(COOKIE)?.value;
  if (token) await db.delete(adminSessions).where(eq(adminSessions.tokenHash, sha256(token)));
  jar.delete(COOKIE);
  jar.set(SIGNED_OUT_COOKIE, "1", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 3600,
  });
}

export async function getAdmin(): Promise<AdminSession | null> {
  const jar = await cookies();
  const token = jar.get(COOKIE)?.value;
  if (token) {
    const now = new Date();
    const [row] = await db
      .select({
        sid: adminSessions.id,
        lastSeenAt: adminSessions.lastSeenAt,
        id: admins.id,
        email: admins.email,
        role: admins.role,
      })
      .from(adminSessions)
      .innerJoin(admins, eq(admins.id, adminSessions.adminId))
      .where(and(eq(adminSessions.tokenHash, sha256(token)), gt(adminSessions.expiresAt, now)));
    if (row) {
      if (now.getTime() - row.lastSeenAt.getTime() > IDLE_MS) {
        await db.delete(adminSessions).where(eq(adminSessions.id, row.sid));
        return null;
      }
      if (now.getTime() - row.lastSeenAt.getTime() > 60_000) {
        await db.update(adminSessions).set({ lastSeenAt: now }).where(eq(adminSessions.id, row.sid));
      }
      return { id: row.id, email: row.email, role: row.role as Role };
    }
  }

  // In embedded preview mode (no external DATABASE_URL), default to the active seeded operator
  // unless the user explicitly clicked Sign Out.
  if (!process.env.DATABASE_URL && jar.get(SIGNED_OUT_COOKIE)?.value !== "1") {
    const { settings } = await import("@/db/schema");
    const [activeSetting] = await db.select().from(settings).where(eq(settings.key, "embedded.active_admin_id"));
    const targetId = Number(activeSetting?.value ?? "1") || 1;
    const [fallbackAdmin] = await db.select().from(admins).where(eq(admins.id, targetId));
    if (fallbackAdmin) {
      return {
        id: fallbackAdmin.id,
        email: fallbackAdmin.email,
        role: fallbackAdmin.role as Role,
      };
    }
  }

  return null;
}

export async function requirePage(min: Role = "viewer"): Promise<AdminSession> {
  const a = await getAdmin();
  if (!a) redirect("/login");
  if (RANK[a.role] < RANK[min]) redirect("/");
  return a;
}

/** For server actions and API routes: throws problem errors instead of redirecting. */
export async function requireRole(min: Role): Promise<AdminSession> {
  const a = await getAdmin();
  if (!a) throw unauthorized();
  if (RANK[a.role] < RANK[min]) throw forbidden(`This operation requires the ${min} role`);
  return a;
}

export const actorOf = (a: AdminSession, correlationId?: string): Actor => ({
  label: `admin:${a.email}`,
  adminId: a.id,
  role: a.role,
  correlationId,
});

/** CSRF defence for cookie-authenticated JSON endpoints: Origin must match Host. */
export function assertSameOrigin(req: Request) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return;
  const origin = req.headers.get("origin");
  const host = req.headers.get("host");
  if (!origin || !host || new URL(origin).host !== host) throw forbidden("Cross-origin request rejected");
}

/* Login throttling (in-memory, per email) */
const attempts = new Map<string, { n: number; first: number }>();
export function loginThrottled(email: string) {
  const a = attempts.get(email);
  if (!a) return false;
  if (Date.now() - a.first > 15 * 60_000) {
    attempts.delete(email);
    return false;
  }
  return a.n >= 5;
}
export function noteLoginFailure(email: string) {
  const a = attempts.get(email);
  if (!a || Date.now() - a.first > 15 * 60_000) attempts.set(email, { n: 1, first: Date.now() });
  else a.n++;
}
export const clearLoginFailures = (email: string) => attempts.delete(email);
