"use server";

import { eq, sql } from "drizzle-orm";
import { redirect } from "next/navigation";
import { db } from "@/db";
import { admins } from "@/db/schema";
import { audit } from "@/lib/audit";
import {
  clearLoginFailures,
  createSession,
  destroySession,
  loginThrottled,
  noteLoginFailure,
  requireRole,
} from "@/lib/auth";
import { decryptSecret, encryptSecret, hashPassword, verifyPassword } from "@/lib/crypto";
import { newTotpSecret, otpauthUri, verifyTotp } from "@/lib/totp";
import { ProblemError } from "@/lib/problem";
import { act, str, type ActionState } from "@/lib/action-helpers";

const DUMMY_HASH = hashPassword("dummy-password-for-timing");

export async function setupAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const email = str(fd, "email").toLowerCase();
    const password = String(fd.get("password") ?? "");
    const setupToken = process.env.OMNI_SETUP_TOKEN;
    if (setupToken && str(fd, "setupToken") !== setupToken) throw new ProblemError(403, "Forbidden", "Invalid setup token");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new ProblemError(422, "Validation failed", "Enter a valid email");
    if (password.length < 12) throw new ProblemError(422, "Validation failed", "Password must be at least 12 characters");
    if (password !== String(fd.get("confirm") ?? "")) throw new ProblemError(422, "Validation failed", "Passwords do not match");
    const id = await db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(7002)`);
      const existing = await tx.select({ id: admins.id }).from(admins).limit(1);
      if (existing.length) throw new ProblemError(409, "Conflict", "Setup has already been completed");
      const [a] = await tx.insert(admins).values({ email, passwordHash: hashPassword(password), role: "owner" }).returning();
      await audit(tx, { label: `admin:${email}` }, "admin.bootstrap", "admin", a.id, {});
      return a.id;
    });
    await createSession(id);
    redirect("/");
  });
}

export async function loginAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const email = str(fd, "email").toLowerCase();
    const password = String(fd.get("password") ?? "");
    if (loginThrottled(email)) throw new ProblemError(429, "Too many attempts", "Too many failed attempts. Try again in 15 minutes.");
    const [a] = await db.select().from(admins).where(eq(admins.email, email));
    const pwOk = verifyPassword(password, a?.passwordHash ?? DUMMY_HASH) && !!a;
    let mfaOk = true;
    if (pwOk && a.totpEnabled && a.totpSecretEnc) mfaOk = verifyTotp(decryptSecret(a.totpSecretEnc), str(fd, "code"));
    if (!pwOk || !mfaOk) {
      noteLoginFailure(email);
      throw new ProblemError(401, "Unauthorized", pwOk ? "Invalid or missing authenticator code" : "Invalid email or password");
    }
    clearLoginFailures(email);
    await db.transaction((tx) => audit(tx, { label: `admin:${email}` }, "admin.login", "admin", a.id, { mfa: a.totpEnabled }));
    await createSession(a.id);
    redirect("/");
  });
}

export async function logoutAction() {
  await destroySession();
  redirect("/login");
}

export async function totpBeginAction(_p: ActionState, _fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("viewer");
    const secret = newTotpSecret();
    await db.update(admins).set({ totpSecretEnc: encryptSecret(secret), totpEnabled: false }).where(eq(admins.id, me.id));
    return {
      message: "Add this secret to your authenticator app, then confirm with a code below.",
      secret: { label: "Authenticator secret", value: secret, hint: otpauthUri(me.email, secret) },
    };
  });
}

export async function totpConfirmAction(_p: ActionState, fd: FormData): Promise<ActionState> {
  return act(async () => {
    const me = await requireRole("viewer");
    const [a] = await db.select().from(admins).where(eq(admins.id, me.id));
    if (!a.totpSecretEnc || !verifyTotp(decryptSecret(a.totpSecretEnc), str(fd, "code"))) {
      throw new ProblemError(422, "Validation failed", "Code did not match. Start enrollment again if needed.");
    }
    await db.transaction(async (tx) => {
      await tx.update(admins).set({ totpEnabled: true }).where(eq(admins.id, me.id));
      await audit(tx, { label: `admin:${me.email}`, adminId: me.id }, "admin.mfa_enable", "admin", me.id, {});
    });
    return { message: "Authenticator enabled. It is now required at sign-in." };
  });
}
