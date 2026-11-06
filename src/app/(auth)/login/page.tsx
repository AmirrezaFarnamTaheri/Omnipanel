import { redirect } from "next/navigation";
import { count } from "drizzle-orm";
import { db } from "@/db";
import { admins } from "@/db/schema";
import { getAdmin } from "@/lib/auth";
import { loginAction } from "@/app/actions/auth";
import { ActionForm } from "@/components/ActionForm";
import { Field, inputCls } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  if (await getAdmin()) redirect("/");
  const [{ n }] = await db.select({ n: count() }).from(admins);
  if (n === 0) redirect("/setup");

  const isLocalDev = process.env.NODE_ENV !== "production" && !process.env.DATABASE_URL;

  return (
    <div className="space-y-5">
      <ActionForm action={loginAction} submitLabel="Sign in" className="space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">Sign in to OmniPanel</h1>
          <p className="text-xs text-slate-500 mt-1">
            Personal self-hosted proxy & subscription control plane.
          </p>
        </div>
        <Field label="Email">
          <input
            name="email"
            type="email"
            required
            defaultValue={isLocalDev ? "owner@omnipanel.internal" : ""}
            placeholder="owner@omnipanel.internal"
            autoComplete="username"
            className={inputCls}
          />
        </Field>
        <Field label="Password">
          <input
            name="password"
            type="password"
            required
            defaultValue={isLocalDev ? "OmniPanel#Owner2026!" : ""}
            placeholder="Enter password"
            autoComplete="current-password"
            className={inputCls}
          />
        </Field>
        <details className="text-xs text-slate-600">
          <summary className="cursor-pointer font-medium text-slate-500 hover:text-slate-800">
            Using two-factor authentication (2FA)?
          </summary>
          <div className="mt-2">
            <Field label="Authenticator code (optional)">
              <input
                name="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="6-digit code"
                className={inputCls}
              />
            </Field>
          </div>
        </details>
      </ActionForm>
    </div>
  );
}
