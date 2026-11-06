import { redirect } from "next/navigation";
import { count } from "drizzle-orm";
import { db } from "@/db";
import { admins } from "@/db/schema";
import { getAdmin } from "@/lib/auth";
import { loginAction } from "@/app/actions/auth";
import { switchOperatorIdentityAction } from "@/app/actions/system";
import { ActionForm } from "@/components/ActionForm";
import { Field, inputCls } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  if (await getAdmin()) redirect("/");
  const [{ n }] = await db.select({ n: count() }).from(admins);
  if (n === 0) redirect("/setup");

  return (
    <div className="space-y-6">
      <ActionForm action={loginAction} submitLabel="Sign in" className="space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">Sign in to OmniPanel</h1>
          <p className="text-xs text-slate-500 mt-1">
            Enter your operator credentials and RFC 6238 TOTP code if MFA is enabled.
          </p>
        </div>
        <Field label="Email">
          <input
            name="email"
            type="email"
            required
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
            placeholder="Enter operator password"
            autoComplete="current-password"
            className={inputCls}
          />
        </Field>
        <Field label="Authenticator code" hint="Only required if custom TOTP secret is enrolled on your account.">
          <input
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            className={inputCls}
          />
        </Field>
      </ActionForm>

      {!process.env.DATABASE_URL && (
        <div className="border-t border-slate-200 pt-4">
          <p className="text-xs font-medium text-slate-600 mb-2">
            Embedded Preview Quick Session Bootstrap:
          </p>
          <div className="grid grid-cols-1 gap-2">
            <form
              action={async (fd) => {
                "use server";
                await switchOperatorIdentityAction(fd);
                redirect("/");
              }}
            >
              <input type="hidden" name="adminId" value="1" />
              <button
                type="submit"
                className="w-full rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2 text-xs font-semibold text-indigo-700 hover:bg-indigo-100"
              >
                Continue as owner@omnipanel.internal (Owner #1)
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
