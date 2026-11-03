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
  return (
    <ActionForm action={loginAction} submit="Sign in" className="space-y-4">
      <h1 className="text-xl font-semibold text-slate-900">Sign in</h1>
      <Field label="Email">
        <input name="email" type="email" required autoComplete="username" className={inputCls} />
      </Field>
      <Field label="Password">
        <input name="password" type="password" required autoComplete="current-password" className={inputCls} />
      </Field>
      <Field label="Authenticator code" hint="Only required if MFA is enabled on your account.">
        <input name="code" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" className={inputCls} />
      </Field>
    </ActionForm>
  );
}
