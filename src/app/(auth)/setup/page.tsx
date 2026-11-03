import { redirect } from "next/navigation";
import { count } from "drizzle-orm";
import { db } from "@/db";
import { admins } from "@/db/schema";
import { setupAction } from "@/app/actions/auth";
import { ActionForm } from "@/components/ActionForm";
import { Field, inputCls } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function SetupPage() {
  const [{ n }] = await db.select({ n: count() }).from(admins);
  if (n > 0) redirect("/login");
  return (
    <ActionForm action={setupAction} submit="Create owner account" className="space-y-4">
      <h1 className="text-xl font-semibold text-slate-900">Create the first administrator</h1>
      <p className="text-sm text-slate-600">
        This one-time bootstrap creates the owner account. Enable an authenticator app under Settings afterwards.
      </p>
      <Field label="Email">
        <input name="email" type="email" required autoComplete="username" className={inputCls} />
      </Field>
      <Field label="Password" hint="At least 12 characters.">
        <input name="password" type="password" required minLength={12} autoComplete="new-password" className={inputCls} />
      </Field>
      <Field label="Confirm password">
        <input name="confirm" type="password" required minLength={12} autoComplete="new-password" className={inputCls} />
      </Field>
      {process.env.OMNI_SETUP_TOKEN && (
        <Field label="Setup token">
          <input name="setupToken" type="password" required className={inputCls} />
        </Field>
      )}
    </ActionForm>
  );
}
