import Link from "next/link";
import { redirect } from "next/navigation";
import { count } from "drizzle-orm";
import { db } from "@/db";
import { admins } from "@/db/schema";
import { setupAction } from "@/app/actions/auth";
import { ActionForm } from "@/components/ActionForm";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, Field, Input, PageHeader } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function SetupPage() {
  const [{ n }] = await db.select({ n: count() }).from(admins);
  if (n > 0) redirect("/login");
  return (
    <div className="mx-auto max-w-md py-12 sm:py-16 lg:py-20">
      <PageHeader
        title="Create owner account"
        subtitle="This one-time bootstrap creates the first administrator. Enable an authenticator app under Settings afterwards."
      />
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Owner credentials</CardTitle>
          <CardDescription>Choose a strong email and password. At least 12 characters required.</CardDescription>
        </CardHeader>
        <CardContent>
          <ActionForm action={setupAction} submit="Create owner account" className="space-y-4">
            <Field label="Email" hint="Used for sign-in and audit attribution.">
              <Input name="email" type="email" required autoComplete="username" />
            </Field>
            <Field label="Password" hint="At least 12 characters. Scrypt-hashed at rest.">
              <Input name="password" type="password" required minLength={12} autoComplete="new-password" />
            </Field>
            <Field label="Confirm password">
              <Input name="confirm" type="password" required minLength={12} autoComplete="new-password" />
            </Field>
            {process.env.OMNI_SETUP_TOKEN && (
              <Field label="Setup token">
                <Input name="setupToken" type="password" required />
              </Field>
            )}
          </ActionForm>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>What happens next</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="space-y-3 text-sm text-slate-600">
            <li className="flex items-start gap-3">
              <span className="font-mono font-semibold text-indigo-600">1.</span>
              <span>The owner account is created with scrypt password hashing and AES-256-GCM envelope encryption.</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="font-mono font-semibold text-indigo-600">2.</span>
              <span>
                Sign in at{" "}
                <Link className="text-indigo-600 underline" href="/login">
                  /login
                </Link>{" "}
                and complete MFA setup under Settings.
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="font-mono font-semibold text-indigo-600">3.</span>
              <span>Register a node, create a plan, add users — the intent → revision → application → observation loop is ready.</span>
            </li>
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
