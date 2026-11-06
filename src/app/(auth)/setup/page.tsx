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
    <div className="mx-auto max-w-md py-12 sm:py-16">
      <PageHeader
        title="Welcome to OmniPanel"
        subtitle="Create your personal admin account to start managing nodes and subscriptions."
      />
      <Card>
        <CardHeader>
          <CardTitle>Admin Account</CardTitle>
          <CardDescription>Choose an email and password (8+ characters).</CardDescription>
        </CardHeader>
        <CardContent>
          <ActionForm action={setupAction} submit="Create Account & Continue" className="space-y-4">
            <Field label="Email">
              <Input name="email" type="email" required defaultValue="admin@omnipanel.local" autoComplete="username" />
            </Field>
            <Field label="Password">
              <Input name="password" type="password" required minLength={8} autoComplete="new-password" />
            </Field>
            {process.env.OMNI_SETUP_TOKEN && (
              <Field label="Setup token">
                <Input name="setupToken" type="password" required />
              </Field>
            )}
          </ActionForm>
        </CardContent>
      </Card>
    </div>
  );
}
