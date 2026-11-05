import { randomUUID } from "node:crypto";
import { sql, eq } from "drizzle-orm";
import { db } from "@/db";
import { plans, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { fmtBytes } from "@/lib/format";
import { createPlanAction } from "@/app/actions/people";
import { ActionForm } from "@/components/ActionForm";
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  Field,
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
} from "@/components/ui";

export default async function PlansPage() {
  const me = await requirePage("viewer");
  const rows = await db
    .select({ p: plans, n: sql<number>`count(${users.id})::int` })
    .from(plans)
    .leftJoin(users, eq(users.planId, plans.id))
    .groupBy(plans.id)
    .orderBy(plans.id);
  const idem = randomUUID();

  return (
    <>
      <PageHeader
        title="Plans"
        subtitle="Enforcement classes state what the platform can actually guarantee. Hard quotas are only available once a runtime has verified lab evidence."
      />
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Plans</CardTitle>
          <CardDescription>{rows.length} plan(s) defined</CardDescription>
        </CardHeader>
        <CardContent>
          {rows.length === 0 ? (
            <EmptyState
              title="No plans yet"
              description="Create a plan to define usage quotas and enforcement behavior for users."
              action={
                <div className="w-full">
                  <ActionForm action={createPlanAction} submit="Create plan" />
                </div>
              }
            />
          ) : (
            <>
              <TableWrapper>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Plan</TableHead>
                      <TableHead className="w-24">Quota</TableHead>
                      <TableHead className="w-24">Enforcement</TableHead>
                      <TableHead className="w-16">Users</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map(({ p, n }) => (
                      <TableRow key={p.id}>
                        <TableCell className="font-medium">{p.name}</TableCell>
                        <TableCell>{p.quotaBytes ? fmtBytes(p.quotaBytes) : "unlimited"}</TableCell>
                        <TableCell>
                          <Badge
                            variant={p.enforcement === "hard" ? "destructive" : p.enforcement === "metered" ? "warning" : "secondary"}
                          >
                            {p.enforcement}
                          </Badge>
                        </TableCell>
                        <TableCell>{n}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableWrapper>
              <ul className="mt-6 space-y-1 text-xs text-slate-500">
                <li><strong>hard</strong>: strict byte budget within a verified overshoot bound.</li>
                <li><strong>metered</strong>: traffic is measured; new sessions are denied after the measured limit with a delay bounded by collection interval.</li>
                <li><strong>unmetered</strong>: measured for visibility only.</li>
              </ul>
            </>
          )}
        </CardContent>
      </Card>
      {me.role !== "viewer" && (
        <Card>
          <CardHeader>
            <CardTitle>Create plan</CardTitle>
          </CardHeader>
          <CardContent>
            <ActionForm action={createPlanAction} submit="Create plan">
              <input type="hidden" name="idemKey" value={idem} />
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Name">
                  <input name="name" required className="w-full" />
                </Field>
                <Field label="Monthly quota (GB)">
                  <input name="quotaGb" type="number" step="any" min="0" className="w-full" />
                </Field>
                <Field label="Enforcement">
                  <select name="enforcement" className="w-full">
                    <option value="metered">metered</option>
                    <option value="hard">hard (requires verified evidence)</option>
                    <option value="unmetered">unmetered</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </CardContent>
        </Card>
      )}
    </>
  );
}
