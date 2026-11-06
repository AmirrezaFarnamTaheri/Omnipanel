import { randomUUID } from "node:crypto";
import { sql, eq } from "drizzle-orm";
import { Layers } from "lucide-react";
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
  Input,
  PageHeader,
  Select,
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
    <div className="space-y-6">
      <PageHeader
        title="Plans & Quota Enforcement"
        subtitle="Enforcement classes state what the platform can actually guarantee. Hard quotas are only available once a runtime has verified lab evidence."
      />
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-indigo-600" />
            <CardTitle>Plans</CardTitle>
          </div>
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
                      <TableHead className="w-36 text-right">Quota</TableHead>
                      <TableHead className="w-32">Enforcement</TableHead>
                      <TableHead className="w-24 text-right">Users</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map(({ p, n }) => (
                      <TableRow key={p.id}>
                        <TableCell className="font-semibold text-slate-900">{p.name}</TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {p.quotaBytes ? fmtBytes(p.quotaBytes) : "unlimited"}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              p.enforcement === "hard"
                                ? "destructive"
                                : p.enforcement === "metered"
                                  ? "warning"
                                  : "secondary"
                            }
                          >
                            {p.enforcement}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">{n}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableWrapper>
              <ul className="mt-6 space-y-1.5 rounded-lg border border-slate-200 bg-slate-50/70 p-3.5 text-xs text-slate-600">
                <li>
                  <strong className="text-slate-900">hard</strong>: strict byte budget within a verified overshoot bound (gated until lab evidence is reviewed).
                </li>
                <li>
                  <strong className="text-slate-900">metered</strong>: traffic is measured via monotonic generation checkpoints; new sessions are denied after the measured limit.
                </li>
                <li>
                  <strong className="text-slate-900">unmetered</strong>: measured for visibility only.
                </li>
              </ul>
            </>
          )}
        </CardContent>
      </Card>
      {me.role !== "viewer" && (
        <Card>
          <CardHeader>
            <CardTitle>Create plan</CardTitle>
            <CardDescription>Define a quota tier and enforcement level.</CardDescription>
          </CardHeader>
          <CardContent>
            <ActionForm action={createPlanAction} submit="Create plan">
              <input type="hidden" name="idemKey" value={idem} />
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Name">
                  <Input name="name" required placeholder="Enterprise 500 GB" />
                </Field>
                <Field label="Monthly quota (GB)">
                  <Input name="quotaGb" type="number" step="any" min="0" placeholder="500" className="font-mono" />
                </Field>
                <Field label="Enforcement">
                  <Select name="enforcement">
                    <option value="metered">metered</option>
                    <option value="hard">hard (requires verified evidence)</option>
                    <option value="unmetered">unmetered</option>
                  </Select>
                </Field>
              </div>
            </ActionForm>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
