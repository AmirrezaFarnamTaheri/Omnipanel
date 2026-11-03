import { randomUUID } from "node:crypto";
import Link from "next/link";
import { db } from "@/db";
import { plans } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { listUsers, usageForUser } from "@/lib/users";
import { fmtBytes, fmtDate } from "@/lib/format";
import { createUserAction } from "@/app/actions/people";
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

export default async function UsersPage() {
  const me = await requirePage("viewer");
  const rows = await listUsers();
  const allPlans = await db.select().from(plans).orderBy(plans.id);
  const usage = await Promise.all(rows.map((r) => usageForUser(db, r.u.id)));
  const idem = randomUUID();

  return (
    <>
      <PageHeader
        title="Users"
        subtitle="One logical subscription identity per user; independent credentials per endpoint."
      />
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Users</CardTitle>
          <CardDescription>{rows.length} user(s) across {allPlans.length} plan(s)</CardDescription>
        </CardHeader>
        <CardContent>
          {rows.length === 0 ? (
            <EmptyState
              title="No users yet"
              description="Create your first user to begin issuing subscription credentials."
              action={
                <div className="w-full">
                  {allPlans.length === 0 ? (
                    <p className="text-sm text-slate-600">Create a <Link className="text-indigo-600 underline" href="/plans">plan</Link> first.</p>
                  ) : (
                    <ActionForm action={createUserAction} submit="Create & provision" />
                  )}
                </div>
              }
            />
          ) : (
            <>
              <TableWrapper>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>User</TableHead>
                      <TableHead className="w-24">Plan</TableHead>
                      <TableHead className="w-20">Status</TableHead>
                      <TableHead className="w-40">Measured / quota</TableHead>
                      <TableHead className="w-24">Quality</TableHead>
                      <TableHead className="w-24">Expires</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map(({ u, planName }, i) => {
                      const plan = allPlans.find((p) => p.id === u.planId);
                      return (
                        <TableRow key={u.id}>
                          <TableCell>
                            <Link href={`/users/${u.id}`} className="font-medium text-indigo-600 hover:underline">
                              {u.name}
                            </Link>
                            <div className="text-xs text-slate-500">{u.email ?? ""}</div>
                          </TableCell>
                          <TableCell>{planName}</TableCell>
                          <TableCell>
                            <Badge variant="secondary">{u.status}</Badge>
                            {u.suspendReason && <span className="ml-1 text-xs text-slate-500">({u.suspendReason})</span>}
                          </TableCell>
                          <TableCell>
                            {fmtBytes(usage[i].total)}{plan?.quotaBytes ? ` / ${fmtBytes(plan.quotaBytes)}` : " / unlimited"}
                            {plan?.quotaBytes && (
                              <div className="mt-1 h-1 w-32 overflow-hidden rounded bg-slate-100">
                                <div
                                  className={`h-full ${usage[i].total >= plan.quotaBytes ? "bg-rose-500" : usage[i].total > plan.quotaBytes * 0.8 ? "bg-amber-500" : "bg-indigo-500"}`}
                                  style={{ width: `${Math.min(100, (usage[i].total / plan.quotaBytes) * 100)}%` }}
                                />
                              </div>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary">{usage[i].quality}</Badge>
                          </TableCell>
                          <TableCell className="text-xs">{fmtDate(u.expiresAt)}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableWrapper>
            </>
          )}
        </CardContent>
      </Card>
      {me.role !== "viewer" && (
        <Card>
          <CardHeader>
            <CardTitle>Create user</CardTitle>
          </CardHeader>
          <CardContent>
            {allPlans.length === 0 ? (
              <p className="text-sm text-slate-600">Create a <Link className="text-indigo-600 underline" href="/plans">plan</Link> first.</p>
            ) : (
              <ActionForm action={createUserAction} submit="Create & provision">
                <input type="hidden" name="idemKey" value={idem} />
                <div className="grid gap-4 md:grid-cols-4">
                  <Field label="Name">
                    <input name="name" required className="w-full" />
                  </Field>
                  <Field label="Email (optional)">
                    <input name="email" type="email" className="w-full" />
                  </Field>
                  <Field label="Plan">
                    <select name="planId" className="w-full">
                      {allPlans.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.enforcement})
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Expires (optional)">
                    <input name="expiresAt" type="date" className="w-full" />
                  </Field>
                </div>
              </ActionForm>
            )}
          </CardContent>
        </Card>
      )}
    </>
  );
}
