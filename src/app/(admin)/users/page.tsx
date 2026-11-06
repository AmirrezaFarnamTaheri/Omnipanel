import { randomUUID } from "node:crypto";
import Link from "next/link";
import { Layers, Users } from "lucide-react";
import { db } from "@/db";
import { plans } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { listUsers, usageForUser } from "@/lib/users";
import { fmtBytes, fmtDate } from "@/lib/format";
import { bulkUserLifecycleAction, createUserAction } from "@/app/actions/people";
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
  statusTone,
} from "@/components/ui";

export default async function UsersPage() {
  const me = await requirePage("viewer");
  const rows = await listUsers();
  const allPlans = await db.select().from(plans).orderBy(plans.id);
  const usage = await Promise.all(rows.map((r) => usageForUser(db, r.u.id)));
  const idem = randomUUID();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users & Subscriptions"
        subtitle="One logical subscription identity per user; independent per-endpoint credentials and deterministic profile emission."
      />
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Users className="h-4 w-4 text-indigo-600" />
            <CardTitle>Users</CardTitle>
          </div>
          <CardDescription>
            {rows.length} user(s) across {allPlans.length} plan(s)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {rows.length === 0 ? (
            <EmptyState
              title="No users yet"
              description="Create your first user to begin issuing subscription credentials."
              action={
                <div className="w-full">
                  {allPlans.length === 0 ? (
                    <p className="text-sm text-slate-600">
                      Create a{" "}
                      <Link className="text-indigo-600 underline" href="/plans">
                        plan
                      </Link>{" "}
                      first.
                    </p>
                  ) : (
                    <ActionForm action={createUserAction} submit="Create & provision" />
                  )}
                </div>
              }
            />
          ) : (
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead className="w-32">Plan</TableHead>
                    <TableHead className="w-28">Status</TableHead>
                    <TableHead className="w-48">Measured / quota</TableHead>
                    <TableHead className="w-28">Quality</TableHead>
                    <TableHead className="w-32 text-right">Expires</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map(({ u, planName }, i) => {
                    const plan = allPlans.find((p) => p.id === u.planId);
                    return (
                      <TableRow key={u.id}>
                        <TableCell>
                          <Link href={`/users/${u.id}`} className="font-semibold text-indigo-600 hover:underline">
                            {u.name}
                          </Link>
                          <div className="text-xs text-slate-500">{u.email ?? ""}</div>
                        </TableCell>
                        <TableCell className="font-medium text-slate-700">{planName}</TableCell>
                        <TableCell>
                          <Badge variant={statusTone(u.status)}>{u.status}</Badge>
                          {u.suspendReason && (
                            <span className="ml-1 text-xs text-slate-500">({u.suspendReason})</span>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs tabular-nums">
                          {fmtBytes(usage[i].total)}
                          {plan?.quotaBytes ? ` / ${fmtBytes(plan.quotaBytes)}` : " / unlimited"}
                          {plan?.quotaBytes && (
                            <div className="mt-1.5 h-1.5 w-36 overflow-hidden rounded-full bg-slate-100">
                              <div
                                className={`h-full ${
                                  usage[i].total >= plan.quotaBytes
                                    ? "bg-rose-500"
                                    : usage[i].total > plan.quotaBytes * 0.8
                                      ? "bg-amber-500"
                                      : "bg-indigo-500"
                                }`}
                                style={{ width: `${Math.min(100, (usage[i].total / plan.quotaBytes) * 100)}%` }}
                              />
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant={statusTone(usage[i].quality)}>{usage[i].quality}</Badge>
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-slate-600">
                          {fmtDate(u.expiresAt)}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableWrapper>
          )}
        </CardContent>
      </Card>

      {me.role !== "viewer" && (
        <div className="grid gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle>Create user</CardTitle>
              <CardDescription>
                Automatically provisions per-endpoint credentials and a rotatable 256-bit subscription bearer token.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {allPlans.length === 0 ? (
                <p className="text-sm text-slate-600">
                  Create a{" "}
                  <Link className="text-indigo-600 underline" href="/plans">
                    plan
                  </Link>{" "}
                  first.
                </p>
              ) : (
                <ActionForm action={createUserAction} submit="Create & provision">
                  <input type="hidden" name="idemKey" value={idem} />
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Name">
                      <Input name="name" required placeholder="charlie-ops" />
                    </Field>
                    <Field label="Email (optional)">
                      <Input name="email" type="email" placeholder="charlie@omnipanel.internal" />
                    </Field>
                    <Field label="Plan">
                      <Select name="planId">
                        {allPlans.map((p) => (
                          <option key={p.id} value={p.id}>
                            {p.name} ({p.enforcement})
                          </option>
                        ))}
                      </Select>
                    </Field>
                    <Field label="Expires (optional)">
                      <Input name="expiresAt" type="date" />
                    </Field>
                  </div>
                </ActionForm>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-indigo-600" />
                <CardTitle>Bulk Subscriber Lifecycle & Entitlement Operations</CardTitle>
              </div>
              <CardDescription>
                Executes atomic batch lifecycle transitions with optimistic version increments, node membership sequence updates, and genesis audit logging.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ActionForm
                action={bulkUserLifecycleAction}
                submitLabel="Execute Batch Lifecycle Action"
                variant="outline"
                className="space-y-4"
              >
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Batch Operation">
                    <Select name="operation" defaultValue="extend_expiry_30d">
                      <option value="extend_expiry_30d">Extend All Expirations (+30 Days UTC)</option>
                      <option value="resume_suspended">Resume All Suspended / Expired Users</option>
                      <option value="assign_plan">Reassign All Users to Selected Plan</option>
                      <option value="rotate_all_tokens">Rotate All Subscription Bearer Tokens</option>
                    </Select>
                  </Field>
                  <Field label="Target Plan (when reassigning)">
                    <Select name="planId">
                      {allPlans.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.enforcement})
                        </option>
                      ))}
                    </Select>
                  </Field>
                </div>
              </ActionForm>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

