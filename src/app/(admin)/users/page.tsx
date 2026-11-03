import { randomUUID } from "node:crypto";
import Link from "next/link";
import { db } from "@/db";
import { plans } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { listUsers, usageForUser } from "@/lib/users";
import { fmtBytes, fmtDate } from "@/lib/format";
import { createUserAction } from "@/app/actions/people";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, statusTone, Table, Td } from "@/components/ui";

export default async function UsersPage() {
  const me = await requirePage("viewer");
  const rows = await listUsers();
  const allPlans = await db.select().from(plans).orderBy(plans.id);
  const usage = await Promise.all(rows.map((r) => usageForUser(db, r.u.id)));
  const idem = randomUUID();
  return (
    <>
      <PageHeader title="Users" subtitle="One logical subscription identity per user; independent credentials per endpoint." />
      <Card className="mb-6">
        <Table head={["User", "Plan", "Status", "Measured / quota", "Quality", "Expires"]} empty={rows.length ? undefined : "No users yet."}>
          {rows.map(({ u, planName }, i) => {
            const plan = allPlans.find((p) => p.id === u.planId);
            return (
              <tr key={u.id}>
                <Td>
                  <Link href={`/users/${u.id}`} className="font-medium text-indigo-700 hover:underline">{u.name}</Link>
                  <div className="text-xs text-slate-500">{u.email ?? ""}</div>
                </Td>
                <Td>{planName}</Td>
                <Td><Badge tone={statusTone(u.status)}>{u.status}</Badge>{u.suspendReason && <span className="ml-1 text-xs text-slate-500">({u.suspendReason})</span>}</Td>
                <Td>
                  {fmtBytes(usage[i].total)}{plan?.quotaBytes ? ` / ${fmtBytes(plan.quotaBytes)}` : " / unlimited"}
                  {plan?.quotaBytes ? (
                    <div className="mt-1 h-1.5 w-32 overflow-hidden rounded bg-slate-100">
                      <div className={`h-full ${usage[i].total >= plan.quotaBytes ? "bg-rose-500" : usage[i].total > plan.quotaBytes * 0.8 ? "bg-amber-500" : "bg-indigo-500"}`} style={{ width: `${Math.min(100, (usage[i].total / plan.quotaBytes) * 100)}%` }} />
                    </div>
                  ) : null}
                </Td>
                <Td><Badge tone={statusTone(usage[i].quality)}>{usage[i].quality}</Badge></Td>
                <Td className="text-xs">{fmtDate(u.expiresAt)}</Td>
              </tr>
            );
          })}
        </Table>
      </Card>
      {me.role !== "viewer" && (
        <Card title="Create user">
          {allPlans.length === 0 ? (
            <p className="text-sm text-slate-600">Create a <Link className="text-indigo-700 underline" href="/plans">plan</Link> first.</p>
          ) : (
            <ActionForm action={createUserAction} submit="Create & provision">
              <input type="hidden" name="idemKey" value={idem} />
              <div className="grid gap-4 md:grid-cols-4">
                <Field label="Name"><input name="name" required className={inputCls} /></Field>
                <Field label="Email (optional)"><input name="email" type="email" className={inputCls} /></Field>
                <Field label="Plan">
                  <select name="planId" className={inputCls}>
                    {allPlans.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.enforcement})</option>)}
                  </select>
                </Field>
                <Field label="Expires (optional)"><input name="expiresAt" type="date" className={inputCls} /></Field>
              </div>
            </ActionForm>
          )}
        </Card>
      )}
    </>
  );
}
