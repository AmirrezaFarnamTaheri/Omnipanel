import { randomUUID } from "node:crypto";
import { sql, eq } from "drizzle-orm";
import { db } from "@/db";
import { plans, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { fmtBytes } from "@/lib/format";
import { createPlanAction } from "@/app/actions/people";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";

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
        <Table head={["Plan", "Quota", "Enforcement", "Users"]} empty={rows.length ? undefined : "No plans yet."}>
          {rows.map(({ p, n }) => (
            <tr key={p.id}>
              <Td className="font-medium">{p.name}</Td>
              <Td>{p.quotaBytes ? fmtBytes(p.quotaBytes) : "unlimited"}</Td>
              <Td><Badge tone={p.enforcement === "hard" ? "blue" : p.enforcement === "metered" ? "amber" : "slate"}>{p.enforcement}</Badge></Td>
              <Td>{n}</Td>
            </tr>
          ))}
        </Table>
        <ul className="mt-4 space-y-1 text-xs text-slate-500">
          <li><strong>hard</strong>: strict byte budget within a verified overshoot bound.</li>
          <li><strong>metered</strong>: traffic is measured; new sessions are denied after the measured limit with a delay bounded by collection interval.</li>
          <li><strong>unmetered</strong>: measured for visibility only.</li>
        </ul>
      </Card>
      {me.role !== "viewer" && (
        <Card title="Create plan">
          <ActionForm action={createPlanAction} submit="Create plan">
            <input type="hidden" name="idemKey" value={idem} />
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Name"><input name="name" required className={inputCls} /></Field>
              <Field label="Monthly quota (GB)"><input name="quotaGb" type="number" step="any" min="0" className={inputCls} /></Field>
              <Field label="Enforcement">
                <select name="enforcement" className={inputCls}>
                  <option value="metered">metered</option>
                  <option value="hard">hard (requires verified evidence)</option>
                  <option value="unmetered">unmetered</option>
                </select>
              </Field>
            </div>
          </ActionForm>
        </Card>
      )}
    </>
  );
}
