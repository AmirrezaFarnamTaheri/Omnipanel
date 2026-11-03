import Link from "next/link";
import { count, desc, sql } from "drizzle-orm";
import { db } from "@/db";
import { auditLog, inboundHealth, inbounds, nodes, plans, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { evaluateAlerts } from "@/lib/alerts";
import { drainOutbox, sweepExpiry } from "@/lib/outbox";
import { periodStart, usageForUser } from "@/lib/users";
import { ago, fmtBytes, isOnline } from "@/lib/format";
import { Badge, Card, PageHeader, Stat, statusTone, Table, Td } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";
import { runWorkerAction, seedDemoAction } from "@/app/actions/system";

export default async function Overview() {
  const me = await requirePage("viewer");
  await sweepExpiry();
  await drainOutbox();
  const alerts = await evaluateAlerts();
  const allNodes = await db.select().from(nodes).orderBy(nodes.id);
  const [{ nu }] = await db.select({ nu: count() }).from(users);
  const [{ ni }] = await db.select({ ni: count() }).from(inbounds);
  const [{ na }] = await db.select({ na: count() }).from(auditLog);
  const [{ np }] = await db.select({ np: count() }).from(plans);
  const health = await db.select({ state: inboundHealth.state, n: sql<number>`count(*)::int` }).from(inboundHealth).groupBy(inboundHealth.state);
  const healthy = health.find((h) => h.state === "healthy")?.n ?? 0;
  const recentUsers = await db.select().from(users).orderBy(desc(users.id)).limit(6);
  const usage = await Promise.all(recentUsers.map((u) => usageForUser(db, u.id)));

  if (allNodes.length === 0 && nu === 0) {
    return (
      <>
        <PageHeader title="Welcome to OmniPanel" subtitle="Register a VPS node, define an inbound, create a plan and a user. Or load a simulated two-provider topology to explore the platform." />
        <Card title="Get started">
          <div className="grid gap-4 md:grid-cols-3">
            <Link href="/nodes" className="rounded-lg border border-slate-200 p-4 hover:border-indigo-300">
              <p className="font-medium">1. Register a node</p>
              <p className="mt-1 text-sm text-slate-600">Provider, ASN and address are tracked for diversity analysis.</p>
            </Link>
            <Link href="/plans" className="rounded-lg border border-slate-200 p-4 hover:border-indigo-300">
              <p className="font-medium">2. Create a plan</p>
              <p className="mt-1 text-sm text-slate-600">Choose metered or hard enforcement honestly.</p>
            </Link>
            <Link href="/users" className="rounded-lg border border-slate-200 p-4 hover:border-indigo-300">
              <p className="font-medium">3. Add users</p>
              <p className="mt-1 text-sm text-slate-600">One subscription identity, per-endpoint credentials.</p>
            </Link>
          </div>
          {me.role === "owner" && (
            <ActionForm action={seedDemoAction} submit="Load demo topology" variant="ghost" className="mt-6 border-t border-slate-100 pt-4" />
          )}
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Intent → capability validation → immutable revision → applied state → observed connectivity → accounting → subscription → audit."
        actions={<ActionForm action={runWorkerAction} submit="Run worker now" variant="ghost" />}
      />
      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Nodes" value={allNodes.length} hint={`${new Set(allNodes.map((n) => n.provider.toLowerCase())).size} provider(s)`} />
        <Stat label="Endpoints" value={ni} hint={`${healthy} healthy`} />
        <Stat label="Users" value={nu} hint={`${np} plan(s)`} />
        <Stat label="Open alerts" value={alerts.length} hint={alerts.some((a) => a.severity === "critical") ? "critical present" : "none critical"} />
        <Stat label="Audit records" value={na} hint="hash-chained" />
      </div>

      {alerts.length > 0 && (
        <Card title="Active alerts" className="mb-6">
          <ul className="divide-y divide-slate-100">
            {alerts.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                <span className="flex items-center gap-2">
                  <Badge tone={a.severity === "critical" ? "red" : "amber"}>{a.severity}</Badge>
                  {a.message}
                </span>
                <span className="text-xs text-slate-500">{ago(a.createdAt)}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Card title="Desired vs applied" className="mb-6">
        <Table head={["Node", "Provider / ASN", "Link", "Structural (desired → applied)", "Membership", "Applied state"]} empty={allNodes.length ? undefined : "No nodes yet."}>
          {allNodes.map((n) => {
            const online = isOnline(n.lastSeenAt);
            return (
              <tr key={n.id}>
                <Td>
                  <Link href={`/nodes/${n.id}`} className="font-medium text-indigo-700 hover:underline">
                    {n.name}
                  </Link>
                  <div className="text-xs text-slate-500">{n.publicAddress}</div>
                </Td>
                <Td>
                  {n.provider}
                  <div className="text-xs text-slate-500">{n.asn || "—"}</div>
                </Td>
                <Td>
                  {n.status === "active" ? <Badge tone={online ? "green" : "red"}>{online ? "online" : "offline"}</Badge> : <Badge tone={statusTone(n.status)}>{n.status.replace("_", " ")}</Badge>}
                  <div className="text-xs text-slate-500">{ago(n.lastSeenAt)}</div>
                </Td>
                <Td>
                  #{n.structuralSeq} → #{n.appliedStructuralSeq}{" "}
                  {n.structuralSeq !== n.appliedStructuralSeq && <Badge tone="amber">pending</Badge>}
                </Td>
                <Td>
                  #{n.membershipSeq} → #{n.appliedMembershipSeq}{" "}
                  {n.membershipSeq !== n.appliedMembershipSeq && <Badge tone="amber">pending</Badge>}
                </Td>
                <Td>
                  <Badge tone={statusTone(n.appliedState)}>{n.appliedState}</Badge>
                </Td>
              </tr>
            );
          })}
        </Table>
      </Card>

      <Card title={`Usage this period (from ${periodStart().toISOString().slice(0, 10)})`} aside={<Link href="/users" className="text-sm text-indigo-700 hover:underline">All users</Link>}>
        <Table head={["User", "Status", "Measured", "Accounting quality"]}>
          {recentUsers.map((u, i) => (
            <tr key={u.id}>
              <Td>
                <Link href={`/users/${u.id}`} className="font-medium text-indigo-700 hover:underline">
                  {u.name}
                </Link>
              </Td>
              <Td>
                <Badge tone={statusTone(u.status)}>{u.status}</Badge>
              </Td>
              <Td>{fmtBytes(usage[i].total)}</Td>
              <Td>
                <Badge tone={statusTone(usage[i].quality)}>{usage[i].quality}</Badge>
              </Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
