import Link from "next/link";
import { count, desc } from "drizzle-orm";
import { db } from "@/db";
import { auditLog, inboundHealth, inbounds, nodes, plans, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { evaluateAlerts } from "@/lib/alerts";
import { drainOutbox, sweepExpiry } from "@/lib/outbox";
import { periodStart, usageForUser } from "@/lib/users";
import { ago, fmtBytes, isOnline } from "@/lib/format";
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  PageHeader,
  Spinner,
  Stat,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
} from "@/components/ui";
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
  const health = await db
    .select({ state: inboundHealth.state, n: count() })
    .from(inboundHealth)
    .groupBy(inboundHealth.state);
  const healthy = health.find((h) => h.state === "healthy")?.n ?? 0;
  const recentUsers = await db.select().from(users).orderBy(desc(users.id)).limit(6);
  const usage = await Promise.all(recentUsers.map((u) => usageForUser(db, u.id)));

  if (allNodes.length === 0 && nu === 0) {
    return (
      <>
        <PageHeader
          title="Welcome to OmniPanel"
          subtitle="Register a VPS node, define an inbound, create a plan and a user. Or load a simulated two-provider topology to explore the platform."
        />
        <Card>
          <CardHeader>
            <CardTitle>Get started</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3">
              <Link href="/nodes" className="group block rounded-xl border border-slate-200 p-5 hover:border-indigo-200 hover:bg-indigo-50 transition-colors">
                <div className="w-10 h-10 rounded-xl bg-indigo-100 flex items-center justify-center group-hover:bg-indigo-200 transition-colors mb-3">
                  <span className="text-lg">🖥️</span>
                </div>
                <h3 className="font-semibold">1. Register a node</h3>
                <p className="mt-1 text-sm text-slate-600">Provider, ASN and address are tracked for diversity analysis.</p>
              </Link>
              <Link href="/plans" className="group block rounded-xl border border-slate-200 p-5 hover:border-indigo-200 hover:bg-indigo-50 transition-colors">
                <div className="w-10 h-10 rounded-xl bg-indigo-100 flex items-center justify-center group-hover:bg-indigo-200 transition-colors mb-3">
                  <span className="text-lg">📋</span>
                </div>
                <h3 className="font-semibold">2. Create a plan</h3>
                <p className="mt-1 text-sm text-slate-600">Choose metered or hard enforcement honestly.</p>
              </Link>
              <Link href="/users" className="group block rounded-xl border border-slate-200 p-5 hover:border-indigo-200 hover:bg-indigo-50 transition-colors">
                <div className="w-10 h-10 rounded-xl bg-indigo-100 flex items-center justify-center group-hover:bg-indigo-200 transition-colors mb-3">
                  <span className="text-lg">👥</span>
                </div>
                <h3 className="font-semibold">3. Add users</h3>
                <p className="mt-1 text-sm text-slate-600">One subscription identity, per-endpoint credentials.</p>
              </Link>
            </div>
            {me.role === "owner" && (
              <div className="mt-6">
                <ActionForm action={seedDemoAction} submit="Load demo topology" variant="outline" />
              </div>
            )}
          </CardContent>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Intent → capability validation → immutable revision → applied state → observed connectivity → accounting → subscription → audit."
        actions={<ActionForm action={runWorkerAction} submit="Run worker now" variant="outline" size="sm" />}
      />
      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Stat label="Nodes" value={allNodes.length} hint={`${new Set(allNodes.map((n) => n.provider.toLowerCase())).size} provider(s)`} />
        <Stat label="Endpoints" value={ni} hint={`${healthy} healthy`} />
        <Stat label="Users" value={nu} hint={`${np} plan(s)`} />
        <Stat label="Open alerts" value={alerts.length} hint={alerts.some((a) => a.severity === "critical") ? "critical present" : "none critical"} />
        <Stat label="Audit records" value={na} hint="hash-chained" />
      </div>

      {alerts.length > 0 && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Active alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="divide-y divide-slate-100">
              {alerts.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <span className="flex items-center gap-2">
                    <Badge variant={a.severity === "critical" ? "error" : "warning"}>{a.severity}</Badge>
                    {a.message}
                  </span>
                  <span className="text-xs text-slate-500">{ago(a.createdAt)}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Desired vs applied</CardTitle>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Node</TableHead>
                  <TableHead className="w-24">Provider / ASN</TableHead>
                  <TableHead className="w-20">Link</TableHead>
                  <TableHead className="w-40">Structural (desired → applied)</TableHead>
                  <TableHead className="w-40">Membership</TableHead>
                  <TableHead>Applied state</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {allNodes.map((n) => {
                  const online = isOnline(n.lastSeenAt);
                  return (
                    <TableRow key={n.id}>
                      <TableCell>
                        <Link href={`/nodes/${n.id}`} className="font-medium text-indigo-600 hover:underline">
                          {n.name}
                        </Link>
                        <div className="text-xs text-slate-500">{n.publicAddress}</div>
                      </TableCell>
                      <TableCell>
                        {n.provider}
                        <div className="text-xs text-slate-500">{n.asn || "—"}</div>
                      </TableCell>
                      <TableCell>
                        {n.status === "active" ? (
                          <Badge variant={online ? "success" : "error"}>{online ? "online" : "offline"}</Badge>
                        ) : (
                          <Badge variant="secondary">{n.status.replace("_", " ")}</Badge>
                        )}
                        <div className="text-xs text-slate-500">{ago(n.lastSeenAt)}</div>
                      </TableCell>
                      <TableCell>
                        #{n.structuralSeq} → #{n.appliedStructuralSeq}
                        {n.structuralSeq !== n.appliedStructuralSeq && <Badge variant="warning">pending</Badge>}
                      </TableCell>
                      <TableCell>
                        #{n.membershipSeq} → #{n.appliedMembershipSeq}
                        {n.membershipSeq !== n.appliedMembershipSeq && <Badge variant="warning">pending</Badge>}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{n.appliedState}</Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableWrapper>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Usage this period</CardTitle>
          <CardDescription>from {periodStart().toISOString().slice(0, 10)}</CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead className="w-20">Status</TableHead>
                  <TableHead className="w-24">Measured</TableHead>
                  <TableHead>Accounting quality</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentUsers.map((u, i) => (
                  <TableRow key={u.id}>
                    <TableCell>
                      <Link href={`/users/${u.id}`} className="font-medium text-indigo-600 hover:underline">
                        {u.name}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{u.status}</Badge>
                    </TableCell>
                    <TableCell>{fmtBytes(usage[i].total)}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{usage[i].quality}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableWrapper>
        </CardContent>
      </Card>
    </>
  );
}
