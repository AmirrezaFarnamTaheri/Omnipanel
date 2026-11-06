import Link from "next/link";
import { count, desc } from "drizzle-orm";
import { ArrowRight, FileSignature, Layers, Server, ShieldAlert, Users } from "lucide-react";
import { db } from "@/db";
import { auditLog, inboundHealth, inbounds, nodes, plans, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { evaluateAlerts } from "@/lib/alerts";
import { drainOutbox, sweepExpiry } from "@/lib/outbox";
import { listDesiredStateProposals } from "@/lib/governance-store";
import { periodStart, usageForUser } from "@/lib/users";
import { ago, fmtBytes, isOnline } from "@/lib/format";
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  PageHeader,
  Stat,
  statusTone,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
} from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";
import { runWorkerAction } from "@/app/actions/system";

export const dynamic = "force-dynamic";

export default async function Overview() {
  await requirePage("viewer");
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
  const proposals = await listDesiredStateProposals();
  const pendingProposals = proposals.filter((p) => !p.decision || p.decision.consumedAt === null);

  if (allNodes.length === 0 && nu === 0) {
    return (
      <>
        <PageHeader
          title="Welcome to OmniPanel"
          subtitle="Register a VPS node, create a plan and a user. Runtime deployment remains gated until real capability evidence is verified."
        />
        <Card>
          <CardHeader>
            <CardTitle>Get started</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-3">
              <Link
                href="/nodes"
                className="group block rounded-xl border border-slate-200 p-5 hover:border-indigo-200 hover:bg-indigo-50 transition-colors"
              >
                <div className="w-10 h-10 rounded-xl bg-indigo-100 flex items-center justify-center group-hover:bg-indigo-200 transition-colors mb-3">
                  <Server className="h-5 w-5 text-indigo-700" />
                </div>
                <h3 className="font-semibold">1. Register a node</h3>
                <p className="mt-1 text-sm text-slate-600">Provider, ASN and address are tracked for diversity analysis.</p>
              </Link>
              <Link
                href="/plans"
                className="group block rounded-xl border border-slate-200 p-5 hover:border-indigo-200 hover:bg-indigo-50 transition-colors"
              >
                <div className="w-10 h-10 rounded-xl bg-indigo-100 flex items-center justify-center group-hover:bg-indigo-200 transition-colors mb-3">
                  <Layers className="h-5 w-5 text-indigo-700" />
                </div>
                <h3 className="font-semibold">2. Create a plan</h3>
                <p className="mt-1 text-sm text-slate-600">Choose metered or hard enforcement honestly.</p>
              </Link>
              <Link
                href="/users"
                className="group block rounded-xl border border-slate-200 p-5 hover:border-indigo-200 hover:bg-indigo-50 transition-colors"
              >
                <div className="w-10 h-10 rounded-xl bg-indigo-100 flex items-center justify-center group-hover:bg-indigo-200 transition-colors mb-3">
                  <Users className="h-5 w-5 text-indigo-700" />
                </div>
                <h3 className="font-semibold">3. Add users</h3>
                <p className="mt-1 text-sm text-slate-600">One subscription identity, per-endpoint credentials.</p>
              </Link>
            </div>
          </CardContent>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Manage your VPS nodes, proxy endpoints, and subscriber connection links."
        actions={<ActionForm action={runWorkerAction} submitLabel="Sync Outbox" variant="outline" size="sm" />}
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Nodes"
          value={allNodes.length}
          hint={`${new Set(allNodes.map((n) => n.provider.toLowerCase())).size} provider(s)`}
        />
        <Stat label="Active Endpoints" value={ni} hint={`${healthy} healthy`} />
        <Stat label="Users" value={nu} hint={`${np} plan(s)`} />
        <Stat label="Audit Events" value={na} hint="Tamper-evident log" />
      </div>

      {pendingProposals.length > 0 && (
        <div className="mb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-xl border border-indigo-200 bg-indigo-50/70 p-4">
          <div className="flex items-start gap-3">
            <FileSignature className="h-5 w-5 text-indigo-600 shrink-0 mt-0.5" />
            <div className="text-xs">
              <p className="text-sm font-semibold text-indigo-950">
                {pendingProposals.length} Staged Node Revision(s) Ready to Publish
              </p>
              <p className="text-indigo-800 mt-0.5">
                Next: <code className="font-mono font-semibold">{pendingProposals[0].proposalId}</code> on{" "}
                <strong>{pendingProposals[0].nodeName}</strong> (seq #{pendingProposals[0].structuralSequence}) —{" "}
                {pendingProposals[0].note}
              </p>
            </div>
          </div>
          <Link
            href="/approvals"
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-indigo-700 shrink-0"
          >
            Quick Publish
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      )}

      {alerts.length > 0 && (
        <Card className="mb-6 border-amber-200">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlert className="h-4 w-4 text-amber-600" />
              Active Notices ({alerts.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="divide-y divide-slate-100">
              {alerts.map((a) => (
                <li key={a.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                  <span className="flex items-center gap-2.5">
                    <Badge variant={a.severity === "critical" ? "error" : "warning"}>{a.severity}</Badge>
                    <span>{a.message}</span>
                  </span>
                  <span className="text-xs text-slate-500 tabular-nums">{ago(a.createdAt)}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">Nodes</CardTitle>
                <CardDescription>Status and revision sync across your servers.</CardDescription>
              </div>
              <Link href="/nodes" className="text-xs font-medium text-indigo-600 hover:underline">
                Manage nodes →
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Node</TableHead>
                    <TableHead>Location</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {allNodes.map((n) => {
                    const online = isOnline(n.lastSeenAt);
                    return (
                      <TableRow key={n.id}>
                        <TableCell>
                          <Link href={`/nodes/${n.id}`} className="font-mono text-xs font-semibold text-indigo-600 hover:underline">
                            {n.name}
                          </Link>
                          <div className="font-mono text-xs text-slate-500 tabular-nums">{n.publicAddress}</div>
                        </TableCell>
                        <TableCell className="text-xs text-slate-600">
                          {n.provider} {n.region ? `· ${n.region}` : ""}
                        </TableCell>
                        <TableCell>
                          {n.status === "active" ? (
                            <Badge variant={online ? "success" : "error"}>{online ? "online" : "offline"}</Badge>
                          ) : (
                            <Badge variant="secondary">{n.status.replace("_", " ")}</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Link
                            href={`/nodes/${n.id}`}
                            className="inline-flex items-center rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
                          >
                            Endpoints →
                          </Link>
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
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base">Users & Connection Links</CardTitle>
                <CardDescription>Traffic usage and quick access to client configs.</CardDescription>
              </div>
              <Link href="/users" className="text-xs font-medium text-indigo-600 hover:underline">
                All users →
              </Link>
            </div>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Traffic</TableHead>
                    <TableHead className="text-right">Client Configs</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recentUsers.map((u, i) => (
                    <TableRow key={u.id}>
                      <TableCell>
                        <Link href={`/users/${u.id}`} className="font-medium text-indigo-600 hover:underline">
                          {u.name}
                        </Link>
                        {u.email && <div className="font-mono text-xs text-slate-500">{u.email}</div>}
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusTone(u.status)}>{u.status}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs font-semibold text-slate-900 tabular-nums">
                        {fmtBytes(usage[i].total)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <Link
                            href={`/users/${u.id}`}
                            className="inline-flex items-center rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
                          >
                            Configs
                          </Link>
                          <Link
                            href={`/portal/${u.id}`}
                            className="inline-flex items-center rounded-md bg-indigo-50 px-2.5 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
                          >
                            Portal →
                          </Link>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableWrapper>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
