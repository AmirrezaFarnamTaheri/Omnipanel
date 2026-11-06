import { randomUUID } from "node:crypto";
import Link from "next/link";
import { Cpu, Globe, HardDrive, Server } from "lucide-react";
import { db } from "@/db";
import { inbounds, nodes } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { ago, isOnline } from "@/lib/format";
import { getNodeResourceTelemetry } from "@/lib/governance-store";
import { createNodeAction } from "@/app/actions/infra";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
  statusTone,
} from "@/components/ui";

export default async function NodesPage() {
  const me = await requirePage("viewer");
  const rows = await db.select().from(nodes).orderBy(nodes.id);
  const ibs = await db.select({ nodeId: inbounds.nodeId }).from(inbounds);
  const telemetryByNode = await Promise.all(rows.map((n) => getNodeResourceTelemetry(n.id)));
  const idem = randomUUID();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Nodes & Fleet Topology"
        subtitle="Each VPS runs a headless agent with separate L0–L3 listener health and read-only host resource telemetry."
      />
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-indigo-600" />
            <CardTitle>Registered nodes</CardTitle>
          </div>
          <CardDescription>
            {rows.length} node(s) registered across {new Set(rows.map((n) => n.provider)).size} provider(s)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {rows.length === 0 ? (
            <EmptyState
              title="No nodes registered yet"
              description="Register your first VPS node to begin. The agent will enroll automatically with a one-time token."
              action={
                <div className="w-full">
                  <ActionForm action={createNodeAction} submit="Register node" />
                </div>
              }
            />
          ) : (
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Node</TableHead>
                    <TableHead className="w-36">Provider / ASN</TableHead>
                    <TableHead className="w-32">Region</TableHead>
                    <TableHead className="w-24 text-right">Endpoints</TableHead>
                    <TableHead className="w-44">Host Telemetry (Non-Proxy)</TableHead>
                    <TableHead className="w-44">Status</TableHead>
                    <TableHead className="w-32 text-right">Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((n, idx) => {
                    const online = isOnline(n.lastSeenAt);
                    const telemetry = telemetryByNode[idx];
                    return (
                      <TableRow key={n.id}>
                        <TableCell>
                          <Link href={`/nodes/${n.id}`} className="font-semibold text-indigo-600 hover:underline">
                            {n.name}
                          </Link>
                          <div className="font-mono text-xs text-slate-500">{n.publicAddress}</div>
                        </TableCell>
                        <TableCell>
                          <div className="font-medium text-slate-800">{n.provider}</div>
                          <div className="font-mono text-xs text-slate-500">{n.asn || "—"}</div>
                        </TableCell>
                        <TableCell className="text-xs text-slate-600">
                          <span className="inline-flex items-center gap-1">
                            <Globe className="h-3.5 w-3.5 text-slate-400" />
                            {n.region || "—"}
                          </span>
                        </TableCell>
                        <TableCell className="text-right font-mono tabular-nums">
                          {ibs.filter((i) => i.nodeId === n.id).length}
                        </TableCell>
                        <TableCell>
                          {telemetry && telemetry.snapshot ? (
                            <div className="flex flex-wrap items-center gap-1.5 text-xs">
                              <Badge variant={statusTone(telemetry.freshness)}>
                                {telemetry.freshness}
                              </Badge>
                              <span className="inline-flex items-center gap-1 font-mono tabular-nums text-slate-600">
                                <Cpu className="h-3 w-3 text-slate-400" />
                                {telemetry.snapshot.cpuPercent.toFixed(1)}%
                              </span>
                              <span className="inline-flex items-center gap-1 font-mono tabular-nums text-slate-600">
                                <HardDrive className="h-3 w-3 text-slate-400" />
                                {Math.round(
                                  (telemetry.snapshot.memoryUsedBytes /
                                    Math.max(1, telemetry.snapshot.memoryTotalBytes)) *
                                    100
                                )}
                                %
                              </span>
                            </div>
                          ) : (
                            <span className="text-xs text-slate-400">No host sample</span>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap items-center gap-1.5">
                            <Badge variant={statusTone(n.status)}>{n.status.replace("_", " ")}</Badge>
                            {n.status === "active" && (
                              <Badge variant={online ? "success" : "error"}>{online ? "online" : "offline"}</Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums text-slate-500">
                          {ago(n.lastSeenAt)}
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
        <Card>
          <CardHeader>
            <CardTitle>Register a node</CardTitle>
            <CardDescription>
              Issues a single-use SHA-256 hashed enrollment token. Private, loopback, and cloud metadata addresses are rejected.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ActionForm action={createNodeAction} submit="Register node">
              <input type="hidden" name="idemKey" value={idem} />
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Name">
                  <Input name="name" required placeholder="fra-2" />
                </Field>
                <Field label="Public address" hint="IP or hostname. Private, loopback and metadata ranges are rejected.">
                  <Input name="address" required placeholder="203.0.113.25" className="font-mono" />
                </Field>
                <Field label="Provider">
                  <Input name="provider" required placeholder="Hetzner" />
                </Field>
                <Field label="ASN">
                  <Input name="asn" placeholder="AS24940" className="font-mono" />
                </Field>
                <Field label="Region">
                  <Input name="region" placeholder="Falkenstein, DE" />
                </Field>
              </div>
            </ActionForm>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
