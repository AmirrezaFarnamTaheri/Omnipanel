import { randomUUID } from "node:crypto";
import Link from "next/link";
import { db } from "@/db";
import { inbounds, nodes } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { ago, isOnline } from "@/lib/format";
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
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
} from "@/components/ui";

export default async function NodesPage() {
  const me = await requirePage("viewer");
  const rows = await db.select().from(nodes).orderBy(nodes.id);
  const ibs = await db.select({ nodeId: inbounds.nodeId }).from(inbounds);
  const idem = randomUUID();

  return (
    <>
      <PageHeader
        title="Nodes"
        subtitle="Each VPS runs a headless agent. Registration issues a single-use enrollment token; identity is derived from that token."
      />
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Registered nodes</CardTitle>
          <CardDescription>{rows.length} node(s) registered across {new Set(rows.map((n) => n.provider)).size} provider(s)</CardDescription>
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
            <>
              <TableWrapper>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Node</TableHead>
                      <TableHead className="w-32">Provider / ASN</TableHead>
                      <TableHead className="w-20">Region</TableHead>
                      <TableHead className="w-12">Endpoints</TableHead>
                      <TableHead className="w-40">Status</TableHead>
                      <TableHead className="w-32">Last seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((n) => {
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
                          <TableCell>{n.region || "—"}</TableCell>
                          <TableCell>{ibs.filter((i) => i.nodeId === n.id).length}</TableCell>
                          <TableCell>
                            <Badge variant="secondary">{n.status.replace("_", " ")}</Badge>
                            {n.status === "active" && (
                              <Badge variant={online ? "success" : "error"}>{online ? "online" : "offline"}</Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-xs">{ago(n.lastSeenAt)}</TableCell>
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
            <CardTitle>Register a node</CardTitle>
          </CardHeader>
          <CardContent>
            <ActionForm action={createNodeAction} submit="Register node">
              <input type="hidden" name="idemKey" value={idem} />
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Name">
                  <input name="name" required placeholder="fra-1" className="w-full" />
                </Field>
                <Field label="Public address" hint="IP or hostname. Private, loopback and metadata ranges are rejected.">
                  <input name="address" required placeholder="203.0.113.10" className="w-full" />
                </Field>
                <Field label="Provider">
                  <input name="provider" required placeholder="Hetzner" className="w-full" />
                </Field>
                <Field label="ASN">
                  <input name="asn" placeholder="AS24940" className="w-full" />
                </Field>
                <Field label="Region">
                  <input name="region" placeholder="Falkenstein, DE" className="w-full" />
                </Field>
              </div>
            </ActionForm>
          </CardContent>
        </Card>
      )}
    </>
  );
}
