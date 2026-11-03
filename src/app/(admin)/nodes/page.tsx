import { randomUUID } from "node:crypto";
import Link from "next/link";
import { db } from "@/db";
import { inbounds, nodes } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { ago, isOnline } from "@/lib/format";
import { createNodeAction } from "@/app/actions/infra";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, statusTone, Table, Td } from "@/components/ui";

export default async function NodesPage() {
  const me = await requirePage("viewer");
  const rows = await db.select().from(nodes).orderBy(nodes.id);
  const ibs = await db.select({ nodeId: inbounds.nodeId }).from(inbounds);
  const idem = randomUUID();
  return (
    <>
      <PageHeader title="Nodes" subtitle="Each VPS runs a headless agent. Registration issues a single-use enrollment token; identity is derived from that token." />
      <Card className="mb-6">
        <Table head={["Node", "Provider / ASN", "Region", "Endpoints", "Status", "Last seen"]} empty={rows.length ? undefined : "No nodes registered."}>
          {rows.map((n) => {
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
                  {n.provider} <span className="text-xs text-slate-500">{n.asn}</span>
                </Td>
                <Td>{n.region || "—"}</Td>
                <Td>{ibs.filter((i) => i.nodeId === n.id).length}</Td>
                <Td>
                  <Badge tone={statusTone(n.status)}>{n.status.replace("_", " ")}</Badge>{" "}
                  {n.status === "active" && <Badge tone={online ? "green" : "red"}>{online ? "online" : "offline"}</Badge>}
                </Td>
                <Td>{ago(n.lastSeenAt)}</Td>
              </tr>
            );
          })}
        </Table>
      </Card>
      {me.role !== "viewer" && (
        <Card title="Register a node">
          <ActionForm action={createNodeAction} submit="Register node">
            <input type="hidden" name="idemKey" value={idem} />
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Name"><input name="name" required placeholder="fra-1" className={inputCls} /></Field>
              <Field label="Public address" hint="IP or hostname. Private, loopback and metadata ranges are rejected."><input name="address" required placeholder="203.0.113.10" className={inputCls} /></Field>
              <Field label="Provider"><input name="provider" required placeholder="Hetzner" className={inputCls} /></Field>
              <Field label="ASN"><input name="asn" placeholder="AS24940" className={inputCls} /></Field>
              <Field label="Region"><input name="region" placeholder="Falkenstein, DE" className={inputCls} /></Field>
            </div>
          </ActionForm>
        </Card>
      )}
    </>
  );
}
