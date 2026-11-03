import { requirePage } from "@/lib/auth";
import { updateBpbPolicyAction } from "@/app/actions/m2";
import { getBpbPolicy } from "@/lib/m2";
import { db } from "@/db";
import { nodes } from "@/db/schema";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";

export default async function BpbPage() {
  const me = await requirePage("viewer");
  const nodeRows = await db.select({ id: nodes.id, name: nodes.name }).from(nodes).orderBy(nodes.id);
  // Try to get BPB policy for the first node (or none)
  let policy: any = null;
  if (nodeRows.length > 0) {
    const result = await getBpbPolicy(nodeRows[0].id);
    if (result) policy = result;
  }

  return (
    <>
      <PageHeader
        title="BPB (Bandwidth Policy Bridge)"
        subtitle="BPB enforces per-user rate limits on shaped egress. BPB is a hard-quota candidate once evidence is verified."
      />

      <Card title="Current policy" className="mb-6">
        {policy ? (
          <Table head={["Property", "Value"]}>
            <tr>
              <Td className="font-medium">Node</Td>
              <Td>{policy.nodeId}</Td>
            </tr>
            <tr>
              <Td className="font-medium">Bandwidth limit</Td>
              <Td>{policy.bandwidthLimit} kbps</Td>
            </tr>
            <tr>
              <Td className="font-medium">Priority</Td>
              <Td>{policy.priority}</Td>
            </tr>
            <tr>
              <Td className="font-medium">Updated</Td>
              <Td className="text-xs">{new Date(policy.updatedAt).toISOString()}</Td>
            </tr>
          </Table>
        ) : (
          <p className="text-sm text-slate-500">No BPB policy configured yet.</p>
        )}
      </Card>

      {me.role !== "viewer" && (
        <Card title="Update BPB policy">
          <ActionForm action={updateBpbPolicyAction} submit="Update policy">
            <input type="hidden" name="nodeId" value={String(nodeRows[0]?.id ?? "")} />
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Node">
                <select name="nodeId" className={inputCls}>
                  {nodeRows.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Bandwidth limit (kbps)">
                <input name="bandwidthLimit" type="number" required defaultValue="10000" className={inputCls} />
              </Field>
              <Field label="Priority">
                <input name="priority" type="number" required defaultValue="0" className={inputCls} />
              </Field>
            </div>
          </ActionForm>
        </Card>
      )}
    </>
  );
}
