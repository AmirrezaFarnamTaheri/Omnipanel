import { requirePage } from "@/lib/auth";
import { db } from "@/db";
import { nodes } from "@/db/schema";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";
import type { ActionState } from "@/lib/action-helpers";

export type BpbPolicy = {
  id: number;
  nodeId: number;
  bandwidthLimit: number;
  priority: number;
  updatedAt: string;
};

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`);
  return res.json();
}

export default async function BpbPage() {
  const me = await requirePage("viewer");
  const nodeRows = await db
    .select({ id: nodes.id, name: nodes.name })
    .from(nodes)
    .orderBy(nodes.id);

  let policy: BpbPolicy | null = null;
  let policyError: string | null = null;
  if (nodeRows.length > 0) {
    try {
      const result = await fetchJson<{ policy: BpbPolicy | null }>(
        `/api/m2/bpb/policy?nodeId=${nodeRows[0].id}`
      );
      policy = result.policy;
    } catch (e) {
      policyError = e instanceof Error ? e.message : "Failed to load BPB policy";
    }
  }

  return (
    <>
      <PageHeader
        title="BPB (Bandwidth Policy Bridge)"
        subtitle="BPB enforces per-user rate limits on shaped egress. BPB is a hard-quota candidate once evidence is verified."
      />

      {policyError && (
        <div className="mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
          {policyError}
        </div>
      )}

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
          <ActionForm action={updateBpbPolicy} submit="Update policy">
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

async function updateBpbPolicy(_p: ActionState, fd: FormData): Promise<ActionState> {
  try {
    const res = await fetch("/api/m2/bpb/policy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nodeId: Number(fd.get("nodeId")),
        bandwidthLimit: Number(fd.get("bandwidthLimit")),
        priority: Number(fd.get("priority")),
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { ok: false, error: err.detail || `Failed with status ${res.status}` };
    }
    return { ok: true, message: "BPB policy updated" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Failed to update BPB policy" };
  }
}
