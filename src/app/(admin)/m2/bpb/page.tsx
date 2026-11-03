import { requirePage } from "@/lib/auth";
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Field, PageHeader, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, TableWrapper } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";

export type BpbPolicy = {
  id: number;
  rule: string;
  description: string;
  status: string;
  createdAt: string;
};

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) }, ...init, cache: "no-store" });
  if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`);
  return res.json();
}

export default async function BpbPage() {
  const me = await requirePage("viewer");
  const [policies, error] = await (async () => {
    try {
      const p = await fetchJson<{ policies: BpbPolicy[] }>("/api/m2/bpb/policy");
      return [p.policies, null] as [BpbPolicy[], string | null];
    } catch (e) {
      return [[], e instanceof Error ? e.message : "Failed to load BPB data"];
    }
  })();

  return (
    <>
      <PageHeader
        title="BPB (Border Patrol Bouncer)"
        subtitle="Unqualified legacy prototype. BPB Workers are external sources, not managed quota enforcers. Do not use these policies as enforcement guarantees."
      />

      {error && (
        <div className="mb-6 rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">{error}</div>
      )}

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>BPB policies</CardTitle>
          <CardDescription>{policies.length} policy(ies) configured</CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">#</TableHead>
                  <TableHead>Rule</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead className="w-20">Status</TableHead>
                  <TableHead className="w-24">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5}>
                      <EmptyState title="No BPB policies yet" description="Create your first BPB policy to govern edge traffic." />
                    </TableCell>
                  </TableRow>
                ) : (
                  policies.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="font-medium">#{p.id}</TableCell>
                      <TableCell>{p.rule}</TableCell>
                      <TableCell>{p.description}</TableCell>
                      <TableCell>
                        <Badge variant={p.status === "active" ? "success" : "warning"}>{p.status}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{new Date(p.createdAt).toISOString()}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableWrapper>
        </CardContent>
      </Card>

      {me.role !== "viewer" && (
        <Card>
          <CardHeader>
            <CardTitle>Create BPB policy</CardTitle>
          </CardHeader>
          <CardContent>
            <ActionForm action={createBpbPolicy} submit="Create policy">
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Rule">
                  <input name="rule" required placeholder="deny-inbound-from-rogue-nodes" className="w-full" />
                </Field>
                <Field label="Description">
                  <input name="description" required placeholder="Block traffic from nodes without verified admission" className="w-full" />
                </Field>
                <Field label="Status">
                  <select name="status" className="w-full">
                    <option value="active">active</option>
                    <option value="inactive">inactive</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </CardContent>
        </Card>
      )}
    </>
  );
}

async function createBpbPolicy(_p: { ok?: boolean; error?: string }, fd: FormData) {
  "use server";
  try {
    const res = await fetch("/api/m2/bpb/policy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rule: fd.get("rule"),
        description: fd.get("description"),
        status: fd.get("status"),
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { ok: false, error: err.detail || `Failed with status ${res.status}` };
    }
    return { ok: true, message: "BPB policy created" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Failed to create BPB policy" };
  }
}
