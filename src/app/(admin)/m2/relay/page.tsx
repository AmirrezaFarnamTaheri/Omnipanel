import { requirePage } from "@/lib/auth";
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Field, PageHeader, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, TableWrapper } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";

export type RelayNode = { id: string; name: string; address: string; status: string };
export type RelayTunnel = {
  id: number;
  sourceNode: string;
  destination: string;
  protocol: string;
  status: string;
  createdAt: string;
};

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) }, ...init, cache: "no-store" });
  if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`);
  return res.json();
}

export default async function RelayPage() {
  const me = await requirePage("viewer");
  const [nodes, tunnels, error] = await (async () => {
    try {
      const [n, t] = await Promise.all([
        fetchJson<{ nodes: RelayNode[] }>("/api/m2/relay/nodes"),
        fetchJson<{ tunnels: RelayTunnel[] }>("/api/m2/relay/tunnel"),
      ]);
      return [n.nodes, t.tunnels, null] as [RelayNode[], RelayTunnel[], string | null];
    } catch (e) {
      return [[], [], e instanceof Error ? e.message : "Failed to load relay data"];
    }
  })();

  return (
    <>
      <PageHeader
        title="Relay nodes"
        subtitle="Relay nodes add a hop between clients and edge nodes. Per-flow attribution is required for metering."
      />

      {error && (
        <div className="mb-6 rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">{error}</div>
      )}

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Relay nodes</CardTitle>
          <CardDescription>{nodes.length} relay node(s) configured</CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Node</TableHead>
                  <TableHead>Address</TableHead>
                  <TableHead className="w-20">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {nodes.map((n) => (
                  <TableRow key={n.id}>
                    <TableCell className="font-medium">{n.name}</TableCell>
                    <TableCell>{n.address}</TableCell>
                    <TableCell>
                      <Badge variant={n.status === "healthy" ? "success" : "warning"}>{n.status}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableWrapper>
        </CardContent>
      </Card>

      {me.role !== "viewer" && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Create relay tunnel</CardTitle>
          </CardHeader>
          <CardContent>
            <ActionForm action={createRelayTunnel} submit="Create tunnel">
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Source node">
                  <input name="sourceNode" required placeholder="edge-fra-1" className="w-full" />
                </Field>
                <Field label="Destination">
                  <input name="destination" required placeholder="relay-fra.omnipanel.example.net:443" className="w-full" />
                </Field>
                <Field label="Protocol">
                  <select name="protocol" className="w-full">
                    <option value="grpc">gRPC</option>
                    <option value="http">HTTP</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Relay tunnels</CardTitle>
          <CardDescription>{tunnels.length} tunnel(s) configured</CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">#</TableHead>
                  <TableHead>Source node</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead className="w-20">Protocol</TableHead>
                  <TableHead className="w-20">Status</TableHead>
                  <TableHead className="w-24">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tunnels.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6}>
                      <EmptyState title="No relay tunnels yet" description="Create your first relay tunnel to add a hop between clients and edge nodes." />
                    </TableCell>
                  </TableRow>
                ) : (
                  tunnels.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="font-medium">#{t.id}</TableCell>
                      <TableCell>{t.sourceNode}</TableCell>
                      <TableCell>{t.destination}</TableCell>
                      <TableCell>{t.protocol}</TableCell>
                      <TableCell>
                        <Badge variant={t.status === "active" ? "success" : "warning"}>{t.status}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{new Date(t.createdAt).toISOString()}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableWrapper>
        </CardContent>
      </Card>
    </>
  );
}

async function createRelayTunnel(_p: { ok?: boolean; error?: string }, fd: FormData) {
  "use server";
  try {
    const res = await fetch("/api/m2/relay/tunnel", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sourceNode: fd.get("sourceNode"),
        destination: fd.get("destination"),
        protocol: fd.get("protocol"),
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { ok: false, error: err.detail || `Failed with status ${res.status}` };
    }
    return { ok: true, message: "Relay tunnel created" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Failed to create relay tunnel" };
  }
}
