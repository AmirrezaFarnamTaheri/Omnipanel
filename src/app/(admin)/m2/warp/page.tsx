import { requirePage } from "@/lib/auth";
import { Badge, Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Field, PageHeader, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, TableWrapper } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";

export type WarpPeer = {
  id: string;
  nodeId: string;
  publicKey: string;
  allowedIps: string;
  endpoint: string;
  status: string;
  createdAt: string;
};

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) }, ...init, cache: "no-store" });
  if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`);
  return res.json();
}

export default async function WarpPage() {
  const me = await requirePage("viewer");
  const [peers, configureError] = await (async () => {
    try {
      const p = await fetchJson<{ peers: WarpPeer[] }>("/api/m2/warp/peers");
      return [p.peers, null] as [WarpPeer[], string | null];
    } catch (e) {
      return [[], e instanceof Error ? e.message : "Failed to load WARP data"];
    }
  })();

  return (
    <>
      <PageHeader
        title="WARP peers"
        subtitle="WireGuard-style VPN peers for site-to-site and client connectivity. Keypairs are exchanged per node."
      />

      {configureError && (
        <div className="mb-6 rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">{configureError}</div>
      )}

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>WARP peers</CardTitle>
          <CardDescription>{peers.length} peer(s) configured</CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">#</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead className="w-40">Public key</TableHead>
                  <TableHead className="w-32">Allowed IPs</TableHead>
                  <TableHead>Endpoint</TableHead>
                  <TableHead className="w-20">Status</TableHead>
                  <TableHead className="w-24">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {peers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7}>
                      <EmptyState title="No WARP peers yet" description="Configure your first WARP peer to enable site-to-site VPN connectivity." />
                    </TableCell>
                  </TableRow>
                ) : (
                  peers.map((p) => (
                    <TableRow key={p.id}>
                      <TableCell className="font-medium">#{p.id.slice(-8)}</TableCell>
                      <TableCell>{p.nodeId}</TableCell>
                      <TableCell className="font-mono text-xs truncate max-w-[200px]">{p.publicKey}</TableCell>
                      <TableCell className="text-xs">{p.allowedIps}</TableCell>
                      <TableCell className="text-xs">{p.endpoint}</TableCell>
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

      <Card>
        <CardHeader>
          <CardTitle>Configure WARP</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-4 text-sm text-slate-600">Generate and apply WARP configuration for a node.</p>
          <ActionForm action={configureWarp} submit="Configure WARP">
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Node ID">
                <input name="nodeId" required placeholder="edge-fra-1" className="w-full" />
              </Field>
              <Field label="Allowed IPs">
                <input name="allowedIps" required placeholder="10.0.0.0/24" className="w-full" />
              </Field>
              <Field label="Endpoint">
                <input name="endpoint" required placeholder="warp-fra.omnipanel.example.net:51820" className="w-full" />
              </Field>
            </div>
          </ActionForm>
        </CardContent>
      </Card>
    </>
  );
}

async function configureWarp(_p: { ok?: boolean; error?: string }, fd: FormData) {
  "use server";
  try {
    const res = await fetch("/api/m2/warp/configure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        nodeId: fd.get("nodeId"),
        allowedIps: fd.get("allowedIps"),
        endpoint: fd.get("endpoint"),
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { ok: false, error: err.detail || `Failed with status ${res.status}` };
    }
    return { ok: true, message: "WARP configured" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Failed to configure WARP" };
  }
}
