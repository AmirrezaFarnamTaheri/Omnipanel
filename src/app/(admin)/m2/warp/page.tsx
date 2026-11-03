import { requirePage } from "@/lib/auth";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";
import type { ActionState } from "@/lib/action-helpers";

export type WarpPeer = { id: string; publicKey: string; endpoint: string; status: string };

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`);
  return res.json();
}

export default async function WarpPage() {
  const me = await requirePage("viewer");
  const [peers, error] = await (async () => {
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
        title="WARP"
        subtitle="WARP provides client-to-edge WireGuard connectivity. WARP runtimes are gated until admission evidence is recorded."
      />

      {error && (
        <div className="mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
          {error}
        </div>
      )}

      <Card title="WARP peers" className="mb-6">
        <Table head={["Peer ID", "Public key", "Endpoint", "Status"]}>
          {peers.map((p) => (
            <tr key={p.id}>
              <Td className="font-medium">{p.id}</Td>
              <Td className="text-xs">{p.publicKey || "—"}</Td>
              <Td>{p.endpoint}</Td>
              <Td>
                <Badge tone={p.status === "connected" ? "green" : "amber"}>
                  {p.status}
                </Badge>
              </Td>
            </tr>
          ))}
        </Table>
      </Card>

      {me.role !== "viewer" && (
        <Card title="Configure WARP interface">
          <ActionForm action={configureWarp} submit="Configure">
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="Interface name">
                <input name="interfaceName" required placeholder="wg0" className={inputCls} />
              </Field>
              <Field label="Private key">
                <input name="privateKey" required placeholder="base64-encoded private key" className={inputCls} />
              </Field>
              <Field label="Peer count">
                <input name="peerCount" type="number" defaultValue="0" min="0" className={inputCls} />
              </Field>
              <div className="md:col-span-2 text-xs text-slate-500">
                Add peer public keys and endpoints as additional fields named peer0PublicKey, peer0Endpoint, etc.
              </div>
            </div>
          </ActionForm>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2 mt-6">
        <Card title="Peer list">
          {peers.length === 0 ? (
            <p className="text-sm text-slate-500">No WARP peers configured.</p>
          ) : (
            <ul className="space-y-2">
              {peers.map((p) => (
                <li key={p.id} className="flex justify-between items-center p-2 rounded-lg border border-slate-100 bg-slate-50">
                  <span className="text-sm">{p.id}</span>
                  <Badge tone={p.status === "connected" ? "green" : "amber"}>
                    {p.status}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}

async function configureWarp(_p: ActionState, fd: FormData): Promise<ActionState> {
  try {
    const peerCount = Number(fd.get("peerCount")) || 0;
    const peers: Array<{ publicKey: string; endpoint: string }> = [];
    for (let i = 0; i < peerCount; i++) {
      const pk = fd.get(`peer${i}PublicKey`);
      const ep = fd.get(`peer${i}Endpoint`);
      if (pk && ep) peers.push({ publicKey: String(pk), endpoint: String(ep) });
    }
    const res = await fetch("/api/m2/warp/configure", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        interfaceName: fd.get("interfaceName"),
        privateKey: fd.get("privateKey"),
        peers,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { ok: false, error: err.detail || `Failed with status ${res.status}` };
    }
    return { ok: true, message: "WARP interface configured" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Failed to configure WARP" };
  }
}
