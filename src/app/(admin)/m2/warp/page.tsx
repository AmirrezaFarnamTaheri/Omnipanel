import { requirePage } from "@/lib/auth";
import { listWarpPeers } from "@/lib/m2";
import { configureWarpAction } from "@/app/actions/m2";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";

export default async function WarpPage() {
  const me = await requirePage("viewer");
  const peers = await listWarpPeers();

  return (
    <>
      <PageHeader
        title="WARP"
        subtitle="WARP provides client-to-edge WireGuard connectivity. WARP runtimes are gated until admission evidence is recorded."
      />

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
          <ActionForm action={configureWarpAction} submit="Configure">
            <div className="grid gap-4 md:grid-cols-2">
              <Field label="Interface name">
                <input name="interfaceName" required placeholder="wg0" className={inputCls} />
              </Field>
              <Field label="Private key">
                <input name="privateKey" required placeholder="base64-encoded private key" className={inputCls} />
              </Field>
              <Field label="Peer count">
                <input
                  name="peerCount"
                  type="number"
                  defaultValue="0"
                  min="0"
                  className={inputCls}
                />
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
