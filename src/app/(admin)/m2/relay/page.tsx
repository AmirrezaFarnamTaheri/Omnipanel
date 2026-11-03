import { requirePage } from "@/lib/auth";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";
import type { ActionState } from "@/lib/action-helpers";

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
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
    cache: "no-store",
  });
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
        <div className="mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
          {error}
        </div>
      )}

      <Card title="Relay nodes" className="mb-6">
        <Table head={["Node", "Address", "Status"]}>
          {nodes.map((n) => (
            <tr key={n.id}>
              <Td className="font-medium">{n.name}</Td>
              <Td>{n.address}</Td>
              <Td>
                <Badge tone={n.status === "healthy" ? "green" : "amber"}>
                  {n.status}
                </Badge>
              </Td>
            </tr>
          ))}
        </Table>
      </Card>

      {me.role !== "viewer" && (
        <Card title="Create relay tunnel">
          <ActionForm action={createRelayTunnel} submit="Create tunnel">
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Source node">
                <input name="sourceNode" required placeholder="edge-fra-1" className={inputCls} />
              </Field>
              <Field label="Destination">
                <input
                  name="destination"
                  required
                  placeholder="relay-fra.omnipanel.example.net:443"
                  className={inputCls}
                />
              </Field>
              <Field label="Protocol">
                <select name="protocol" className={inputCls}>
                  <option value="grpc">gRPC</option>
                  <option value="http">HTTP</option>
                </select>
              </Field>
            </div>
          </ActionForm>
        </Card>
      )}

      <Card title="Relay tunnels" className="mt-6">
        <Table
          head={["#", "Source node", "Destination", "Protocol", "Status", "Created"]}
          empty={tunnels.length ? undefined : "No relay tunnels yet."}
        >
          {tunnels.map((t) => (
            <tr key={t.id}>
              <Td className="font-medium">#{t.id}</Td>
              <Td>{t.sourceNode}</Td>
              <Td>{t.destination}</Td>
              <Td>{t.protocol}</Td>
              <Td>
                <Badge tone={t.status === "active" ? "green" : "amber"}>
                  {t.status}
                </Badge>
              </Td>
              <Td className="text-xs">{new Date(t.createdAt).toISOString()}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}

async function createRelayTunnel(_p: ActionState, fd: FormData): Promise<ActionState> {
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
