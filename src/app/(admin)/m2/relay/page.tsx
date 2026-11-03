import { requirePage } from "@/lib/auth";
import { listRelayNodes, listRelayTunnels } from "@/lib/m2";
import { createRelayTunnelAction } from "@/app/actions/m2";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";

export default async function RelayPage() {
  const me = await requirePage("viewer");
  const nodes = await listRelayNodes();
  const tunnels = await listRelayTunnels();

  return (
    <>
      <PageHeader
        title="Relay nodes"
        subtitle="Relay nodes add a hop between clients and edge nodes. Per-flow attribution is required for metering."
      />

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
          <ActionForm action={createRelayTunnelAction} submit="Create tunnel">
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
