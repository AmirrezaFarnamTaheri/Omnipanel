import { db } from "@/db";
import { cdnMappings } from "@/db/schema";
import { desc } from "drizzle-orm";
import { requirePage } from "@/lib/auth";
import { listCdnProviders } from "@/lib/m2";
import { createCdnMappingAction } from "@/app/actions/m2";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";

export default async function CdnPage() {
  const me = await requirePage("viewer");
  const providers = await listCdnProviders();
  const mappings = await db.select().from(cdnMappings).orderBy(desc(cdnMappings.createdAt));
  const idem = typeof crypto !== "undefined" ? crypto.randomUUID() : "idem";

  return (
    <>
      <PageHeader
        title="CDN (Content Delivery Network)"
        subtitle="Map customer-facing domains to origin nodes. CDN runtimes are gated until admission evidence is recorded."
      />

      <Card title="Available providers" className="mb-6">
        <Table head={["Provider", "Status"]}>
          {providers.map((p) => (
            <tr key={p.id}>
              <Td className="font-medium">{p.name}</Td>
              <Td>
                <Badge tone={p.supported ? "green" : "red"}>
                  {p.supported ? "supported" : "unsupported"}
                </Badge>
              </Td>
            </tr>
          ))}
        </Table>
      </Card>

      {me.role !== "viewer" && (
        <Card title="Create CDN mapping">
          <ActionForm action={createCdnMappingAction} submit="Create mapping">
            <div className="grid gap-4 md:grid-cols-3">
              <Field label="Domain">
                <input name="domain" required placeholder="cdn.example.com" className={inputCls} />
              </Field>
              <Field label="Origin">
                <input name="origin" required placeholder="203.0.113.10:443" className={inputCls} />
              </Field>
              <Field label="Provider">
                <select name="provider" className={inputCls}>
                  {providers.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          </ActionForm>
        </Card>
      )}

      <Card title="CDN mappings" className="mt-6">
        <Table
          head={["Domain", "Origin", "Provider", "Status", "Created"]}
          empty={mappings.length ? undefined : "No CDN mappings yet."}
        >
          {mappings.map((m) => (
            <tr key={m.id}>
              <Td className="font-medium">{m.domain}</Td>
              <Td>{m.origin}</Td>
              <Td>{m.provider}</Td>
              <Td>
                <Badge tone={m.status === "active" ? "green" : "amber"}>
                  {m.status}
                </Badge>
              </Td>
              <Td className="text-xs">{new Date(m.createdAt).toISOString()}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
