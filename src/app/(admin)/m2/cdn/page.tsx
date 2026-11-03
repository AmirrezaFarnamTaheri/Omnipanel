import { requirePage } from "@/lib/auth";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";
import type { ActionState } from "@/lib/action-helpers";

export type CdnProvider = { id: string; name: string; supported: boolean };
export type CdnMapping = {
  id: number;
  domain: string;
  origin: string;
  provider: string;
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

export default async function CdnPage() {
  const me = await requirePage("viewer");
  const [providers, mappings, error] = await (async () => {
    try {
      const [p, m] = await Promise.all([
        fetchJson<{ providers: CdnProvider[] }>("/api/m2/cdn/providers"),
        fetchJson<{ mappings: CdnMapping[] }>("/api/m2/cdn/mapping"),
      ]);
      return [p.providers, m.mappings, null] as [CdnProvider[], CdnMapping[], string | null];
    } catch (e) {
      return [[], [], e instanceof Error ? e.message : "Failed to load CDN data"];
    }
  })();

  return (
    <>
      <PageHeader
        title="CDN (Content Delivery Network)"
        subtitle="Map customer-facing domains to origin nodes. CDN runtimes are gated until admission evidence is recorded."
      />

      {error && (
        <div className="mb-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
          {error}
        </div>
      )}

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
          <ActionForm action={createCdnMapping} submit="Create mapping">
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

async function createCdnMapping(_p: ActionState, fd: FormData): Promise<ActionState> {
  try {
    const res = await fetch("/api/m2/cdn/mapping", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domain: fd.get("domain"),
        origin: fd.get("origin"),
        provider: fd.get("provider"),
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return { ok: false, error: err.detail || `Failed with status ${res.status}` };
    }
    return { ok: true, message: "CDN mapping created" };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Failed to create CDN mapping" };
  }
}
