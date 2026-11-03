import { requirePage } from "@/lib/auth";
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Field, PageHeader, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, TableWrapper } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";

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
  const res = await fetch(path, { headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) }, ...init, cache: "no-store" });
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
        <div className="mb-6 rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-800">{error}</div>
      )}

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Available providers</CardTitle>
          <CardDescription>{providers.length} CDN provider(s) available</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-4">
            {providers.map((p) => (
              <div key={p.id} className="rounded-lg border border-slate-200 p-4 flex flex-col items-center text-center">
                <div className="w-10 h-10 rounded-full flex items-center justify-center mb-2 {p.supported ? 'bg-emerald-100 text-emerald-600' : 'bg-slate-100 text-slate-600'}">
                  <span className="text-lg">{p.supported ? "✅" : "❌"}</span>
                </div>
                <h4 className="font-semibold">{p.name}</h4>
                <Badge variant={p.supported ? "success" : "error"}>{p.supported ? "supported" : "unsupported"}</Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {me.role !== "viewer" && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Create CDN mapping</CardTitle>
          </CardHeader>
          <CardContent>
            <ActionForm action={createCdnMapping} submit="Create mapping">
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Domain">
                  <input name="domain" required placeholder="cdn.example.com" className="w-full" />
                </Field>
                <Field label="Origin">
                  <input name="origin" required placeholder="203.0.113.10:443" className="w-full" />
                </Field>
                <Field label="Provider">
                  <select name="provider" className="w-full">
                    {providers.map((p) => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                </Field>
              </div>
            </ActionForm>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>CDN mappings</CardTitle>
          <CardDescription>{mappings.length} mapping(s) configured</CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead>Origin</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead className="w-20">Status</TableHead>
                  <TableHead className="w-24">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mappings.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5}>
                      <EmptyState title="No CDN mappings yet" description="Create your first CDN mapping to route customer traffic through a CDN provider." />
                    </TableCell>
                  </TableRow>
                ) : (
                  mappings.map((m) => (
                    <TableRow key={m.id}>
                      <TableCell className="font-medium">{m.domain}</TableCell>
                      <TableCell>{m.origin}</TableCell>
                      <TableCell>{m.provider}</TableCell>
                      <TableCell>
                        <Badge variant={m.status === "active" ? "success" : "warning"}>{m.status}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{new Date(m.createdAt).toISOString()}</TableCell>
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

async function createCdnMapping(_p: { ok?: boolean; error?: string }, fd: FormData) {
  "use server";
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
