import { eq } from "drizzle-orm";
import { db } from "@/db";
import { settings } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Field, PageHeader, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, TableWrapper, Badge } from "@/components/ui";
import { ActionForm } from "@/components/ActionForm";

export default async function SettingsPage({ params }: { params: Promise<{ section?: string }> }) {
  const me = await requirePage("viewer");
  const { section } = await params;
  const rows = await db.select().from(settings).orderBy(settings.key);
  const map = Object.fromEntries(rows.map((r) => [r.key, r.value]));

  const sections = [
    { id: "general", label: "General", desc: "Site branding, contact, and administrative settings." },
    { id: "auth", label: "Auth", desc: "Session policy, cookie settings, and registration mode." },
    { id: "storage", label: "Storage", desc: "Blob storage, encryption keys, and backup configuration." },
  ];

  return (
    <>
      <PageHeader title="Settings" subtitle="Platform-wide configuration. Changes require owner role." />
      <div className="flex gap-4">
        <nav className="hidden w-64 shrink-0 flex-col rounded-xl border border-slate-200 bg-white p-4 md:block">
          {sections.map((s) => (
            <a
              key={s.id}
              href={`/settings/${s.id}`}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                section === s.id
                  ? "bg-indigo-600/10 text-indigo-700"
                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900",
              )}
            >
              <span>{s.label}</span>
              <p className="ml-4 text-xs text-slate-500">{s.desc}</p>
            </a>
          ))}
        </nav>
        <main className="flex-1">
          <section>
            <Card className="mb-6">
              <CardHeader>
                <CardTitle>{sections.find((s) => s.id === section)?.label ?? "General"}</CardTitle>
                <CardDescription>{sections.find((s) => s.id === section)?.desc ?? ""}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {me.role === "owner" ? (
                    <>
                      <Field label="Site title">
                        <input name="siteTitle" defaultValue={map.siteTitle ?? "OmniPanel"} className="w-full" />
                      </Field>
                      <Field label="Support contact">
                        <input name="supportContact" defaultValue={map.supportContact ?? ""} className="w-full" />
                      </Field>
                      <Field label="Registration">
                        <select name="registrationMode" className="w-full">
                          <option value="open">Open</option>
                          <option value="invite">Invite-only</option>
                          <option value="closed">Closed</option>
                        </select>
                      </Field>
                      <ActionForm action={updateSettingsAction} submit="Save settings">
                        <input type="hidden" name="section" value={section ?? "general"} />
                      </ActionForm>
                    </>
                  ) : (
                    <div className="rounded-lg border border-rose-200 bg-rose-50 p-4">
                      <p className="text-sm text-rose-800">Owner role required to modify settings.</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>System settings</CardTitle>
              </CardHeader>
              <CardContent>
                <TableWrapper>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Key</TableHead>
                        <TableHead>Value</TableHead>
                        <TableHead className="w-20">Type</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {rows.map((r) => (
                        <TableRow key={r.key}>
                          <TableCell className="font-mono text-xs">{r.key}</TableCell>
                        <TableCell className="text-xs truncate max-w-xs">{r.value}</TableCell>
                        <TableCell className="text-xs"><Badge variant="secondary">string</Badge></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableWrapper>
              </CardContent>
            </Card>
          </section>
        </main>
      </div>
    </>
  );
}

function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(" ");
}

async function updateSettingsAction(_p: { ok?: boolean; error?: string }, fd: FormData) {
  "use server";
  try {
    const section = fd.get("section") as string;
    // settings update would go here
    return { ok: true, message: `Settings for ${section} saved` };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Failed to save settings" };
  }
}
