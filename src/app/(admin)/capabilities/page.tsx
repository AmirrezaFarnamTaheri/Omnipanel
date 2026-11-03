import { desc } from "drizzle-orm";
import { db } from "@/db";
import { capabilityEvidence } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { CLIENT_REGISTRY, RUNTIME_CAPABILITIES, loadEvidence, hasEvidence } from "@/lib/capabilities";
import { ago } from "@/lib/format";
import { recordEvidenceAction } from "@/app/actions/system";
import { ActionForm } from "@/components/ActionForm";
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  Field,
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
} from "@/components/ui";

const CLAIMS = ["admission", "metering", "revocation", "hardQuota"] as const;

export default async function CapabilitiesPage() {
  const me = await requirePage("viewer");
  const ev = await loadEvidence();
  const log = await db.select().from(capabilityEvidence).orderBy(desc(capabilityEvidence.id)).limit(10);

  return (
    <>
      <PageHeader
        title="Capability registry"
        subtitle="Unknown capability means unsupported. Gated runtimes and hard-quota claims stay disabled until lab evidence is recorded by an owner."
      />

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Runtime drivers</CardTitle>
          <CardDescription>Each runtime driver must have verified evidence before it can be used in production.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {RUNTIME_CAPABILITIES.map((c) => (
              <div key={c.key} className="rounded-xl border border-slate-200 overflow-hidden">
                <div className="bg-slate-50 px-4 py-3 border-b border-slate-200">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <h3 className="font-semibold">{c.key}</h3>
                    <Badge variant="outline">{c.transport.toUpperCase()} {c.defaultPort}</Badge>
                    {c.gated && <Badge variant="warning">gated</Badge>}
                    {c.hardQuotaCandidate && <Badge variant="info">hard-quota candidate</Badge>}
                  </div>
                  <p className="text-sm text-slate-600">{c.notes}</p>
                </div>
                <div className="p-4">
                  <dl className="grid gap-y-2 text-sm md:grid-cols-3">
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs text-slate-500 uppercase">Metering</dt>
                      <dd className="text-sm">{c.metering.source}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs text-slate-500 uppercase">Counter</dt>
                      <dd className="text-sm">{c.metering.counter}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs text-slate-500 uppercase">Direction</dt>
                      <dd className="text-sm">{c.metering.direction}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs text-slate-500 uppercase">New sessions on revoke</dt>
                      <dd className="text-sm">{c.revocation.newSessions}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs text-slate-500 uppercase">Existing sessions</dt>
                      <dd className="text-sm">{c.revocation.existingSessions}</dd>
                    </div>
                    <div className="col-span-3">
                      <dt className="text-xs text-slate-500 uppercase">Known gap</dt>
                      <dd className="text-sm">{c.metering.note}</dd>
                    </div>
                  </dl>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {CLAIMS.map((cl) => (
                      <Badge
                        key={cl}
                        variant={
                          hasEvidence(ev, c.key, cl)
                            ? "success"
                            : ev.get(`${c.key}|${cl}`) === "failed"
                              ? "error"
                              : "secondary"
                        }
                      >
                        {cl}: {ev.get(`${c.key}|${cl}`) ?? "no evidence"}
                      </Badge>
                    ))}
                  </div>
                  {me.role === "owner" && (
                    <div className="mt-4 pt-4 border-t border-slate-200">
                      <ActionForm action={recordEvidenceAction} submit="Record evidence" variant="outline" size="sm">
                        <input type="hidden" name="key" value={c.key} />
                        <div className="grid gap-3 md:grid-cols-3 mt-3">
                          <Field label="Claim">
                            <select name="claim" className="w-full">
                              {CLAIMS.map((cl) => (
                                <option key={cl}>{cl}</option>
                              ))}
                            </select>
                          </Field>
                          <Field label="Result">
                            <select name="status" className="w-full">
                              <option>verified</option>
                              <option>failed</option>
                            </select>
                          </Field>
                          <Field label="Lab run reference">
                            <input name="note" required minLength={10} placeholder="make gate-lab run 2026-11-03, 1 GB payload ±0.5%" className="w-full" />
                          </Field>
                        </div>
                      </ActionForm>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Client formats</CardTitle>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Format</TableHead>
                    <TableHead className="w-32">Protocols</TableHead>
                    <TableHead className="w-24">Failover</TableHead>
                    <TableHead>Evidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {CLIENT_REGISTRY.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell className="font-medium">{c.label}</TableCell>
                      <TableCell className="text-xs">{c.protocols.join(", ")}</TableCell>
                      <TableCell className="text-xs">{c.failover}</TableCell>
                      <TableCell>
                        <Badge variant="info">{c.evidence}</Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableWrapper>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent evidence records</CardTitle>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Capability</TableHead>
                    <TableHead>Claim</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead className="w-24">By</TableHead>
                    <TableHead className="w-24">When</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {log.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5}>
                        <EmptyState title="No evidence recorded yet" description="Record lab evidence for each capability claim." />
                      </TableCell>
                    </TableRow>
                  ) : (
                    log.map((l) => (
                      <TableRow key={l.id}>
                        <TableCell className="text-xs">{l.capabilityKey}</TableCell>
                        <TableCell>{l.claim}</TableCell>
                        <TableCell>
                          <Badge variant={l.status === "verified" ? "success" : "error"}>{l.status}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{l.recordedBy}</TableCell>
                        <TableCell className="text-xs">{ago(l.recordedAt)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableWrapper>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
