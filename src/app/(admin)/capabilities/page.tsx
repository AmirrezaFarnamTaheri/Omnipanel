import { desc } from "drizzle-orm";
import { db } from "@/db";
import { capabilityEvidence } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { CLIENT_REGISTRY, RUNTIME_CAPABILITIES, loadEvidence, hasEvidence } from "@/lib/capabilities";
import { ago } from "@/lib/format";
import { recordEvidenceAction } from "@/app/actions/system";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, Table, Td } from "@/components/ui";

export default async function CapabilitiesPage() {
  const me = await requirePage("viewer");
  const ev = await loadEvidence();
  const log = await db.select().from(capabilityEvidence).orderBy(desc(capabilityEvidence.id)).limit(10);
  const claims = ["admission", "metering", "revocation", "hardQuota"] as const;
  return (
    <>
      <PageHeader
        title="Capability registry"
        subtitle="Unknown capability means unsupported. Gated runtimes and hard-quota claims stay disabled until lab evidence is recorded by an owner."
      />
      <Card title="Runtime drivers" className="mb-6">
        <div className="space-y-5">
          {RUNTIME_CAPABILITIES.map((c) => (
            <div key={c.key} className="rounded-lg border border-slate-200 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="font-semibold">{c.key}</h3>
                <Badge tone="slate">{c.transport.toUpperCase()} {c.defaultPort}</Badge>
                {c.gated && <Badge tone="amber">gated</Badge>}
                {c.hardQuotaCandidate && <Badge tone="blue">hard-quota candidate</Badge>}
              </div>
              <p className="mt-1 text-sm text-slate-600">{c.notes}</p>
              <dl className="mt-3 grid gap-x-6 gap-y-1 text-sm md:grid-cols-2">
                <div><dt className="inline text-slate-500">Metering: </dt><dd className="inline">{c.metering.source} ({c.metering.counter})</dd></div>
                <div><dt className="inline text-slate-500">Direction: </dt><dd className="inline">{c.metering.direction}</dd></div>
                <div><dt className="inline text-slate-500">New sessions on revoke: </dt><dd className="inline">{c.revocation.newSessions}</dd></div>
                <div><dt className="inline text-slate-500">Existing sessions: </dt><dd className="inline">{c.revocation.existingSessions}</dd></div>
                <div className="md:col-span-2"><dt className="inline text-slate-500">Known gap: </dt><dd className="inline">{c.metering.note}</dd></div>
              </dl>
              <div className="mt-3 flex flex-wrap gap-2">
                {claims.map((cl) => (
                  <Badge key={cl} tone={hasEvidence(ev, c.key, cl) ? "green" : ev.get(`${c.key}|${cl}`) === "failed" ? "red" : "slate"}>
                    {cl}: {ev.get(`${c.key}|${cl}`) ?? "no evidence"}
                  </Badge>
                ))}
              </div>
              {me.role === "owner" && (
                <ActionForm action={recordEvidenceAction} submit="Record evidence" variant="ghost" className="mt-3">
                  <input type="hidden" name="key" value={c.key} />
                  <div className="grid gap-3 md:grid-cols-4">
                    <Field label="Claim">
                      <select name="claim" className={inputCls}>{claims.map((cl) => <option key={cl}>{cl}</option>)}</select>
                    </Field>
                    <Field label="Result">
                      <select name="status" className={inputCls}><option>verified</option><option>failed</option></select>
                    </Field>
                    <div className="md:col-span-2">
                      <Field label="Lab run reference"><input name="note" required minLength={10} placeholder="make gate-lab run 2026-11-03, 1 GB payload ±0.5%" className={inputCls} /></Field>
                    </div>
                  </div>
                </ActionForm>
              )}
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Client formats">
          <Table head={["Format", "Protocols", "Failover", "Evidence"]}>
            {CLIENT_REGISTRY.map((c) => (
              <tr key={c.id}>
                <Td className="font-medium">{c.label}</Td>
                <Td className="text-xs">{c.protocols.join(", ")}</Td>
                <Td className="text-xs">{c.failover}</Td>
                <Td><Badge tone="amber">{c.evidence}</Badge></Td>
              </tr>
            ))}
          </Table>
        </Card>
        <Card title="Recent evidence records">
          <Table head={["Capability", "Claim", "Result", "By", "When"]} empty={log.length ? undefined : "No evidence recorded yet."}>
            {log.map((l) => (
              <tr key={l.id}>
                <Td className="text-xs">{l.capabilityKey}</Td>
                <Td>{l.claim}</Td>
                <Td><Badge tone={l.status === "verified" ? "green" : "red"}>{l.status}</Badge></Td>
                <Td className="text-xs">{l.recordedBy}</Td>
                <Td className="text-xs">{ago(l.recordedAt)}</Td>
              </tr>
            ))}
          </Table>
        </Card>
      </div>
    </>
  );
}
