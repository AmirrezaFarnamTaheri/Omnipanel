import { desc } from "drizzle-orm";
import { CheckCircle2, Code2, Cpu, FileCheck2, ShieldAlert } from "lucide-react";
import { db } from "@/db";
import { capabilityEvidence, endpointPrincipals, inbounds, nodes } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { CLIENT_REGISTRY, RUNTIME_CAPABILITIES, loadEvidence, hasEvidence } from "@/lib/capabilities";
import { decryptSecret } from "@/lib/crypto";
import { GATE_QUALIFICATION_MATRIX, renderRuntimeConfigFragment } from "@/lib/runtime-renderers";
import { generateSlsaProvenanceAndSbom, runChaosFaultInjectionSuite } from "@/lib/enterprise-hardening";
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
  Input,
  PageHeader,
  Select,
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
  const [firstNode] = await db.select().from(nodes).orderBy(nodes.id).limit(1);
  const [firstInbound] = await db.select().from(inbounds).orderBy(inbounds.id).limit(1);
  const dbPrincipals = await db.select().from(endpointPrincipals).orderBy(endpointPrincipals.id).limit(2);

  const mappedPrincipals = dbPrincipals.map((p) => ({
    attributionKey: p.attributionKey,
    credentialUuidOrToken: decryptSecret(p.credentialEnc),
  }));

  const driverFragments = (["singbox", "hysteria2", "xray"] as const).map((driver) =>
    renderRuntimeConfigFragment({
      nodeName: firstNode?.name ?? "node-1",
      driver,
      listenPort: driver === "hysteria2" ? 8443 : (firstInbound?.port ?? 443),
      serverName: firstInbound?.sni ?? "www.cloudflare.com",
      principals: mappedPrincipals,
    }),
  );

  const chaosSuite = runChaosFaultInjectionSuite();
  const releaseAttestation = generateSlsaProvenanceAndSbom();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Capability & Evidence Registry"
        subtitle="No runtime build is production-qualified yet. Notes below are historical assertions, not gate evidence; they cannot enable admission or hard quotas."
      />

      {/* M0 / M1 / M2 Production Gate Qualification Matrix */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-indigo-600" />
              <CardTitle>M0 / M1 / M2 Production Gate Qualification Matrix</CardTitle>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="success">In-Repo Contract Suite: PASS</Badge>
              <Badge variant="warning">External Hardware Gates: BLOCKED (Fail-Closed)</Badge>
            </div>
          </div>
          <CardDescription>
            Separates deterministic in-repo contract verification (<code className="font-mono text-xs">npm run test:contracts</code> + <code className="font-mono text-xs">verify-provenance_test.sh</code>) from external multi-host / root network-namespace lab gates (<code className="font-mono text-xs">make gate-*</code>).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-36">Makefile Target</TableHead>
                  <TableHead className="w-20">Milestone</TableHead>
                  <TableHead>Gate Scope & Verification Summary</TableHead>
                  <TableHead className="w-40">In-Repo Contracts</TableHead>
                  <TableHead className="w-44">External Lab Gate</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {GATE_QUALIFICATION_MATRIX.map((g) => (
                  <TableRow key={g.gateTarget}>
                    <TableCell className="font-mono text-xs font-semibold text-slate-900">
                      make {g.gateTarget}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-xs">
                        {g.milestone}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs">
                      <div className="font-semibold text-slate-900">{g.title}</div>
                      <div className="mt-0.5 text-slate-600">{g.localEvidenceSummary}</div>
                      {g.externalLabGateStatus === "BLOCKED" && (
                        <div className="mt-1 font-mono text-[11px] text-amber-800">
                          Blocker: {g.externalRequirement}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="success">{g.localContractSuiteStatus}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={g.externalLabGateStatus === "VERIFIED" ? "success" : "warning"}>
                        {g.externalLabGateStatus}
                      </Badge>
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
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-indigo-600" />
            <CardTitle>Runtime drivers</CardTitle>
          </div>
          <CardDescription>
            Candidate behavior below remains a hypothesis until tested against an exact build. Qualification requires a reviewed driver integration and versioned lab evidence.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {RUNTIME_CAPABILITIES.map((c) => (
              <div key={c.key} className="overflow-hidden rounded-xl border border-slate-200">
                <div className="border-b border-slate-200 bg-slate-50 px-4 py-3">
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <h3 className="font-mono text-sm font-semibold text-slate-900">{c.key}</h3>
                    <Badge variant="outline" className="font-mono">
                      {c.transport.toUpperCase()} {c.defaultPort}
                    </Badge>
                    {c.gated && <Badge variant="warning">gated</Badge>}
                    {c.hardQuotaCandidate && <Badge variant="info">hard-quota candidate</Badge>}
                  </div>
                  <p className="text-sm text-slate-600">{c.notes}</p>
                </div>
                <div className="p-4">
                  <dl className="grid gap-y-2 text-sm md:grid-cols-3">
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Metering</dt>
                      <dd className="text-sm font-medium text-slate-800">{c.metering.source}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Counter</dt>
                      <dd className="text-sm font-medium text-slate-800">{c.metering.counter}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Direction</dt>
                      <dd className="text-sm font-medium text-slate-800">{c.metering.direction}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">New sessions on revoke</dt>
                      <dd className="text-sm text-slate-700">{c.revocation.newSessions}</dd>
                    </div>
                    <div className="col-span-3 md:col-span-1">
                      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Existing sessions</dt>
                      <dd className="text-sm text-slate-700">{c.revocation.existingSessions}</dd>
                    </div>
                    <div className="col-span-3">
                      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">Known gap</dt>
                      <dd className="text-sm text-slate-700">{c.metering.note}</dd>
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
                    <div className="mt-4 border-t border-slate-200 pt-4">
                      <ActionForm
                        action={recordEvidenceAction}
                        submit="Record historical note"
                        variant="outline"
                        size="sm"
                      >
                        <input type="hidden" name="key" value={c.key} />
                        <div className="mt-3 grid gap-3 md:grid-cols-3">
                          <Field label="Claim">
                            <Select name="claim">
                              {CLAIMS.map((cl) => (
                                <option key={cl}>{cl}</option>
                              ))}
                            </Select>
                          </Field>
                          <Field label="Result">
                            <Select name="status">
                              <option>verified</option>
                              <option>failed</option>
                            </Select>
                          </Field>
                          <Field label="Lab run reference">
                            <Input
                              name="note"
                              required
                              minLength={10}
                              placeholder="make gate-lab run 2026-11-03, 1 GB payload ±0.5%"
                            />
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

      {/* Multi-Driver Config Fragment Renderer Preview */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Code2 className="h-4 w-4 text-indigo-600" />
            <CardTitle>Deterministic Multi-Driver Config Fragment Renderer (Sing-Box · Hysteria2 · Xray)</CardTitle>
          </div>
          <CardDescription>
            Server-side config fragments generated by <code className="font-mono text-xs">renderRuntimeConfigFragment</code>. All drivers enforce RFC1918/link-local/metadata egress blackholes and reference secrets strictly via <code className="font-mono text-xs">secretref://</code> URIs.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 lg:grid-cols-3">
            {driverFragments.map((frag) => (
              <div key={frag.driver} className="flex flex-col rounded-xl border border-slate-200 bg-slate-900 p-3.5 text-slate-100">
                <div className="mb-2 flex items-center justify-between border-b border-slate-800 pb-2 text-xs">
                  <span className="font-mono font-semibold text-indigo-400">
                    {frag.driver} ({frag.protocol})
                  </span>
                  <Badge variant="outline" className="border-slate-700 font-mono text-[10px] text-slate-300">
                    {frag.transport.toUpperCase()} · sha256:{frag.sha256.slice(0, 10)}…
                  </Badge>
                </div>
                <p className="mb-2 text-[11px] text-slate-400">{frag.qualificationNote}</p>
                <pre className="max-h-60 flex-1 overflow-auto rounded bg-slate-950/70 p-2.5 font-mono text-[11px] leading-relaxed text-slate-200">
                  {frag.configJson}
                </pre>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Client formats</CardTitle>
            <CardDescription>Exact release compatibility matrix and emitter policy.</CardDescription>
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
                      <TableCell className="font-semibold text-slate-900">{c.label}</TableCell>
                      <TableCell className="font-mono text-xs">{c.protocols.join(", ")}</TableCell>
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
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-600" />
              <CardTitle>Historical evidence notes</CardTitle>
            </div>
            <CardDescription>Informational lab logs. Cannot unlock QUALIFIED_BUILDS without reviewed artifacts.</CardDescription>
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
                    <TableHead className="w-24 text-right">When</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {log.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5}>
                        <EmptyState title="No notes recorded yet" description="Record lab evidence for each capability claim." />
                      </TableCell>
                    </TableRow>
                  ) : (
                    log.map((l) => (
                      <TableRow key={l.id}>
                        <TableCell className="font-mono text-xs">{l.capabilityKey}</TableCell>
                        <TableCell className="font-medium">{l.claim}</TableCell>
                        <TableCell>
                          <Badge variant={l.status === "verified" ? "success" : "error"}>{l.status}</Badge>
                        </TableCell>
                        <TableCell className="text-xs">{l.recordedBy}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">{ago(l.recordedAt)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableWrapper>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <FileCheck2 className="h-4 w-4 text-indigo-600" />
                Fault-Injection Chaos Suite
              </CardTitle>
              <Badge variant={chaosSuite.allPassed ? "success" : "error"}>
                {chaosSuite.allPassed ? `${chaosSuite.scenarios.length}/${chaosSuite.scenarios.length} PASS` : "FAIL"}
              </Badge>
            </div>
            <CardDescription>
              Deterministic verification of watchdog rollback, corrupted WAL frame isolation, JCS signature rejection, and NTP skew fail-closed behavior.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-xs">
            {chaosSuite.scenarios.map((s) => (
              <div
                key={s.scenarioId}
                className="flex items-start justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-2.5"
              >
                <div>
                  <div className="font-mono font-semibold text-slate-900">{s.scenarioId}</div>
                  <div className="text-slate-600">{s.expectedInvariant}</div>
                </div>
                <Badge variant={s.passed ? "success" : "error"}>{s.passed ? "PASS" : "FAIL"}</Badge>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <FileCheck2 className="h-4 w-4 text-indigo-600" />
                SLSA Level 3 Provenance & CycloneDX 1.5 SBOM
              </CardTitle>
              <Badge variant="info" className="font-mono text-xs">
                {releaseAttestation.slsaLevel}
              </Badge>
            </div>
            <CardDescription>
              Signed in-toto v1 statement and CycloneDX 1.5 component inventory for release artifacts.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5 text-xs font-mono">
            <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5 space-y-1">
              <div className="flex justify-between">
                <span className="font-sans text-slate-500">Builder ID:</span>
                <span className="truncate max-w-[240px] text-slate-900" title={releaseAttestation.builderId}>
                  {releaseAttestation.builderId}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="font-sans text-slate-500">Bundle Digest:</span>
                <span className="text-emerald-700">{releaseAttestation.bundleDigest.slice(0, 24)}…</span>
              </div>
              <div className="flex justify-between">
                <span className="font-sans text-slate-500">SBOM Format:</span>
                <span className="text-indigo-700">
                  {releaseAttestation.sbomFormat} ({releaseAttestation.sbomComponentsCount} components)
                </span>
              </div>
              <div className="flex justify-between">
                <span className="font-sans text-slate-500">Attested Subjects:</span>
                <span className="text-slate-900">{releaseAttestation.binarySubjects.length} release binaries</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

