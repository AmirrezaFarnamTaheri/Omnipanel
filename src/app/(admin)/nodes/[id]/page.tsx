import { randomUUID } from "node:crypto";
import { notFound } from "next/navigation";
import { and, desc, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { deploymentAttempts, endpointPrincipals, healthObservations, inboundHealth, inbounds, nodes, structuralRevisions } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { RUNTIME_CAPABILITIES, findCapability, isAdmissible, isHardQuotaCapable, loadEvidence } from "@/lib/capabilities";
import { previewPublish } from "@/lib/revisions";
import { ago, fmtDate } from "@/lib/format";
import {
  createInboundAction,
  nodeStatusAction,
  probeAction,
  publishAction,
  quarantineAction,
  reissueEnrollAction,
  rotateSecretsAction,
  toggleInboundAction,
  updateAddressAction,
  updateInboundAction,
} from "@/app/actions/infra";
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

export default async function NodePage({ params }: { params: Promise<{ id: string }> }) {
  const me = await requirePage("viewer");
  const id = Number((await params).id);
  if (!Number.isInteger(id)) notFound();
  const [node] = await db.select().from(nodes).where(eq(nodes.id, id));
  if (!node) notFound();
  const canEdit = me.role !== "viewer";
  const ev = await loadEvidence();
  const ibs = await db
    .select({ ib: inbounds, h: inboundHealth.state, hs: inboundHealth.since })
    .from(inbounds)
    .leftJoin(inboundHealth, eq(inboundHealth.inboundId, inbounds.id))
    .where(eq(inbounds.nodeId, id))
    .orderBy(inbounds.id);
  const counts = await db
    .select({ inboundId: endpointPrincipals.inboundId, n: sql<number>`count(*)::int` })
    .from(endpointPrincipals)
    .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
    .where(and(eq(inbounds.nodeId, id), eq(endpointPrincipals.state, "active")))
    .groupBy(endpointPrincipals.inboundId);
  const preview = await previewPublish(id);
  const revs = await db.select().from(structuralRevisions).where(eq(structuralRevisions.nodeId, id)).orderBy(desc(structuralRevisions.sequence)).limit(10);
  const attempts = await db.select().from(deploymentAttempts).where(eq(deploymentAttempts.nodeId, id)).orderBy(desc(deploymentAttempts.id)).limit(8);
  const obs = await db.select().from(healthObservations).where(eq(healthObservations.nodeId, id)).orderBy(desc(healthObservations.id)).limit(12);
  const idem = randomUUID();
  const ibName = new Map(ibs.map((x) => [x.ib.id, x.ib.name]));

  return (
    <>
      <PageHeader
        title={node.name}
        subtitle={`${node.publicAddress} · ${node.provider} ${node.asn} · ${node.region || "no region"} · agent ${node.agentVersion ?? "not enrolled"}`}
        actions={
          <div className="flex items-center gap-2">
            <Badge variant="secondary">{node.status.replace("_", " ")}</Badge>
            <Badge variant="secondary">{node.appliedState}</Badge>
          </div>
        }
      />

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Pending change preview (redacted)</CardTitle>
          </CardHeader>
          <CardContent>
            {preview.unchanged ? (
              <p className="text-sm text-emerald-700">Intent matches published revision #{node.structuralSeq}. Nothing to publish.</p>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  Predicted disruption:
                  <Badge variant={preview.disruption === "network" || preview.disruption === "listener_restart" ? "warning" : "info"}>{preview.disruption}</Badge>
                </div>
                <ul className="space-y-1 text-sm">
                  {preview.changes.length === 0 && <li className="text-slate-600">Content identical to an earlier revision (rollback target) or first publish.</li>}
                  {preview.changes.map((c, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <Badge variant={c.kind === "added" ? "success" : c.kind === "removed" ? "destructive" : "warning"}>{c.kind}</Badge>
                      <span className="font-medium">{c.name}</span>
                      <span className="text-slate-500">{c.fields.join(", ")}</span>
                    </li>
                  ))}
                </ul>
                <p className="break-all text-xs text-slate-500">Digest sha256:{preview.digest.slice(0, 32)}… Secrets appear only as references and hashes.</p>
                {canEdit && (
                  <ActionForm action={publishAction} submit="Publish immutable revision">
                    <input type="hidden" name="nodeId" value={id} />
                  </ActionForm>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Applied state reported by agent</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-y-1 text-sm">
              <dt className="text-slate-500">Structural</dt><dd>desired #{node.structuralSeq} · applied #{node.appliedStructuralSeq}</dd>
              <dt className="text-slate-500">Membership</dt><dd>desired #{node.membershipSeq} · applied #{node.appliedMembershipSeq}</dd>
              <dt className="text-slate-500">Epoch</dt><dd>{node.appliedEpoch ?? "—"}</dd>
              <dt className="text-slate-500">Last seen</dt><dd>{ago(node.lastSeenAt)}</dd>
            </dl>
            <div className="mt-3 flex flex-wrap gap-2">
              {node.components.length === 0 && <span className="text-sm text-slate-500">No component reports yet.</span>}
              {node.components.map((c) => (
                <Badge key={c.name} variant="secondary">{c.name}: {c.state}</Badge>
              ))}
            </div>
            {canEdit && (
              <ActionForm action={probeAction} submit="Probe TCP listeners now" variant="outline" size="sm" className="mt-4">
                <input type="hidden" name="nodeId" value={id} />
              </ActionForm>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Endpoints & port ownership</CardTitle>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead className="w-24">Runtime / protocol</TableHead>
                  <TableHead className="w-20">Listener</TableHead>
                  <TableHead className="w-24">SNI</TableHead>
                  <TableHead className="w-24">Credentials</TableHead>
                  <TableHead className="w-20">Health</TableHead>
                  <TableHead className="w-24">Enforceability</TableHead>
                  <TableHead className="w-32">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ibs.map(({ ib, h }) => {
                  const cap = findCapability(ib.runtime, ib.protocol);
                  return (
                    <TableRow key={ib.id}>
                      <TableCell className="font-medium">{ib.name}</TableCell>
                      <TableCell className="text-xs">{ib.runtime} / {ib.protocol}</TableCell>
                      <TableCell>{ib.transport.toUpperCase()} {ib.port}</TableCell>
                      <TableCell className="text-xs">{ib.sni}</TableCell>
                      <TableCell>{counts.find((c) => c.inboundId === ib.id)?.n ?? 0}</TableCell>
                      <TableCell>
                        <Badge variant={statusTone(h ?? "healthy")}>{(h ?? "unverified").replace("_", " ")}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={cap && isHardQuotaCapable(cap, ev) ? "info" : "secondary"}>{cap && isHardQuotaCapable(cap, ev) ? "hard-capable" : "metered"}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-2">
                          <ActionForm action={updateInboundAction} submit="Save" variant="outline" size="sm">
                            <input type="hidden" name="inboundId" value={ib.id} />
                            <div className="flex gap-2">
                              <input name="port" type="number" defaultValue={ib.port} className="w-20" />
                              <input name="sni" defaultValue={ib.sni} className="w-40" />
                            </div>
                          </ActionForm>
                          <ActionForm action={toggleInboundAction} submit={ib.enabled ? "Disable" : "Enable"} variant="outline" size="sm">
                            <input type="hidden" name="inboundId" value={ib.id} />
                            <input type="hidden" name="enabled" value={ib.enabled ? "0" : "1"} />
                          </ActionForm>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableWrapper>
          {canEdit && (
            <ActionForm action={createInboundAction} submit="Add endpoint" variant="outline" size="sm" className="mt-5 border-t border-slate-100 pt-4">
              <input type="hidden" name="nodeId" value={id} />
              <input type="hidden" name="idemKey" value={idem} />
              <div className="grid gap-4 md:grid-cols-4">
                <Field label="Name">
                  <input name="name" required placeholder="reality-443" className="w-full" />
                </Field>
                <Field label="Runtime / protocol">
                  <select name="capability" className="w-full">
                    {RUNTIME_CAPABILITIES.map((c) => (
                      <option key={c.key} value={`${c.runtime}|${c.protocol}`} disabled={!isAdmissible(c, ev)}>
                        {c.runtime} · {c.protocol} ({c.transport.toUpperCase()}){isAdmissible(c, ev) ? "" : " — gated"}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Port">
                  <input name="port" type="number" required defaultValue={443} className="w-full" />
                </Field>
                <Field label="SNI / handshake host">
                  <input name="sni" required placeholder="www.example.com" className="w-full" />
                </Field>
              </div>
            </ActionForm>
          )}
        </CardContent>
      </Card>

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Revision history (immutable)</CardTitle>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>#</TableHead>
                    <TableHead className="w-20">Epoch</TableHead>
                    <TableHead>Digest</TableHead>
                    <TableHead className="w-20">Disruption</TableHead>
                    <TableHead>By</TableHead>
                    <TableHead className="w-32">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {revs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6}>
                        <EmptyState title="No revisions published" description="History is never rewritten once committed." />
                      </TableCell>
                    </TableRow>
                  ) : (
                    revs.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell className="font-medium">#{r.sequence}</TableCell>
                        <TableCell>{r.epoch}</TableCell>
                        <TableCell className="font-mono text-xs">{r.digest.slice(0, 10)}</TableCell>
                        <TableCell><Badge variant="secondary">{r.disruption}</Badge></TableCell>
                        <TableCell className="text-xs">{r.createdBy.replace("admin:", "")}<div className="text-slate-500">{ago(r.createdAt)}</div></TableCell>
                        <TableCell>
                          {canEdit && r.sequence !== node.structuralSeq && (
                            <ActionForm action={publishAction} submit="Roll back" variant="outline" size="sm">
                              <input type="hidden" name="nodeId" value={id} />
                              <input type="hidden" name="rollbackOf" value={r.sequence} />
                            </ActionForm>
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableWrapper>
            <p className="mt-3 text-xs text-slate-500">A rollback publishes a new, higher revision with the earlier content. History is never rewritten.</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Deployment attempts reported by the agent</CardTitle>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Revision</TableHead>
                    <TableHead className="w-24">State</TableHead>
                    <TableHead className="w-24">When</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {attempts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={3}>
                        <EmptyState title="No deployment attempts yet" description="The agent has not reported yet." />
                      </TableCell>
                    </TableRow>
                  ) : (
                    attempts.map((a) => (
                      <TableRow key={a.id}>
                        <TableCell>#{a.structuralSeq}</TableCell>
                        <TableCell><Badge variant={statusTone(a.state)}>{a.state}</Badge></TableCell>
                        <TableCell className="text-xs">{fmtDate(a.reportedAt)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableWrapper>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent health observations</CardTitle>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead className="w-24">Vantage</TableHead>
                  <TableHead className="w-20">Level</TableHead>
                  <TableHead className="w-24">Result</TableHead>
                  <TableHead className="w-20">Latency</TableHead>
                  <TableHead className="w-24">When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {obs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6}>
                      <EmptyState title="No health observations yet" description="L0 socket · L1 TLS/QUIC handshake · L2 authenticated session · L3 canary request." />
                    </TableCell>
                  </TableRow>
                ) : (
                  obs.map((o) => (
                    <TableRow key={o.id}>
                      <TableCell>{ibName.get(o.inboundId) ?? o.inboundId}</TableCell>
                      <TableCell className="text-xs">{o.vantage}</TableCell>
                      <TableCell>{o.level}</TableCell>
                      <TableCell>
                        <Badge variant={o.ok ? "success" : "error"}>{o.ok ? "ok" : o.detail || "fail"}</Badge>
                      </TableCell>
                      <TableCell>{o.latencyMs != null ? `${o.latencyMs} ms` : "—"}</TableCell>
                      <TableCell className="text-xs">{ago(o.observedAt)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableWrapper>
          <p className="mt-3 text-xs text-slate-500">Only the control-plane L0 probe runs here; others are reported by agents and external vantages.</p>
        </CardContent>
      </Card>

      {canEdit && (
        <Card>
          <CardHeader>
            <CardTitle>Lifecycle & incident response</CardTitle>
          </CardHeader>
          <CardContent>
          <div className="grid gap-6 md:grid-cols-2">
            <div className="space-y-4">
              <ActionForm action={nodeStatusAction} submit={node.status === "draining" ? "Return to service" : "Drain node"} variant="outline" size="sm">
                <input type="hidden" name="nodeId" value={id} />
                <input type="hidden" name="status" value={node.status === "draining" ? "active" : "draining"} />
                <p className="mt-2 text-sm text-slate-600">Draining removes this node from new subscription outputs without touching existing sessions.</p>
              </ActionForm>
              <ActionForm action={updateAddressAction} submit="Replace address" variant="outline" size="sm">
                <input type="hidden" name="nodeId" value={id} />
                <Field label="New public address" hint="Manual IP rotation. Subscriptions pick it up on next refresh.">
                  <input name="address" defaultValue={node.publicAddress} className="w-full" />
                </Field>
              </ActionForm>
              <ActionForm action={reissueEnrollAction} submit="Re-issue enrollment token" variant="outline" size="sm">
                <input type="hidden" name="nodeId" value={id} />
                <p className="mt-2 text-sm text-slate-600">Revokes the current agent identity; the node must enroll again.</p>
              </ActionForm>
            </div>
            {me.role === "owner" && (
              <div className="space-y-4 rounded-lg border border-rose-200 bg-rose-50/40 p-4">
                <ActionForm action={quarantineAction} submit="Quarantine node" variant="destructive" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <Field label="Type QUARANTINE to confirm" hint="Revokes agent access and removes the node from subscriptions.">
                    <input name="confirm" className="w-full" />
                  </Field>
                </ActionForm>
                <ActionForm action={rotateSecretsAction} submit="Rotate all credentials on this node" variant="destructive" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <p className="mt-2 text-sm text-slate-600">Compromise response: new per-user credentials and Reality keys for every endpoint here.</p>
                </ActionForm>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
      )}
    </>
  );
}

function statusTone(state: string): "success" | "error" | "warning" | "secondary" {
  const s = (state ?? "").toLowerCase();
  if (s.includes("healthy") || s.includes("active") || s.includes("ok")) return "success";
  if (s.includes("error") || s.includes("fail") || s.includes("quarantine")) return "error";
  if (s.includes("pending") || s.includes("draining") || s.includes("unverified")) return "warning";
  return "secondary";
}
