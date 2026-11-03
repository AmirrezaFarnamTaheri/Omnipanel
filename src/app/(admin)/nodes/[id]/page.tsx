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
import { Badge, Card, Field, inputCls, PageHeader, statusTone, Table, Td } from "@/components/ui";

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
            <Badge tone={statusTone(node.status)}>{node.status.replace("_", " ")}</Badge>
            <Badge tone={statusTone(node.appliedState)}>{node.appliedState}</Badge>
          </div>
        }
      />

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card title="Pending change preview (redacted)">
          {preview.unchanged ? (
            <p className="text-sm text-emerald-700">Intent matches published revision #{node.structuralSeq}. Nothing to publish.</p>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm">
                Predicted disruption: <Badge tone={preview.disruption === "network" || preview.disruption === "listener_restart" ? "amber" : "blue"}>{preview.disruption}</Badge>
              </div>
              <ul className="space-y-1 text-sm">
                {preview.changes.length === 0 && <li className="text-slate-600">Content identical to an earlier revision (rollback target) or first publish.</li>}
                {preview.changes.map((c, i) => (
                  <li key={i} className="flex items-center gap-2">
                    <Badge tone={c.kind === "added" ? "green" : c.kind === "removed" ? "red" : "amber"}>{c.kind}</Badge>
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
        </Card>

        <Card title="Applied state reported by agent">
          <dl className="grid grid-cols-2 gap-y-1 text-sm">
            <dt className="text-slate-500">Structural</dt><dd>desired #{node.structuralSeq} · applied #{node.appliedStructuralSeq}</dd>
            <dt className="text-slate-500">Membership</dt><dd>desired #{node.membershipSeq} · applied #{node.appliedMembershipSeq}</dd>
            <dt className="text-slate-500">Epoch</dt><dd>{node.appliedEpoch ?? "—"}</dd>
            <dt className="text-slate-500">Last seen</dt><dd>{ago(node.lastSeenAt)}</dd>
          </dl>
          <div className="mt-3 flex flex-wrap gap-2">
            {node.components.length === 0 && <span className="text-sm text-slate-500">No component reports yet.</span>}
            {node.components.map((c) => (
              <Badge key={c.name} tone={statusTone(c.state)}>{c.name}: {c.state}</Badge>
            ))}
          </div>
          {canEdit && (
            <ActionForm action={probeAction} submit="Probe TCP listeners now" variant="ghost" className="mt-4">
              <input type="hidden" name="nodeId" value={id} />
            </ActionForm>
          )}
        </Card>
      </div>

      <Card title="Endpoints & port ownership" className="mb-6">
        <Table head={["Endpoint", "Runtime / protocol", "Listener", "SNI", "Credentials", "Health", "Enforceability", ""]} empty={ibs.length ? undefined : "No endpoints yet."}>
          {ibs.map(({ ib, h }) => {
            const cap = findCapability(ib.runtime, ib.protocol);
            return (
              <tr key={ib.id}>
                <Td>
                  <span className="font-medium">{ib.name}</span>
                  {!ib.enabled && <Badge tone="slate">disabled</Badge>}
                </Td>
                <Td className="text-xs">{ib.runtime} / {ib.protocol}</Td>
                <Td>{ib.transport.toUpperCase()} {ib.port}</Td>
                <Td className="text-xs">{ib.sni}</Td>
                <Td>{counts.find((c) => c.inboundId === ib.id)?.n ?? 0}</Td>
                <Td><Badge tone={statusTone(h ?? "healthy")}>{(h ?? "unverified").replace("_", " ")}</Badge></Td>
                <Td><Badge tone={cap && isHardQuotaCapable(cap, ev) ? "blue" : "slate"}>{cap && isHardQuotaCapable(cap, ev) ? "hard-capable" : "metered"}</Badge></Td>
                <Td>
                  {canEdit && (
                    <div className="flex flex-col gap-2">
                      <ActionForm action={updateInboundAction} submit="Save" variant="ghost">
                        <input type="hidden" name="inboundId" value={ib.id} />
                        <div className="flex gap-2">
                          <input name="port" type="number" defaultValue={ib.port} className={`${inputCls} w-20`} aria-label="port" />
                          <input name="sni" defaultValue={ib.sni} className={`${inputCls} w-40`} aria-label="sni" />
                        </div>
                      </ActionForm>
                      <ActionForm action={toggleInboundAction} submit={ib.enabled ? "Disable" : "Enable"} variant="ghost">
                        <input type="hidden" name="inboundId" value={ib.id} />
                        <input type="hidden" name="enabled" value={ib.enabled ? "0" : "1"} />
                      </ActionForm>
                    </div>
                  )}
                </Td>
              </tr>
            );
          })}
        </Table>
        {canEdit && (
          <ActionForm action={createInboundAction} submit="Add endpoint" className="mt-5 border-t border-slate-100 pt-4">
            <input type="hidden" name="nodeId" value={id} />
            <input type="hidden" name="idemKey" value={idem} />
            <div className="grid gap-4 md:grid-cols-4">
              <Field label="Name"><input name="name" required placeholder="reality-443" className={inputCls} /></Field>
              <Field label="Runtime / protocol">
                <select name="capability" className={inputCls}>
                  {RUNTIME_CAPABILITIES.map((c) => (
                    <option key={c.key} value={`${c.runtime}|${c.protocol}`} disabled={!isAdmissible(c, ev)}>
                      {c.runtime} · {c.protocol} ({c.transport.toUpperCase()}){isAdmissible(c, ev) ? "" : " — gated"}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Port"><input name="port" type="number" required defaultValue={443} className={inputCls} /></Field>
              <Field label="SNI / handshake host"><input name="sni" required placeholder="www.example.com" className={inputCls} /></Field>
            </div>
          </ActionForm>
        )}
      </Card>

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card title="Revision history (immutable)">
          <Table head={["#", "Epoch", "Digest", "Disruption", "By", ""]} empty={revs.length ? undefined : "No revisions published."}>
            {revs.map((r) => (
              <tr key={r.id}>
                <Td>#{r.sequence}{r.rollbackOf ? <span className="text-xs text-slate-500"> (rollback of #{r.rollbackOf})</span> : null}</Td>
                <Td>{r.epoch}</Td>
                <Td className="font-mono text-xs">{r.digest.slice(0, 10)}</Td>
                <Td><Badge tone="slate">{r.disruption}</Badge></Td>
                <Td className="text-xs">{r.createdBy.replace("admin:", "")}<div className="text-slate-500">{ago(r.createdAt)}</div></Td>
                <Td>
                  {canEdit && r.sequence !== node.structuralSeq && (
                    <ActionForm action={publishAction} submit="Roll back" variant="ghost">
                      <input type="hidden" name="nodeId" value={id} />
                      <input type="hidden" name="rollbackOf" value={r.sequence} />
                    </ActionForm>
                  )}
                </Td>
              </tr>
            ))}
          </Table>
          <p className="mt-3 text-xs text-slate-500">A rollback publishes a new, higher revision with the earlier content. History is never rewritten.</p>
        </Card>

        <Card title="Deployment attempts reported by the agent">
          <Table head={["Revision", "State", "When"]} empty={attempts.length ? undefined : "The agent has not reported yet."}>
            {attempts.map((a) => (
              <tr key={a.id}>
                <Td>#{a.structuralSeq}</Td>
                <Td><Badge tone={statusTone(a.state)}>{a.state}</Badge></Td>
                <Td className="text-xs">{fmtDate(a.reportedAt)}</Td>
              </tr>
            ))}
          </Table>
        </Card>
      </div>

      <Card title="Recent health observations" className="mb-6">
        <Table head={["Endpoint", "Vantage", "Level", "Result", "Latency", "When"]} empty={obs.length ? undefined : "No observations."}>
          {obs.map((o) => (
            <tr key={o.id}>
              <Td>{ibName.get(o.inboundId) ?? o.inboundId}</Td>
              <Td className="text-xs">{o.vantage}</Td>
              <Td>{o.level}</Td>
              <Td><Badge tone={o.ok ? "green" : "red"}>{o.ok ? "ok" : o.detail || "fail"}</Badge></Td>
              <Td>{o.latencyMs != null ? `${o.latencyMs} ms` : "—"}</Td>
              <Td className="text-xs">{ago(o.observedAt)}</Td>
            </tr>
          ))}
        </Table>
        <p className="mt-3 text-xs text-slate-500">L0 socket · L1 TLS/QUIC handshake · L2 authenticated session · L3 canary request. Only the control-plane L0 probe runs here; others are reported by agents and external vantages.</p>
      </Card>

      {canEdit && (
        <Card title="Lifecycle & incident response">
          <div className="grid gap-6 md:grid-cols-2">
            <div className="space-y-4">
              <ActionForm action={nodeStatusAction} submit={node.status === "draining" ? "Return to service" : "Drain node"} variant="ghost">
                <input type="hidden" name="nodeId" value={id} />
                <input type="hidden" name="status" value={node.status === "draining" ? "active" : "draining"} />
                <p className="text-sm text-slate-600">Draining removes this node from new subscription outputs without touching existing sessions.</p>
              </ActionForm>
              <ActionForm action={updateAddressAction} submit="Replace address" variant="ghost">
                <input type="hidden" name="nodeId" value={id} />
                <Field label="New public address" hint="Manual IP rotation. Subscriptions pick it up on next refresh."><input name="address" defaultValue={node.publicAddress} className={inputCls} /></Field>
              </ActionForm>
              <ActionForm action={reissueEnrollAction} submit="Re-issue enrollment token" variant="ghost">
                <input type="hidden" name="nodeId" value={id} />
                <p className="text-sm text-slate-600">Revokes the current agent identity; the node must enroll again.</p>
              </ActionForm>
            </div>
            {me.role === "owner" && (
              <div className="space-y-4 rounded-lg border border-rose-200 bg-rose-50/40 p-4">
                <ActionForm action={quarantineAction} submit="Quarantine node" variant="danger">
                  <input type="hidden" name="nodeId" value={id} />
                  <Field label="Type QUARANTINE to confirm" hint="Revokes agent access and removes the node from subscriptions."><input name="confirm" className={inputCls} /></Field>
                </ActionForm>
                <ActionForm action={rotateSecretsAction} submit="Rotate all credentials on this node" variant="danger">
                  <input type="hidden" name="nodeId" value={id} />
                  <p className="text-sm text-slate-600">Compromise response: new per-user credentials and Reality keys for every endpoint here.</p>
                </ActionForm>
              </div>
            )}
          </div>
        </Card>
      )}
    </>
  );
}
