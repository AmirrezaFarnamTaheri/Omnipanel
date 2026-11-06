import { randomUUID } from "node:crypto";
import Link from "next/link";
import { notFound } from "next/navigation";
import { and, desc, eq, sql } from "drizzle-orm";
import {
  Activity,
  ChevronRight,
  Cpu,
  Database,
  FileSignature,
  Gauge,
  HardDrive,
  Network,
  Server,
  ShieldAlert,
  ShieldCheck,
  TimerReset,
} from "lucide-react";
import { db } from "@/db";
import {
  deploymentAttempts,
  endpointPrincipals,
  healthObservations,
  inboundHealth,
  inbounds,
  nodes,
  structuralRevisions,
} from "@/db/schema";
import { requirePage } from "@/lib/auth";
import {
  RUNTIME_CAPABILITIES,
  findCapability,
  isAdmissible,
  isHardQuotaCapable,
  loadEvidence,
} from "@/lib/capabilities";
import { previewPublish } from "@/lib/revisions";
import { ago, fmtBytes, fmtDate } from "@/lib/format";
import {
  getNodeFirewallInventory,
  getNodeReconcileWatchdogState,
  getNodeResourceTelemetry,
  getNodeSessionAndMeteringState,
  getNodeSyncFeedPage,
  listDesiredStateProposals,
} from "@/lib/governance-store";
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
import {
  advanceSyncFeedAction,
  createProposalAction,
  mutateNodeSessionMeteringAction,
  mutateReconcileWatchdogAction,
  recordResourceSnapshotAction,
} from "@/app/actions/system";
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
  statusTone,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
} from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function NodePage({ params }: { params: Promise<{ id: string }> }) {
  const me = await requirePage("viewer");
  const id = Number((await params).id);
  if (!Number.isInteger(id)) notFound();
  const [node] = await db.select().from(nodes).where(eq(nodes.id, id));
  if (!node) notFound();
  const canEdit = me.role !== "viewer";
  const isOwner = me.role === "owner";
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
  const revs = await db
    .select()
    .from(structuralRevisions)
    .where(eq(structuralRevisions.nodeId, id))
    .orderBy(desc(structuralRevisions.sequence))
    .limit(10);
  const attempts = await db
    .select()
    .from(deploymentAttempts)
    .where(eq(deploymentAttempts.nodeId, id))
    .orderBy(desc(deploymentAttempts.id))
    .limit(8);
  const obs = await db
    .select()
    .from(healthObservations)
    .where(eq(healthObservations.nodeId, id))
    .orderBy(desc(healthObservations.id))
    .limit(10);

  const resourceTelemetry = await getNodeResourceTelemetry(id, new Date());
  const syncFeed = await getNodeSyncFeedPage(id);
  const firewallInventory = await getNodeFirewallInventory(id);
  const reconcileWatchdog = await getNodeReconcileWatchdogState(id);
  const sessionMetering = await getNodeSessionAndMeteringState(id);
  const nodeProposals = (await listDesiredStateProposals()).filter((p) => p.nodeId === id);

  const idem = randomUUID();
  const ibName = new Map(ibs.map((x) => [x.ib.id, x.ib.name]));
  const snap = resourceTelemetry.snapshot;
  const memPct = snap ? Math.min(100, Math.round((snap.memoryUsedBytes / snap.memoryTotalBytes) * 100)) : 0;
  const primaryPrincipalId = sessionMetering.checkpoint.trackedUsers[0]?.principalId ?? "primary";

  return (
    <div className="space-y-6">
      <PageHeader
        breadcrumbs={
          <>
            <Link href="/nodes" className="hover:text-slate-900">
              Nodes
            </Link>
            <span>/</span>
            <span className="text-slate-900">{node.name}</span>
          </>
        }
        title={node.name}
        subtitle={`${node.publicAddress} · ${node.provider} ${node.asn} · ${node.region || "no region"} · ${node.agentVersion ?? "not enrolled"}`}
        actions={
          <div className="flex items-center gap-2">
            <Badge variant={statusTone(node.status)}>{node.status.replace("_", " ")}</Badge>
            <Badge variant={statusTone(node.appliedState)}>{node.appliedState}</Badge>
          </div>
        }
      />

      {/* Row 1: Desired-State Governance & Applied Agent State */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <FileSignature className="h-4 w-4 text-indigo-600" />
              Desired-State Revision & Dual-Operator Governance
            </CardTitle>
            <CardDescription>
              Secrets appear strictly as <code className="font-mono text-xs">secretRefs</code> and SHA-256 digests in manifests.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {preview.unchanged ? (
              <div className="rounded-lg border border-emerald-200 bg-emerald-50/70 p-3 text-xs text-emerald-900">
                Published revision <strong>#{node.structuralSeq}</strong> matches current listener intent (
                <code className="font-mono">sha256:{preview.digest.slice(0, 18)}…</code>).
              </div>
            ) : (
              <div className="space-y-2 rounded-lg border border-amber-200 bg-amber-50/60 p-3 text-xs">
                <div className="flex items-center gap-2 font-medium text-amber-900">
                  <span>Predicted disruption:</span>
                  <Badge variant="warning">{preview.disruption}</Badge>
                </div>
                <ul className="space-y-1">
                  {preview.changes.map((c, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <Badge variant={c.kind === "added" ? "success" : c.kind === "removed" ? "error" : "warning"}>
                        {c.kind}
                      </Badge>
                      <span className="font-mono font-medium">{c.name}</span>
                      <span className="text-slate-600">{c.fields.join(", ")}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {nodeProposals.length > 0 && (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-800">Staged Proposals</span>
                  <Link href="/approvals" className="font-medium text-indigo-600 hover:underline">
                    Approvals Console →
                  </Link>
                </div>
                {nodeProposals.slice(0, 2).map((p) => {
                  const st = p.decision?.consumedAt ? "published" : p.decision ? "approved" : "proposed";
                  return (
                    <div key={p.proposalId} className="flex items-center justify-between gap-2 text-[11px]">
                      <span className="font-mono text-slate-700">
                        {p.proposalId} (seq #{p.structuralSequence})
                      </span>
                      <Badge variant={statusTone(st)}>{st}</Badge>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 pt-1">
              {isOwner && (
                <ActionForm
                  action={createProposalAction}
                  submitLabel={`Stage Signed Proposal (seq #${node.structuralSeq + 1})`}
                  size="sm"
                >
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="ttlSeconds" value="300" />
                  <input
                    type="hidden"
                    name="note"
                    value={`Signed desired-state publication for ${node.name} seq #${node.structuralSeq + 1}`}
                  />
                </ActionForm>
              )}
              {canEdit && !preview.unchanged && (
                <ActionForm action={publishAction} submitLabel="Direct Operator Publish" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                </ActionForm>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Server className="h-4 w-4 text-indigo-600" />
              Applied State Reported by Node Agent
            </CardTitle>
            <CardDescription>
              Reconciled via mTLS desired-state polling and verified against the local SQLite WAL journal.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-slate-500">Structural Cursor</dt>
              <dd className="font-mono text-xs font-medium tabular-nums">
                desired #{node.structuralSeq} · applied #{node.appliedStructuralSeq}
              </dd>
              <dt className="text-slate-500">Membership Cursor</dt>
              <dd className="font-mono text-xs font-medium tabular-nums">
                desired #{node.membershipSeq} · applied #{node.appliedMembershipSeq}
              </dd>
              <dt className="text-slate-500">Applied Epoch</dt>
              <dd className="font-mono text-xs font-medium tabular-nums">#{node.appliedEpoch ?? "—"}</dd>
              <dt className="text-slate-500">Last Heartbeat</dt>
              <dd className="text-xs tabular-nums">{ago(node.lastSeenAt)}</dd>
            </dl>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {node.components.map((c) => (
                <Badge key={c.name} variant={statusTone(c.state)} className="font-mono text-[11px]">
                  {c.name}: {c.state}
                </Badge>
              ))}
            </div>
            {canEdit && (
              <ActionForm
                action={probeAction}
                submitLabel="Probe TCP Listeners (L0) Now"
                variant="outline"
                size="sm"
                className="mt-3"
              >
                <input type="hidden" name="nodeId" value={id} />
              </ActionForm>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 2: Primary Endpoints & Port Ownership */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Endpoints & Port Ownership</CardTitle>
          <CardDescription>
            Protocol-transport compatibility is validated before persistence; port conflicts on the same node and transport are rejected.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Runtime / Protocol</TableHead>
                  <TableHead>Listener</TableHead>
                  <TableHead>SNI</TableHead>
                  <TableHead>Principals</TableHead>
                  <TableHead>L0–L3 Health</TableHead>
                  <TableHead>Enforceability</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ibs.map(({ ib, h }) => {
                  const cap = findCapability(ib.runtime, ib.protocol);
                  return (
                    <TableRow key={ib.id}>
                      <TableCell className="font-mono text-xs font-semibold text-slate-900">{ib.name}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {ib.runtime} / {ib.protocol}
                      </TableCell>
                      <TableCell className="font-mono text-xs tabular-nums">
                        {ib.transport.toUpperCase()} :{ib.port}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{ib.sni}</TableCell>
                      <TableCell className="tabular-nums font-mono text-xs">
                        {counts.find((c) => c.inboundId === ib.id)?.n ?? 0}
                      </TableCell>
                      <TableCell>
                        <Badge variant={statusTone(h ?? "healthy")}>{(h ?? "unverified").replace("_", " ")}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={cap && isHardQuotaCapable(cap, ev) ? "info" : "secondary"}>
                          {cap && isHardQuotaCapable(cap, ev) ? "hard-capable" : "metered"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-2">
                          <ActionForm action={updateInboundAction} submitLabel="Save" variant="outline" size="sm">
                            <input type="hidden" name="inboundId" value={ib.id} />
                            <div className="flex items-center gap-1.5">
                              <Input name="port" type="number" defaultValue={ib.port} className="h-8 w-20 text-xs font-mono" />
                              <Input name="sni" defaultValue={ib.sni} className="h-8 w-36 text-xs font-mono" />
                            </div>
                          </ActionForm>
                          <ActionForm
                            action={toggleInboundAction}
                            submitLabel={ib.enabled ? "Disable" : "Enable"}
                            variant="outline"
                            size="sm"
                          >
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
            <ActionForm
              action={createInboundAction}
              submitLabel="Add Endpoint"
              variant="outline"
              size="sm"
              className="mt-4 border-t border-slate-100 pt-4"
            >
              <input type="hidden" name="nodeId" value={id} />
              <input type="hidden" name="idemKey" value={idem} />
              <div className="grid gap-3 md:grid-cols-4">
                <Field label="Endpoint Name">
                  <Input name="name" required placeholder="reality-tcp-8443" />
                </Field>
                <Field label="Runtime / Protocol">
                  <Select name="capability">
                    {RUNTIME_CAPABILITIES.map((c) => (
                      <option key={c.key} value={`${c.runtime}|${c.protocol}`} disabled={!isAdmissible(c, ev)}>
                        {c.runtime} · {c.protocol} ({c.transport.toUpperCase()}){isAdmissible(c, ev) ? "" : " — gated (M0)"}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="Listener Port">
                  <Input name="port" type="number" required defaultValue={8443} className="font-mono tabular-nums" />
                </Field>
                <Field label="SNI / Handshake Host">
                  <Input name="sni" required placeholder="www.cloudflare.com" className="font-mono" />
                </Field>
              </div>
            </ActionForm>
          )}
        </CardContent>
      </Card>

      {/* Row 3: Host Resource Telemetry & L0-L3 Listener Health */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Cpu className="h-4 w-4 text-indigo-600" />
                Host Resource Snapshot
              </CardTitle>
              <Badge variant={statusTone(resourceTelemetry.freshness)}>
                {resourceTelemetry.freshness.toUpperCase()}
              </Badge>
            </div>
            <CardDescription>
              Read-only host metrics validated by <code className="font-mono text-xs">observability</code> contract, separated from L0–L3 proxy listener health.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {snap ? (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-3">
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>CPU Load</span>
                      <span className="font-mono font-semibold text-slate-900 tabular-nums">
                        {snap.cpuPercent.toFixed(1)}%
                      </span>
                    </div>
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200">
                      <div
                        className="h-full bg-indigo-600"
                        style={{ width: `${Math.min(100, snap.cpuPercent)}%` }}
                      />
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-3">
                    <div className="flex items-center justify-between text-xs text-slate-500">
                      <span>Memory ({memPct}%)</span>
                      <span className="font-mono font-semibold text-slate-900 tabular-nums">
                        {fmtBytes(snap.memoryUsedBytes)} / {fmtBytes(snap.memoryTotalBytes)}
                      </span>
                    </div>
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200">
                      <div className="h-full bg-emerald-600" style={{ width: `${memPct}%` }} />
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs">
                  <div className="rounded-lg border border-slate-200 p-2.5 space-y-1">
                    <div className="flex items-center gap-1.5 font-semibold text-slate-700">
                      <HardDrive className="h-3.5 w-3.5 text-slate-500" />
                      <span>Filesystems</span>
                    </div>
                    {snap.filesystems.map((fs) => {
                      const pct = Math.min(100, Math.round((fs.usedBytes / fs.totalBytes) * 100));
                      return (
                        <div key={fs.id} className="flex items-center justify-between gap-2 font-mono text-[11px] tabular-nums">
                          <span className="truncate text-slate-600">{fs.id}</span>
                          <span className="shrink-0 text-slate-900">
                            {fmtBytes(fs.usedBytes)} / {fmtBytes(fs.totalBytes)} ({pct}%)
                          </span>
                        </div>
                      );
                    })}
                  </div>
                  <div className="rounded-lg border border-slate-200 p-2.5 space-y-1">
                    <div className="flex items-center gap-1.5 font-semibold text-slate-700">
                      <Network className="h-3.5 w-3.5 text-slate-500" />
                      <span>Interfaces</span>
                    </div>
                    {snap.network.map((net) => (
                      <div key={net.interface} className="flex items-center justify-between gap-2 font-mono text-[11px] tabular-nums">
                        <span className="text-slate-600">{net.interface}</span>
                        <span className="text-slate-900">
                          RX {fmtBytes(net.receivedBytes)} · TX {fmtBytes(net.sentBytes)}
                        </span>
                      </div>
                    ))}
                    <div className="text-[11px] text-slate-400 tabular-nums">
                      Gen #{snap.generation} · Sampled {ago(snap.sampledAt)}
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <EmptyState title="No host resource snapshot" description="Sample host OS telemetry below." />
            )}

            {canEdit && (
              <ActionForm
                action={recordResourceSnapshotAction}
                submitLabel="Sample Live Host OS Telemetry"
                variant="outline"
                size="sm"
              >
                <input type="hidden" name="nodeId" value={id} />
              </ActionForm>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4 text-indigo-600" />
              Multi-Layer Proxy Listener Health (L0–L3)
            </CardTitle>
            <CardDescription>
              L0 socket · L1 TLS/Reality/QUIC handshake · L2 authenticated proxy session · L3 canary echo.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Endpoint</TableHead>
                    <TableHead>Vantage</TableHead>
                    <TableHead>Layer</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead>Latency</TableHead>
                    <TableHead>Observed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {obs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6}>
                        <EmptyState title="No health observations yet" description="Run an L0 listener probe above." />
                      </TableCell>
                    </TableRow>
                  ) : (
                    obs.map((o) => (
                      <TableRow key={o.id}>
                        <TableCell className="font-mono text-xs font-medium">
                          {ibName.get(o.inboundId) ?? o.inboundId}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{o.vantage}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="font-mono text-xs">
                            {o.level}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={o.ok ? "success" : "error"}>{o.ok ? "ok" : o.detail || "fail"}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs tabular-nums">
                          {o.latencyMs != null ? `${o.latencyMs} ms` : "—"}
                        </TableCell>
                        <TableCell className="text-xs text-slate-500 tabular-nums">{ago(o.observedAt)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableWrapper>
          </CardContent>
        </Card>
      </div>

      {/* Row 4: Reconciler Watchdog & Live Session / WAL Metering */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <TimerReset className="h-4 w-4 text-indigo-600" />
                Journaled Reconciler & Commit-Confirm Watchdog
              </CardTitle>
              <div className="flex items-center gap-1.5">
                <Badge
                  variant={
                    reconcileWatchdog.stage === "VERIFIED"
                      ? "success"
                      : reconcileWatchdog.stage === "ROLLED_BACK"
                        ? "warning"
                        : "info"
                  }
                >
                  {reconcileWatchdog.stage}
                </Badge>
                {reconcileWatchdog.watchdogArmed && <Badge variant="warning">WATCHDOG ARMED (60s)</Badge>}
              </div>
            </div>
            <CardDescription>
              8-stage SQLite WAL state machine. Preflighting never advances <code className="font-mono text-xs">appliedStructuralSequence</code> or LKG until commit-confirm verification passes.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-3 font-mono">
              <div>
                <div className="font-sans text-slate-500">Received vs Applied</div>
                <div className="font-semibold text-slate-900 tabular-nums">
                  recv #{reconcileWatchdog.receivedStructuralSequence} · applied #{reconcileWatchdog.appliedStructuralSequence}
                </div>
              </div>
              <div>
                <div className="font-sans text-slate-500">Last Known Good (LKG)</div>
                <div className="font-semibold text-emerald-700 tabular-nums">
                  seq #{reconcileWatchdog.lastKnownGoodSequence} ({reconcileWatchdog.lastKnownGoodDigest?.slice(0, 10) ?? "none"}…)
                </div>
              </div>
              <div className="col-span-2 truncate text-[11px] text-slate-600" title={reconcileWatchdog.candidateDigest}>
                Candidate SHA-256: {reconcileWatchdog.candidateDigest.slice(0, 22)}… · {reconcileWatchdog.lastTransitionReason}
              </div>
            </div>

            {canEdit && (
              <div className="flex flex-wrap gap-1.5">
                <ActionForm action={mutateReconcileWatchdogAction} submitLabel="1. Stage & Preflight" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="stage_candidate" />
                </ActionForm>
                <ActionForm action={mutateReconcileWatchdogAction} submitLabel="2. Apply & Arm 60s Watchdog" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="arm_apply_unverified" />
                </ActionForm>
                <ActionForm action={mutateReconcileWatchdogAction} submitLabel="3A. Confirm Health (VERIFIED)" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="confirm_verified" />
                </ActionForm>
                <ActionForm action={mutateReconcileWatchdogAction} submitLabel="3B. Timeout Rollback" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="trigger_watchdog_timeout" />
                </ActionForm>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Gauge className="h-4 w-4 text-indigo-600" />
                Live Session Revocation & Durable WAL Metering
              </CardTitle>
              <Badge variant="info" className="font-mono text-xs">
                WAL seq #{sessionMetering.checkpoint.checkpointSequence}
              </Badge>
            </div>
            <CardDescription>
              Separates TCP runtime closers (<code className="font-mono text-xs">closed</code>) from multiplexed QUIC streams (<code className="font-mono text-xs">muted_unclosable</code>) and enforces persist-before-ack WAL checkpointing.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="rounded-lg border border-slate-200 divide-y divide-slate-100">
              {sessionMetering.sessions.map((s) => (
                <div key={s.sessionId} className="flex items-center justify-between px-3 py-1.5 font-mono text-[11px]">
                  <div>
                    <span className="font-semibold text-slate-900">{s.principalId}</span>{" "}
                    <span className="text-slate-500">({s.protocol} · gen #{s.credentialGeneration})</span>
                  </div>
                  <Badge
                    variant={
                      s.disposition === "active" ? "success" : s.disposition === "closed" ? "secondary" : "warning"
                    }
                  >
                    {s.disposition}
                  </Badge>
                </div>
              ))}
            </div>

            {sessionMetering.lastRevocationSummary && (
              <div className="rounded-lg border border-amber-200 bg-amber-50/70 px-3 py-2 text-[11px] text-amber-950 font-mono">
                Revoked {sessionMetering.lastRevocationSummary.principalId}:{" "}
                <strong>{sessionMetering.lastRevocationSummary.closedCount} closed</strong> ·{" "}
                <strong>{sessionMetering.lastRevocationSummary.mutedUnclosableCount} muted_unclosable</strong> ·{" "}
                terminated: <strong>{String(sessionMetering.lastRevocationSummary.existingStreamsGuaranteedTerminated)}</strong>
              </div>
            )}

            <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5 font-mono text-[11px] space-y-1">
              {sessionMetering.checkpoint.trackedUsers.map((u) => (
                <div key={u.principalId} className="flex items-center justify-between tabular-nums">
                  <span>
                    {u.principalId} (seq #{u.lastSequence})
                  </span>
                  <span>
                    ↑ {fmtBytes(u.totalAccumulatedUplinkBytes)} · ↓ {fmtBytes(u.totalAccumulatedDownlinkBytes)}{" "}
                    <span className={u.dirty ? "text-amber-700 font-semibold" : "text-emerald-700"}>
                      [{u.dirty ? "dirty WAL" : "flushed"}]
                    </span>
                  </span>
                </div>
              ))}
            </div>

            {canEdit && (
              <div className="flex flex-wrap gap-1.5">
                <ActionForm action={mutateNodeSessionMeteringAction} submitLabel="+ Sample WAL Counter" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="accept_sample" />
                </ActionForm>
                <ActionForm action={mutateNodeSessionMeteringAction} submitLabel="Flush Durable Totals" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="flush_durable" />
                </ActionForm>
                <ActionForm
                  action={mutateNodeSessionMeteringAction}
                  submitLabel={`Revoke ${primaryPrincipalId} Sessions`}
                  variant="outline"
                  size="sm"
                >
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="revoke_u1_sessions" />
                </ActionForm>
                <ActionForm action={mutateNodeSessionMeteringAction} submitLabel="Re-Authorize Next Gen" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="operation" value="reset_active_sessions" />
                </ActionForm>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 5: Collapsible Deep Diagnostics, Firewall, SyncFeed, Revisions & Incident Controls */}
      <div className="space-y-3">
        <details className="group rounded-xl border border-slate-200 bg-white shadow-xs">
          <summary className="flex cursor-pointer list-none items-center justify-between px-5 py-3.5 text-sm font-semibold text-slate-900">
            <span className="flex items-center gap-2">
              <ChevronRight className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-90" />
              <ShieldCheck className="h-4 w-4 text-indigo-600" />
              Read-Only Firewall Inventory & Protected-Rule Safety ({firewallInventory.snapshot.rules.length} rules)
            </span>
            <Badge variant={firewallInventory.report.valid ? "success" : "error"}>
              {firewallInventory.report.valid ? "SAFETY VERIFIED" : "UNSAFE RULE"}
            </Badge>
          </summary>
          <div className="border-t border-slate-100 p-5 space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 font-mono">
              <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5">
                <div className="font-sans text-slate-500">SSH / Mgmt (:22)</div>
                <div className="mt-0.5 font-semibold text-emerald-700">
                  {firewallInventory.report.sshManagementProtected ? "PROTECTED" : "UNPROTECTED"}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5">
                <div className="font-sans text-slate-500">Loopback (lo)</div>
                <div className="mt-0.5 font-semibold text-emerald-700">
                  {firewallInventory.report.loopbackProtected ? "PROTECTED" : "UNPROTECTED"}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5">
                <div className="font-sans text-slate-500">Private Egress Guard</div>
                <div className="mt-0.5 font-semibold text-emerald-700">
                  {firewallInventory.report.privateEgressGuardComplete ? "7/7 CIDRs BLOCKED" : "INCOMPLETE"}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5">
                <div className="font-sans text-slate-500">Rule Ownership</div>
                <div className="mt-0.5 font-semibold text-slate-900">
                  {firewallInventory.report.ownedRuleCount} owned · {firewallInventory.report.unmanagedRuleCount} host
                </div>
              </div>
            </div>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule ID</TableHead>
                    <TableHead>Table / Chain</TableHead>
                    <TableHead>Protocol & Target</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead>Ownership</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {firewallInventory.snapshot.rules.map((r) => (
                    <TableRow key={r.ruleId}>
                      <TableCell className="font-mono text-xs font-medium text-slate-900">{r.ruleId}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {r.table} / {r.chain}
                      </TableCell>
                      <TableCell className="font-mono text-xs tabular-nums">
                        {r.protocol.toUpperCase()}
                        {r.portRange && r.portRange !== "any" ? ` :${r.portRange}` : ""}
                        {r.destinationCidr && r.destinationCidr !== "0.0.0.0/0" ? ` → ${r.destinationCidr}` : ""}
                      </TableCell>
                      <TableCell>
                        <Badge variant={r.verdict === "accept" ? "success" : "warning"}>{r.verdict}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={r.ownedByOmniPanel ? "info" : "secondary"}>
                          {r.ownedByOmniPanel ? "OmniPanel-owned" : "unmanaged host"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableWrapper>
          </div>
        </details>

        <details className="group rounded-xl border border-slate-200 bg-white shadow-xs">
          <summary className="flex cursor-pointer list-none items-center justify-between px-5 py-3.5 text-sm font-semibold text-slate-900">
            <span className="flex items-center gap-2">
              <ChevronRight className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-90" />
              <Database className="h-4 w-4 text-indigo-600" />
              Bounded SyncFeed Cursor, Tombstones & Revision History ({revs.length} revisions)
            </span>
            <Badge variant={syncFeed.verified ? "success" : "error"}>
              SyncFeed [{syncFeed.page.baseCursor}→{syncFeed.page.nextCursor}]
            </Badge>
          </summary>
          <div className="border-t border-slate-100 p-5 grid gap-6 lg:grid-cols-2 text-xs">
            <div className="space-y-3">
              <div className="flex items-center justify-between font-mono rounded-lg border border-slate-200 bg-slate-50 p-2.5">
                <span>
                  Cursor {syncFeed.page.baseCursor} → {syncFeed.page.nextCursor} ({syncFeed.page.records.length} records)
                </span>
                <span className="text-slate-600">sha256:{syncFeed.page.digest.slice(0, 16)}…</span>
              </div>
              <div className="max-h-36 overflow-y-auto rounded-lg border border-slate-200 divide-y divide-slate-100">
                {syncFeed.page.records.map((r) => (
                  <div key={r.sequence} className="flex items-center justify-between px-3 py-1.5 font-mono text-[11px]">
                    <span>
                      #{r.sequence} {r.id}
                    </span>
                    <Badge variant={r.tombstone ? "warning" : "success"} className="text-[10px]">
                      {r.tombstone ? "tombstone (0 B)" : `active (${Buffer.byteLength(r.payloadUtf8, "utf8")} B)`}
                    </Badge>
                  </div>
                ))}
              </div>
              {canEdit && (
                <div className="flex flex-wrap gap-1.5">
                  <ActionForm action={advanceSyncFeedAction} submitLabel="+ Active Record" variant="outline" size="sm">
                    <input type="hidden" name="nodeId" value={id} />
                    <input type="hidden" name="operation" value="append_active" />
                  </ActionForm>
                  <ActionForm action={advanceSyncFeedAction} submitLabel="+ Tombstone" variant="outline" size="sm">
                    <input type="hidden" name="nodeId" value={id} />
                    <input type="hidden" name="operation" value="emit_tombstone" />
                  </ActionForm>
                  <ActionForm action={advanceSyncFeedAction} submitLabel="Compact Cursor" variant="outline" size="sm">
                    <input type="hidden" name="nodeId" value={id} />
                    <input type="hidden" name="operation" value="compact_cursor" />
                  </ActionForm>
                </div>
              )}
            </div>

            <div className="space-y-3">
              <TableWrapper>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Seq</TableHead>
                      <TableHead>Epoch</TableHead>
                      <TableHead>Digest</TableHead>
                      <TableHead>Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {revs.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell className="font-mono text-xs font-semibold tabular-nums">#{r.sequence}</TableCell>
                        <TableCell className="font-mono text-xs tabular-nums">#{r.epoch}</TableCell>
                        <TableCell className="font-mono text-xs">{r.digest.slice(0, 12)}…</TableCell>
                        <TableCell>
                          {canEdit && r.sequence !== node.structuralSeq ? (
                            <ActionForm action={publishAction} submitLabel="Roll back" variant="outline" size="sm">
                              <input type="hidden" name="nodeId" value={id} />
                              <input type="hidden" name="rollbackOf" value={r.sequence} />
                            </ActionForm>
                          ) : (
                            <span className="text-slate-400">Active (#{attempts[0]?.structuralSeq ?? r.sequence})</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableWrapper>
            </div>
          </div>
        </details>

        {canEdit && (
          <details className="group rounded-xl border border-rose-200/80 bg-white shadow-xs">
            <summary className="flex cursor-pointer list-none items-center justify-between px-5 py-3.5 text-sm font-semibold text-slate-900">
              <span className="flex items-center gap-2">
                <ChevronRight className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-90" />
                <ShieldAlert className="h-4 w-4 text-rose-600" />
                Node Lifecycle & Incident Response Controls
              </span>
              <Badge variant="outline" className="text-xs">
                Drain · Re-Enroll · Quarantine · Key Rotation
              </Badge>
            </summary>
            <div className="border-t border-slate-100 p-5 grid gap-6 md:grid-cols-2">
              <div className="space-y-4">
                <ActionForm
                  action={nodeStatusAction}
                  submitLabel={node.status === "draining" ? "Return Node to Active Service" : "Drain Node"}
                  variant="outline"
                  size="sm"
                >
                  <input type="hidden" name="nodeId" value={id} />
                  <input type="hidden" name="status" value={node.status === "draining" ? "active" : "draining"} />
                </ActionForm>

                <ActionForm action={updateAddressAction} submitLabel="Replace Public Address" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                  <Field label="New Public IP / Hostname">
                    <Input name="address" defaultValue={node.publicAddress} className="font-mono" />
                  </Field>
                </ActionForm>

                <ActionForm action={reissueEnrollAction} submitLabel="Re-Issue One-Time Enrollment Token" variant="outline" size="sm">
                  <input type="hidden" name="nodeId" value={id} />
                </ActionForm>
              </div>

              {isOwner && (
                <div className="space-y-4 rounded-xl border border-rose-200 bg-rose-50/40 p-4">
                  <ActionForm action={quarantineAction} submitLabel="Quarantine Node" variant="destructive" size="sm">
                    <input type="hidden" name="nodeId" value={id} />
                    <Field label="Type QUARANTINE to confirm">
                      <Input name="confirm" placeholder="QUARANTINE" className="font-mono" />
                    </Field>
                  </ActionForm>

                  <ActionForm
                    action={rotateSecretsAction}
                    submitLabel="Rotate All Credentials & Reality Keys on Node"
                    variant="destructive"
                    size="sm"
                  >
                    <input type="hidden" name="nodeId" value={id} />
                  </ActionForm>
                </div>
              )}
            </div>
          </details>
        )}
      </div>
    </div>
  );
}
