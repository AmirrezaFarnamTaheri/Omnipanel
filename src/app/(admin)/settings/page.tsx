import Link from "next/link";
import {
  Archive,
  ChevronRight,
  Database,
  FileSpreadsheet,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldCheck,
  Sliders,
  Trash2,
  UserCheck,
} from "lucide-react";
import { db } from "@/db";
import { nodes, plans, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { verifyAuditChain } from "@/lib/audit";
import { ago, fmtBytes } from "@/lib/format";
import {
  getCertificateInventory,
  getEnrollmentAuthorityState,
  getLastPanelImportDryRun,
  getLastPitrRecoveryDrill,
  getSubscriptionProfileConfig,
  listBackupTasks,
} from "@/lib/governance-store";
import {
  buildTimeSeriesPartitionPlan,
  evaluateDatabaseScalabilityReadiness,
  evaluateShortLivedMtlsPolicy,
  signAlertWebhookEnvelope,
  wrapWithKmsTransitEnvelope,
} from "@/lib/enterprise-hardening";
import { getEpoch } from "@/lib/revisions";
import { profileMetadataHeaders, subscriptionUserinfo } from "@/lib/subscription-profile";
import { usageForUser } from "@/lib/users";
import { totpBeginAction, totpConfirmAction, totpDisableAction } from "@/app/actions/auth";
import {
  advanceBackupTaskAction,
  commitPanelImportUsersAction,
  declareEpochAction,
  purgeRetentionAction,
  queueBackupTaskAction,
  runEnrollmentAuthorityDrillAction,
  runPanelImportDryRunAction,
  runPitrRecoveryDrillAction,
  updateSubscriptionProfileAction,
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
  Stat,
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

export default async function SettingsPage() {
  const me = await requirePage("viewer");
  const isOwner = me.role === "owner";
  const epoch = await getEpoch();
  const auditChain = await verifyAuditChain();
  const profileCfg = await getSubscriptionProfileConfig();
  const backupTasks = await listBackupTasks();
  const pitrDrill = await getLastPitrRecoveryDrill();
  const certInventory = await getCertificateInventory();
  const importDryRun = await getLastPanelImportDryRun();
  const enrollmentAuth = await getEnrollmentAuthorityState();
  const allNodes = await db.select().from(nodes).orderBy(nodes.id);

  const kmsEnvelopeSample = wrapWithKmsTransitEnvelope({
    kmsKeyUri: "kms://vault.omnipanel.internal/transit/keys/control-plane-kek-v2",
    keyVersion: epoch,
    kmsMasterSecret: Buffer.alloc(32, 0x42),
    contextAad: { epoch: String(epoch), auditCount: String(auditChain.count) },
    plaintext: Buffer.from(`epoch-${epoch}-audit-${auditChain.count}-dek-probe`, "utf8"),
  });
  const shortLivedMtls = evaluateShortLivedMtlsPolicy({
    nodeId: allNodes[0]?.id ?? 1,
    ttlSeconds: 14_400,
    revokedSerials: [],
  });
  const partitionPlans = buildTimeSeriesPartitionPlan();
  const dbScalability = evaluateDatabaseScalabilityReadiness();
  const webhookTimestampSec = Math.floor(
    (allNodes[0]?.lastSeenAt?.getTime() ?? allNodes[0]?.createdAt?.getTime() ?? 1_762_400_000_000) / 1000,
  );
  const sampleSignedWebhook = signAlertWebhookEnvelope({
    secret: "omnipanel-webhook-signing-key",
    eventId: `evt-epoch-${epoch}`,
    timestamp: webhookTimestampSec,
    severity: "info",
    eventKind: "slo_burn_rate_nominal",
    payload: {
      node: allNodes[0]?.name ?? "control-plane",
      epoch,
    },
  });

  const [firstUser] = await db.select().from(users).orderBy(users.id).limit(1);
  const allPlans = await db.select().from(plans);
  const userPlan = firstUser ? allPlans.find((p) => p.id === firstUser.planId) : undefined;
  const realUsage = firstUser ? await usageForUser(db, firstUser.id) : { up: 0, down: 0, total: 0 };

  const previewUserinfo = subscriptionUserinfo({
    uploadBytes: realUsage.up,
    downloadBytes: realUsage.down,
    quotaBytes: userPlan?.quotaBytes ?? null,
    expiresAt: firstUser?.expiresAt ?? null,
    expiryPresentation: profileCfg.expiryPresentation,
  });
  const previewHeaders = profileMetadataHeaders({
    title: `${profileCfg.profileTitlePrefix} ${firstUser?.name ?? "Subscriber"}`,
    supportUrl: profileCfg.supportUrl || undefined,
    webPageUrl: profileCfg.profileWebPageUrl || undefined,
    announce: profileCfg.announce || undefined,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings, Backups & Migration"
        subtitle="Customize subscription client headers, manage backups, import users from S-UI or 3X-UI, and configure optional account security."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Control-Plane Epoch" value={`#${epoch}`} hint="Monotonic recovery epoch" />
        <Stat
          label="Audit Hash Chain"
          value={auditChain.ok ? "VERIFIED" : "BROKEN"}
          hint={`${auditChain.count} chained event(s)`}
        />
        <Stat
          label="Update Interval"
          value={`${profileCfg.updateIntervalHours}h`}
          hint={`Expiry mode: ${profileCfg.expiryPresentation}`}
        />
        <Stat
          label="Backups"
          value={backupTasks.length}
          hint={`${backupTasks.filter((t) => t.state === "succeeded" || t.state === "restored").length} completed`}
        />
      </div>

      {/* Section 1: Subscription Profile & Live Header Preview */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Sliders className="h-4 w-4 text-indigo-600" />
              Subscription Client Display & Headers
            </CardTitle>
            <CardDescription>
              Customize the profile title, update interval, and optional announcement shown inside Sing-box, Clash Meta, and v2rayNG.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isOwner ? (
              <ActionForm
                action={updateSubscriptionProfileAction}
                submitLabel="Save Subscription Settings"
                className="grid grid-cols-1 gap-4 sm:grid-cols-2"
              >
                <Field label="Profile Title Prefix" hint="Shown before the user name in client apps">
                  <Input name="profileTitlePrefix" required defaultValue={profileCfg.profileTitlePrefix} />
                </Field>
                <Field label="Expiry Timestamp Mode">
                  <Select name="expiryPresentation" defaultValue={profileCfg.expiryPresentation}>
                    <option value="exclusive">exclusive (exact timestamp)</option>
                    <option value="inclusive">inclusive (display-adjusted -1s)</option>
                  </Select>
                </Field>
                <Field label="Support URL (optional, https://)">
                  <Input name="supportUrl" type="url" defaultValue={profileCfg.supportUrl} />
                </Field>
                <Field label="Portal URL (optional, https://)">
                  <Input name="profileWebPageUrl" type="url" defaultValue={profileCfg.profileWebPageUrl} />
                </Field>
                <Field label="Auto-Update Interval (Hours)">
                  <Input
                    name="updateIntervalHours"
                    type="number"
                    min={1}
                    max={168}
                    defaultValue={profileCfg.updateIntervalHours}
                  />
                </Field>
                <Field label="Client Announcement Banner (optional)" className="sm:col-span-2">
                  <Input name="announce" defaultValue={profileCfg.announce} />
                </Field>
              </ActionForm>
            ) : (
              <p className="text-sm text-slate-600">
                Updating subscription profile settings requires an owner account.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Live HTTP Header Preview</CardTitle>
            <CardDescription>
              Sample headers for <code className="font-mono text-xs">{firstUser?.name ?? "Subscriber"}</code>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="rounded-lg bg-slate-900 p-3 font-mono text-[11px] text-slate-100 space-y-1.5 overflow-x-auto">
              <div>
                <span className="text-indigo-400">subscription-userinfo:</span> {previewUserinfo}
              </div>
              <div>
                <span className="text-indigo-400">profile-update-interval:</span> {profileCfg.updateIntervalHours}
              </div>
              {Object.entries(previewHeaders).map(([k, v]) => (
                <div key={k} className="break-all">
                  <span className="text-emerald-400">{k}:</span> {v}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Section 2: Dry-Run S-UI / 3X-UI Migration Importer */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-base">
                <FileSpreadsheet className="h-4 w-4 text-indigo-600" />
                S-UI & 3X-UI Migration Importer
              </CardTitle>
              <CardDescription>
                Preview and import users and endpoints from S-UI or 3X-UI JSON exports. Legacy traffic is tagged{" "}
                <code className="font-mono text-xs">historical_non_billable</code> so imported users aren&apos;t unexpectedly suspended.
              </CardDescription>
            </div>
            {importDryRun && (
              <Badge variant="info" className="font-mono text-xs">
                {importDryRun.sourcePanel} v{importDryRun.sourceVersion} · {importDryRun.admittedInbounds.length} admitted / {importDryRun.rejectedInbounds.length} rejected
              </Badge>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          {importDryRun ? (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <TableWrapper>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Candidate Endpoint</TableHead>
                      <TableHead>Protocol / Port</TableHead>
                      <TableHead>Decision</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {importDryRun.admittedInbounds.map((ep) => (
                      <TableRow key={ep.tag}>
                        <TableCell className="font-mono text-xs font-semibold text-slate-900">{ep.tag}</TableCell>
                        <TableCell className="font-mono text-xs tabular-nums">
                          {ep.canonicalProtocol} :{ep.port}
                        </TableCell>
                        <TableCell>
                          <Badge variant="success">admitted ({ep.clientCount} client)</Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                    {importDryRun.rejectedInbounds.map((ep) => (
                      <TableRow key={ep.tag}>
                        <TableCell className="font-mono text-xs font-semibold text-slate-900">{ep.tag}</TableCell>
                        <TableCell className="font-mono text-xs text-slate-500">rejected</TableCell>
                        <TableCell>
                          <Badge variant="warning">rejected</Badge>
                          <div className="mt-1 text-[11px] text-amber-800">{ep.reason}</div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableWrapper>

              <TableWrapper>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Candidate Subscriber</TableHead>
                      <TableHead>Historical Traffic</TableHead>
                      <TableHead>Classification</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {importDryRun.historicalUsage.map((u) => (
                      <TableRow key={u.logicalUserName}>
                        <TableCell className="font-mono text-xs font-semibold text-slate-900">
                          {u.logicalUserName}
                        </TableCell>
                        <TableCell className="font-mono text-xs tabular-nums">
                          ↑ {fmtBytes(u.historicalUpBytes)} · ↓ {fmtBytes(u.historicalDownBytes)}
                        </TableCell>
                        <TableCell>
                          <Badge variant="info">{u.accountingClassification}</Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableWrapper>
            </div>
          ) : (
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-slate-600">
              Paste a 3X-UI or S-UI export JSON below (or leave blank to test with a snapshot of your current panel) to preview admitted endpoints and users.
            </div>
          )}

          {isOwner && (
            <div className="space-y-3 border-t border-slate-100 pt-3">
              <ActionForm
                action={runPanelImportDryRunAction}
                submitLabel="Preview Migration Import"
                variant="outline"
                size="sm"
                className="space-y-3"
              >
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <Field label="Source Panel">
                    <Select name="sourcePanel" defaultValue={importDryRun?.sourcePanel ?? "3x-ui"}>
                      <option value="s-ui">S-UI (Sing-box JSON)</option>
                      <option value="3x-ui">3X-UI (Xray JSON)</option>
                    </Select>
                  </Field>
                  <Field
                    label="Export JSON (optional — leave blank to preview current DB snapshot)"
                    className="sm:col-span-2"
                  >
                    <textarea
                      name="rawExportJson"
                      rows={2}
                      placeholder='{"sourcePanel":"3x-ui","sourceVersion":"2.4.1","inbounds":[...]}'
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-[11px] text-slate-900 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 focus:outline-hidden"
                    />
                  </Field>
                </div>
              </ActionForm>

              {importDryRun && (
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-indigo-100 bg-indigo-50/50 p-3">
                  <div className="text-xs text-slate-700">
                    <strong>Ready to Import ({importDryRun.migrationJournalDigest.slice(0, 12)}…):</strong>{" "}
                    Provisions admitted users onto your active endpoints in a single transaction.
                  </div>
                  <ActionForm
                    action={commitPanelImportUsersAction}
                    submitLabel="Import Admitted Users"
                    size="sm"
                  >
                    <input type="hidden" name="expectedDryRunDigest" value={importDryRun.migrationJournalDigest} />
                  </ActionForm>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Section 3: Backups & Maintenance */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Archive className="h-4 w-4 text-indigo-600" />
              Backups & Snapshots
            </CardTitle>
            <CardDescription>
              Queue local or S3-compatible control-plane backups and track verification digests.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {isOwner && (
              <ActionForm
                action={queueBackupTaskAction}
                submitLabel="Create Backup Task"
                size="sm"
                className="grid grid-cols-1 gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-3 sm:grid-cols-3"
              >
                <Field label="Operation">
                  <Select name="kind" defaultValue="backup">
                    <option value="backup">Backup Control Plane</option>
                    <option value="restore">Verify & Stage Restore</option>
                  </Select>
                </Field>
                <Field label="Storage Path / URI" className="sm:col-span-2">
                  <Input
                    name="storageTarget"
                    required
                    defaultValue="local:/var/lib/omnipanel/archives/snap.tar.zst"
                  />
                </Field>
              </ActionForm>
            )}

            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Task ID</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Target & Digest</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead>Step</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {backupTasks.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6}>
                        <EmptyState title="No backup tasks" description="Create a backup task above." />
                      </TableCell>
                    </TableRow>
                  ) : (
                    backupTasks.map((t) => {
                      const nextOptions: string[] = [];
                      if (t.state === "queued") nextOptions.push("running");
                      if (t.state === "running") {
                        if (t.kind === "restore") nextOptions.push("verifying_restore");
                        nextOptions.push("succeeded", "failed");
                      }
                      if (t.state === "verifying_restore") nextOptions.push("restored", "failed");
                      if (t.state === "failed") nextOptions.push("queued");

                      return (
                        <TableRow key={t.id}>
                          <TableCell className="font-mono text-xs font-medium text-slate-900">{t.id}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="uppercase text-[10px]">
                              {t.kind}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge variant={statusTone(t.state)}>{t.state}</Badge>
                          </TableCell>
                          <TableCell className="max-w-[220px]">
                            <div className="truncate font-mono text-xs text-slate-800" title={t.storageTarget}>
                              {t.storageTarget}
                            </div>
                            {t.artifactDigest && (
                              <div className="truncate font-mono text-[10px] text-emerald-700" title={t.artifactDigest}>
                                {t.artifactDigest}
                              </div>
                            )}
                          </TableCell>
                          <TableCell className="text-xs text-slate-500 tabular-nums">
                            {ago(new Date(t.updatedAt))}
                          </TableCell>
                          <TableCell>
                            {isOwner && nextOptions.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {nextOptions.map((nextState) => (
                                  <ActionForm
                                    key={nextState}
                                    action={advanceBackupTaskAction}
                                    submitLabel={`→ ${nextState}`}
                                    variant="outline"
                                    size="sm"
                                  >
                                    <input type="hidden" name="taskId" value={t.id} />
                                    <input type="hidden" name="nextState" value={nextState} />
                                  </ActionForm>
                                ))}
                              </div>
                            ) : (
                              <span className="text-xs text-slate-400">Done</span>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </TableWrapper>
          </CardContent>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <KeyRound className="h-4 w-4 text-indigo-600" />
                Optional Two-Factor Auth (TOTP)
              </CardTitle>
              <CardDescription>
                2FA is completely optional for personal use. You can enable or disable it anytime.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex flex-wrap gap-2">
                <ActionForm action={totpBeginAction} submitLabel="Generate TOTP Secret" variant="outline" size="sm" />
                <ActionForm action={totpDisableAction} submitLabel="Disable 2FA" variant="outline" size="sm" />
              </div>
              <ActionForm
                action={totpConfirmAction}
                submitLabel="Verify & Enable 2FA"
                size="sm"
                className="border-t border-slate-100 pt-3 space-y-2"
              >
                <Field label="6-Digit Authenticator Code">
                  <Input name="code" placeholder="123456" pattern="\d{6}" required className="font-mono tabular-nums" />
                </Field>
              </ActionForm>
            </CardContent>
          </Card>

          {isOwner && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Trash2 className="h-4 w-4 text-slate-600" />
                  Cleanup & Recovery Epoch
                </CardTitle>
                <CardDescription>
                  One-click telemetry cleanup and control-plane epoch bump.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap gap-2">
                  <ActionForm
                    action={purgeRetentionAction}
                    submitLabel="Purge Old Telemetry (>30d)"
                    variant="outline"
                    size="sm"
                  />
                  <ActionForm
                    action={declareEpochAction}
                    submitLabel={`Bump Epoch (#${epoch} → #${epoch + 1})`}
                    variant="outline"
                    size="sm"
                  >
                    <input type="hidden" name="reason" value="Personal operator recovery epoch bump" />
                  </ActionForm>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Collapsible Advanced Security & Architecture Diagnostics */}
      <details className="group rounded-xl border border-slate-200 bg-white shadow-xs">
        <summary className="flex cursor-pointer list-none items-center justify-between px-5 py-3.5 text-sm font-semibold text-slate-900">
          <span className="flex items-center gap-2">
            <ChevronRight className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-90" />
            <ShieldCheck className="h-4 w-4 text-indigo-600" />
            Advanced Security Diagnostics: Certificate Boundaries, PITR Drill, Enrollment Grants & Metrics
          </span>
          <div className="flex items-center gap-2">
            <Badge variant="success">{kmsEnvelopeSample.version}</Badge>
            <Badge variant="info">mTLS TTL: {shortLivedMtls.ttlSeconds / 3600}h</Badge>
            <Link
              href="/api/metrics"
              className="rounded border border-indigo-200 bg-indigo-50 px-2 py-0.5 font-mono text-xs text-indigo-700 hover:bg-indigo-100"
            >
              /api/metrics →
            </Link>
          </div>
        </summary>
        <div className="border-t border-slate-100 p-5 space-y-6 text-xs">
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <div className="space-y-3 rounded-lg border border-slate-200 p-4">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-900 flex items-center gap-1.5">
                  <Database className="h-4 w-4 text-indigo-600" />
                  PITR + KEK Unsealing Drill
                </span>
                <Badge variant={pitrDrill?.verified ? "info" : "secondary"}>
                  {pitrDrill ? (pitrDrill.verified ? "OK" : "FAILED") : "READY"}
                </Badge>
              </div>
              {pitrDrill && (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 font-mono text-[11px]">
                  {pitrDrill.kekId} · Epoch #{pitrDrill.previousEpoch} → #{pitrDrill.newAuthorizedEpoch}
                </div>
              )}
              {isOwner && (
                <ActionForm
                  action={runPitrRecoveryDrillAction}
                  submitLabel="Run PITR + KEK Drill"
                  variant="outline"
                  size="sm"
                >
                  <input type="hidden" name="providerKind" value="local_private_dir" />
                </ActionForm>
              )}
            </div>

            <div className="space-y-3 rounded-lg border border-slate-200 p-4">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-900 flex items-center gap-1.5">
                  <UserCheck className="h-4 w-4 text-indigo-600" />
                  Enrollment Grant Authority
                </span>
                <Badge variant="info">{enrollmentAuth.grantStatus}</Badge>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 font-mono text-[11px]">
                {enrollmentAuth.activeGrantId} · {enrollmentAuth.stepUpVerifiedSource} (#{enrollmentAuth.stepUpCounter})
              </div>
              {isOwner && (
                <div className="flex flex-wrap gap-1.5">
                  <ActionForm action={runEnrollmentAuthorityDrillAction} submitLabel="Mint Grant" variant="outline" size="sm">
                    <input type="hidden" name="operation" value="mint_trusted_grant" />
                  </ActionForm>
                  <ActionForm action={runEnrollmentAuthorityDrillAction} submitLabel="Redeem CSR" variant="outline" size="sm">
                    <input type="hidden" name="operation" value="redeem_csr_mtls" />
                  </ActionForm>
                </div>
              )}
            </div>

            <div className="space-y-2 rounded-lg border border-slate-200 p-4 font-mono text-[11px]">
              <div className="font-sans font-semibold text-slate-900 flex items-center gap-1.5">
                <Lock className="h-4 w-4 text-indigo-600" />
                PKI & Database Scalability
              </div>
              <div className="truncate text-indigo-700">{kmsEnvelopeSample.kmsKeyUri}</div>
              <div className="truncate text-emerald-700">{shortLivedMtls.spiffeUri}</div>
              <div className="text-slate-600">
                {partitionPlans.length} partitioned tables · Outbox: {dbScalability.channelName} · Webhook: {sampleSignedWebhook.signatureHeader.slice(0, 18)}…
              </div>
            </div>
          </div>

          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Boundary</TableHead>
                  <TableHead>Domain / SPIFFE SAN</TableHead>
                  <TableHead>Node</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {certInventory.entries.map((c, idx) => {
                  const ev = certInventory.report.evaluations[idx];
                  return (
                    <TableRow key={c.certId}>
                      <TableCell className="font-mono text-xs font-semibold text-slate-900">{c.boundary}</TableCell>
                      <TableCell className="font-mono text-xs">{c.domainOrSan}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-600">{c.nodeId ?? "control-plane"}</TableCell>
                      <TableCell>
                        <Badge variant={statusTone(ev?.state ?? "healthy")}>{ev?.state ?? "healthy"}</Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableWrapper>
        </div>
      </details>
    </div>
  );
}
