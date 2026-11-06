import {
  Archive,
  Database,
  FileSpreadsheet,
  KeyRound,
  Lock,
  RefreshCw,
  Sliders,
  Trash2,
  UserCheck,
} from "lucide-react";
import { db } from "@/db";
import { plans, users } from "@/db/schema";
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
import { getEpoch } from "@/lib/revisions";
import { profileMetadataHeaders, subscriptionUserinfo } from "@/lib/subscription-profile";
import { usageForUser } from "@/lib/users";
import { totpBeginAction, totpConfirmAction } from "@/app/actions/auth";
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
        title="Control-Plane Governance & Settings"
        subtitle="Audited, owner-gated configuration for subscription metadata headers, backup/restore lifecycles, PITR + KEK recovery drills, certificate boundaries, and dry-run panel migration."
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Control-Plane Epoch" value={`#${epoch}`} hint="Monotonic recovery epoch" />
        <Stat
          label="Audit Hash Chain"
          value={auditChain.ok ? "VERIFIED" : "BROKEN"}
          hint={`${auditChain.count} genesis-chained record(s)`}
        />
        <Stat
          label="Expiry Presentation"
          value={profileCfg.expiryPresentation.toUpperCase()}
          hint={`Update interval: ${profileCfg.updateIntervalHours}h`}
        />
        <Stat
          label="Backup / DR Ledger"
          value={backupTasks.length}
          hint={`${backupTasks.filter((t) => t.state === "succeeded" || t.state === "restored").length} verified artifact(s)`}
        />
      </div>

      {/* Section 1: Subscription Profile & Live Header Preview */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Sliders className="h-4 w-4 text-indigo-600" />
              Subscription Profile & Client Metadata Policy
            </CardTitle>
            <CardDescription>
              Controls RFC-compliant <code className="font-mono text-xs">Profile-Title</code>,{" "}
              <code className="font-mono text-xs">Support-Url</code>,{" "}
              <code className="font-mono text-xs">Profile-Web-Page-Url</code>,{" "}
              <code className="font-mono text-xs">Announce</code>, and{" "}
              <code className="font-mono text-xs">Subscription-Userinfo</code> headers emitted by{" "}
              <code className="font-mono text-xs">/sub/[token]</code>.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isOwner ? (
              <ActionForm
                action={updateSubscriptionProfileAction}
                submitLabel="Save Subscription Profile Policy"
                className="grid grid-cols-1 gap-4 sm:grid-cols-2"
              >
                <Field label="Profile Title Prefix" hint="Prepended to subscriber name (UTF-8 Base64)">
                  <Input name="profileTitlePrefix" required defaultValue={profileCfg.profileTitlePrefix} />
                </Field>
                <Field label="Expiry Timestamp Presentation" hint="Inclusive subtracts 1s from midnight UTC">
                  <Select name="expiryPresentation" defaultValue={profileCfg.expiryPresentation}>
                    <option value="exclusive">exclusive (exact stored timestamp)</option>
                    <option value="inclusive">inclusive (display-adjusted -1s)</option>
                  </Select>
                </Field>
                <Field label="Support URL (https:// only)">
                  <Input name="supportUrl" type="url" defaultValue={profileCfg.supportUrl} />
                </Field>
                <Field label="Subscriber Portal URL (https:// only)">
                  <Input name="profileWebPageUrl" type="url" defaultValue={profileCfg.profileWebPageUrl} />
                </Field>
                <Field label="Client Update Interval (Hours)">
                  <Input
                    name="updateIntervalHours"
                    type="number"
                    min={1}
                    max={168}
                    defaultValue={profileCfg.updateIntervalHours}
                  />
                </Field>
                <Field label="Announcement Banner (UTF-8 Base64)" className="sm:col-span-2">
                  <Input name="announce" defaultValue={profileCfg.announce} />
                </Field>
              </ActionForm>
            ) : (
              <p className="text-sm text-slate-600">
                Updating subscription profile metadata requires the <strong>owner</strong> role.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Live HTTP Header Preview</CardTitle>
            <CardDescription>
              Computed from subscriber <code className="font-mono text-xs">{firstUser?.name ?? "none"}</code>
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
            <p className="text-slate-500">
              Header injection characters (<code className="font-mono">CR</code> / <code className="font-mono">LF</code>) and non-HTTPS URLs are rejected before persistence.
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Section 2: Backup & Restore Task Lifecycle Ledger + PITR/KEK Drill */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Archive className="h-4 w-4 text-indigo-600" />
              Durable Backup & Restore Task Ledger
            </CardTitle>
            <CardDescription>
              Provider-neutral state machine enforcing monotonic timestamps and mandatory SHA-256 artifact digests.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {isOwner && (
              <ActionForm
                action={queueBackupTaskAction}
                submitLabel="Queue Archive Task"
                size="sm"
                className="grid grid-cols-1 gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-3 sm:grid-cols-3"
              >
                <Field label="Operation Kind">
                  <Select name="kind" defaultValue="backup">
                    <option value="backup">backup (Snapshot Control Plane)</option>
                    <option value="restore">restore (Verify & Stage Archive)</option>
                  </Select>
                </Field>
                <Field label="Storage Target URI" className="sm:col-span-2">
                  <Input
                    name="storageTarget"
                    required
                    placeholder="s3://omni-dr-vault-eu/control-plane/snap.tar.zst"
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
                    <TableHead>Transition</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {backupTasks.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6}>
                        <EmptyState title="No backup or restore tasks" description="Queue a task above." />
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
                              <span className="text-xs text-slate-400">Terminal</span>
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

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Database className="h-4 w-4 text-indigo-600" />
                PITR + KEK Recovery Drill
              </CardTitle>
              <Badge variant={pitrDrill?.verified ? "success" : "secondary"}>
                {pitrDrill ? (pitrDrill.verified ? "VERIFIED" : "FAILED") : "NOT RUN"}
              </Badge>
            </div>
            <CardDescription>
              Verifies AES-256-GCM DEK/KEK envelope encryption, audit-chain continuity, and monotonic recovery epoch advancement.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            {pitrDrill ? (
              <div className="grid grid-cols-2 gap-2.5 rounded-lg border border-slate-200 bg-slate-50/70 p-3 font-mono">
                <div>
                  <div className="font-sans text-slate-500">KEK / WAL LSN</div>
                  <div className="font-semibold text-slate-900">
                    {pitrDrill.kekId} · {pitrDrill.walTargetLsn}
                  </div>
                </div>
                <div>
                  <div className="font-sans text-slate-500">Simulated Epoch</div>
                  <div className="font-semibold text-emerald-700 tabular-nums">
                    #{pitrDrill.previousEpoch} → #{pitrDrill.newAuthorizedEpoch}
                  </div>
                </div>
                <div className="col-span-2 truncate text-[10px] text-slate-600" title={pitrDrill.plaintextSha256}>
                  sha256:{pitrDrill.plaintextSha256} ({pitrDrill.decryptedPayloadBytes} B)
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-slate-600">
                No PITR + KEK recovery drill has been executed in this session yet.
              </div>
            )}

            {isOwner && (
              <ActionForm
                action={runPitrRecoveryDrillAction}
                submitLabel="Execute PITR + KEK Unsealing Drill"
                variant="outline"
                size="sm"
                className="space-y-3"
              >
                <Field label="Storage Provider">
                  <Select name="providerKind" defaultValue="s3_compatible">
                    <option value="s3_compatible">s3_compatible (HTTPS TLS-verified)</option>
                    <option value="local_private_dir">local_private_dir (0700 mode)</option>
                  </Select>
                </Field>
              </ActionForm>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Section 3: Certificate Boundaries & Enrollment Authority */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <Lock className="h-4 w-4 text-indigo-600" />
                Certificate & ACME TLS Boundary Inventory
              </CardTitle>
              <Badge variant={certInventory.report.valid ? "success" : "error"}>
                {certInventory.report.valid ? "ISOLATED" : "VIOLATION"}
              </Badge>
            </div>
            <CardDescription>
              Derived from live nodes and inbounds. Separates internal <code className="font-mono text-xs">node_mtls</code> SPIFFE CA, public <code className="font-mono text-xs">acme_public_tls</code>, and <code className="font-mono text-xs">reality_decoy</code> targets.
            </CardDescription>
          </CardHeader>
          <CardContent className="text-xs">
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
                        <TableCell className="font-mono text-xs">
                          <div className="truncate max-w-[210px]" title={c.domainOrSan}>
                            {c.domainOrSan}
                          </div>
                        </TableCell>
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <UserCheck className="h-4 w-4 text-indigo-600" />
                Enrollment Grant Authority & Trusted TOTP Step-Up
              </CardTitle>
              <Badge
                variant={
                  enrollmentAuth.grantStatus === "redeemed"
                    ? "success"
                    : enrollmentAuth.grantStatus === "invalidated_by_logout"
                      ? "warning"
                      : "info"
                }
              >
                {enrollmentAuth.grantStatus.replaceAll("_", " ").toUpperCase()}
              </Badge>
            </div>
            <CardDescription>
              Dual-owner grant issuance, RFC 6238 replay counter, logout invalidation, and 60s HMAC peer limiter.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-2.5 font-mono">
              <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5">
                <div className="font-sans text-slate-500">Grant & Dual Owners</div>
                <div className="mt-0.5 font-semibold text-slate-900">{enrollmentAuth.activeGrantId}</div>
                <div className="text-[10px] text-slate-600">
                  {enrollmentAuth.issuerEmail.split("@")[0]} → {enrollmentAuth.approverEmail.split("@")[0]}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-2.5">
                <div className="font-sans text-slate-500">Step-Up & HMAC Limiter</div>
                <div className="mt-0.5 font-semibold text-slate-900 tabular-nums">
                  {enrollmentAuth.stepUpVerifiedSource} (#{enrollmentAuth.stepUpCounter})
                </div>
                <div className="truncate text-[10px] text-slate-600">
                  hmac:{enrollmentAuth.lastRateLimitCheck.peerDigestHex.slice(0, 14)}…
                </div>
              </div>
            </div>

            {isOwner && (
              <div className="flex flex-wrap items-center gap-1.5">
                <ActionForm
                  action={runEnrollmentAuthorityDrillAction}
                  submitLabel="Mint Dual-Owner Grant"
                  variant="outline"
                  size="sm"
                >
                  <input type="hidden" name="operation" value="mint_trusted_grant" />
                </ActionForm>
                <ActionForm
                  action={runEnrollmentAuthorityDrillAction}
                  submitLabel="Redeem CSR → SPIFFE mTLS"
                  variant="outline"
                  size="sm"
                >
                  <input type="hidden" name="operation" value="redeem_csr_mtls" />
                </ActionForm>
                <ActionForm
                  action={runEnrollmentAuthorityDrillAction}
                  submitLabel="Logout Revoke Grant"
                  variant="outline"
                  size="sm"
                >
                  <input type="hidden" name="operation" value="logout_revoke_unredeemed" />
                </ActionForm>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Section 4: Dry-Run S-UI / 3X-UI Migration Importer */}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-base">
                <FileSpreadsheet className="h-4 w-4 text-indigo-600" />
                Dry-Run-First S-UI & 3X-UI Migration Importer
              </CardTitle>
              <CardDescription>
                Evaluates S-UI and 3X-UI exports against the protocol compatibility matrix and port ownership table without mutating live listeners. Imported usage is tagged <code className="font-mono text-xs">historical_non_billable</code>.
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
              No migration dry-run has been evaluated yet. Run a dry-run diff below using a custom S-UI/3X-UI export JSON or leave blank to evaluate a live database snapshot.
            </div>
          )}

          {isOwner && (
            <div className="space-y-3 border-t border-slate-100 pt-3">
              <ActionForm
                action={runPanelImportDryRunAction}
                submitLabel="Run Migration Dry-Run Diff"
                variant="outline"
                size="sm"
                className="space-y-3"
              >
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <Field label="Source Panel Dialect">
                    <Select name="sourcePanel" defaultValue={importDryRun?.sourcePanel ?? "3x-ui"}>
                      <option value="s-ui">S-UI (Sing-box export JSON)</option>
                      <option value="3x-ui">3X-UI (Xray inbound/client export JSON)</option>
                    </Select>
                  </Field>
                  <Field
                    label="S-UI / 3X-UI Export JSON (optional — leave blank to snapshot current DB)"
                    className="sm:col-span-2"
                  >
                    <textarea
                      name="rawExportJson"
                      rows={3}
                      placeholder='{"sourcePanel":"3x-ui","sourceVersion":"2.4.1","inbounds":[...]}'
                      className="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-[11px] text-slate-900 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 focus:outline-hidden"
                    />
                  </Field>
                </div>
              </ActionForm>

              {importDryRun && (
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-indigo-100 bg-indigo-50/50 p-3">
                  <div className="text-xs text-slate-700">
                    <strong>Atomic Non-Conflicting Commit:</strong> Provisions admitted subscribers onto eligible endpoints and records legacy counters as <code className="font-mono">historical_non_billable</code>.
                  </div>
                  <ActionForm
                    action={commitPanelImportUsersAction}
                    submitLabel="Commit Admitted Subscribers"
                    size="sm"
                  />
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Section 5: MFA (TOTP), Recovery Epoch Declaration & Retention Purge */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyRound className="h-4 w-4 text-indigo-600" />
              Operator MFA (TOTP)
            </CardTitle>
            <CardDescription>
              Enroll an RFC 6238 secret encrypted with the envelope KEK (<code className="font-mono text-xs">AES-256-GCM</code>).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <ActionForm action={totpBeginAction} submitLabel="Generate TOTP Secret" variant="outline" size="sm" />
            <ActionForm
              action={totpConfirmAction}
              submitLabel="Verify & Enable TOTP"
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
          <>
            <Card className="border-amber-200/80">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <RefreshCw className="h-4 w-4 text-amber-600" />
                  Declare Recovery Epoch (#{epoch})
                </CardTitle>
                <CardDescription>
                  Increments the control-plane epoch after a restore and forces signed recovery snapshots.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ActionForm
                  action={declareEpochAction}
                  submitLabel={`Authorize Epoch #${epoch + 1}`}
                  variant="outline"
                  size="sm"
                  className="space-y-3"
                >
                  <Field label="Recovery Event Rationale (min 10 chars)">
                    <Input name="reason" required placeholder="Point-in-time snapshot restore verification" />
                  </Field>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    <Field label="Step-Up Password">
                      <Input name="password" type="password" required placeholder="Enter owner password" />
                    </Field>
                    <Field label="TOTP Code">
                      <Input name="code" placeholder="If enrolled" className="font-mono" />
                    </Field>
                  </div>
                </ActionForm>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Trash2 className="h-4 w-4 text-slate-600" />
                  Telemetry Retention Purge
                </CardTitle>
                <CardDescription>
                  Purges raw metering &gt;30d, hourly aggregates &gt;180d, and health probes &gt;7d. Audit records are permanent.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5 text-xs text-slate-600 space-y-1">
                  <div className="flex justify-between">
                    <span>Raw meter_observations:</span>
                    <span className="font-mono font-medium text-slate-900">30 days</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Hourly usage_aggregates:</span>
                    <span className="font-mono font-medium text-slate-900">180 days</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Health observations:</span>
                    <span className="font-mono font-medium text-slate-900">7 days</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Cryptographic audit_log:</span>
                    <span className="font-mono font-semibold text-emerald-700">Permanent</span>
                  </div>
                </div>
                <ActionForm
                  action={purgeRetentionAction}
                  submitLabel="Execute Retention Purge"
                  variant="outline"
                  size="sm"
                />
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
