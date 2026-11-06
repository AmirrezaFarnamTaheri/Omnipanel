import Link from "next/link";
import { notFound } from "next/navigation";
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/db";
import { endpointPrincipals, healthObservations, inbounds, nodes, plans, subscriptionTokens, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { decryptSecret, sha256 } from "@/lib/crypto";
import { buildIR, compile, type AccessPath, type IR } from "@/lib/subscription";
import { compileClientBalancerDocument, computeAdaptiveBalancerParameters } from "@/lib/subscription-balancer";
import { computeSubscriptionEtag } from "@/lib/enterprise-hardening";
import { profileMetadataHeaders, subscriptionUserinfo } from "@/lib/subscription-profile";
import { getSubscriptionProfileConfig } from "@/lib/governance-store";
import { usageForUser } from "@/lib/users";
import { CLIENT_REGISTRY } from "@/lib/capabilities";
import { ago, fmtBytes, fmtDate } from "@/lib/format";
import { rotateEndpointAction, rotateTokenAction, updateUserAction, userStatusAction } from "@/app/actions/people";
import { ActionForm } from "@/components/ActionForm";
import { SubscriptionInspector, type CompiledFormatPreview } from "@/components/SubscriptionInspector";
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

export default async function UserPage({ params }: { params: Promise<{ id: string }> }) {
  const me = await requirePage("viewer");
  const id = Number((await params).id);
  if (!Number.isInteger(id)) notFound();
  const [u] = await db.select().from(users).where(eq(users.id, id));
  if (!u) notFound();
  const canEdit = me.role !== "viewer";
  const allPlans = await db.select().from(plans).orderBy(plans.id);
  const plan = allPlans.find((p) => p.id === u.planId);
  const usage = await usageForUser(db, id);
  const ir = await buildIR(id);
  const profileCfg = await getSubscriptionProfileConfig();

  const principals = await db
    .select({ p: endpointPrincipals, ib: inbounds, node: nodes })
    .from(endpointPrincipals)
    .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
    .innerJoin(nodes, eq(nodes.id, inbounds.nodeId))
    .where(and(eq(endpointPrincipals.userId, id), eq(endpointPrincipals.state, "active")))
    .orderBy(endpointPrincipals.id);

  const [tok] = await db
    .select()
    .from(subscriptionTokens)
    .where(and(eq(subscriptionTokens.userId, id)))
    .orderBy(subscriptionTokens.id)
    .then((r) => r.filter((t) => !t.revokedAt).slice(-1));

  const recentObs = await db
    .select()
    .from(healthObservations)
    .orderBy(desc(healthObservations.id))
    .limit(16);
  const adaptiveTuning = computeAdaptiveBalancerParameters(
    recentObs.map((o) => o.latencyMs).filter((ms): ms is number => typeof ms === "number" && ms >= 0),
  );

  const pct = plan?.quotaBytes ? Math.min(100, (usage.total / plan.quotaBytes) * 100) : 0;

  const provisionedPaths: AccessPath[] = principals
    .filter(({ ib }) => ib.protocol === "vless-reality-vision")
    .map(({ p, ib, node }) => {
      const paramsObj = (ib.params ?? {}) as Record<string, string>;
      return {
        inboundId: ib.id,
        tag: `${node.name}-${ib.name}`,
        nodeName: node.name,
        server: node.publicAddress,
        port: ib.port,
        protocol: "vless-reality-vision",
        transport: "tcp",
        runtime: "singbox",
        credential: decryptSecret(p.credentialEnc),
        sni: ib.sni,
        tlsModel: "reality",
        reality: {
          publicKey: paramsObj.realityPublicKey ?? "",
          shortId: paramsObj.shortId ?? "",
          fingerprint: paramsObj.fingerprint ?? "chrome",
          flow: paramsObj.flow ?? "xtls-rprx-vision",
        },
        route: "direct",
        enforceability: "metered",
        revision: node.structuralSeq,
        health: "healthy",
      };
    });

  const previewIr: IR = {
    user: { id: u.id, name: u.name, status: u.status },
    paths: ir.paths.length > 0 ? ir.paths : provisionedPaths,
    excluded: ir.excluded,
    diagnostics: ir.diagnostics,
    quotaBytes: plan?.quotaBytes ?? null,
    expiresAt: u.expiresAt,
  };

  const balancerDoc = compileClientBalancerDocument({
    groupTag: "omni-auto-best",
    strategy: "url-test",
    probeUrl: "https://cp.cloudflare.com/generate_204",
    intervalSeconds: adaptiveTuning.intervalSeconds,
    toleranceMs: adaptiveTuning.toleranceMs,
    endpoints: previewIr.paths.map((p) => ({
      tag: p.tag,
      protocol: p.protocol,
      weight: 100,
    })),
  });
  const balancerJson = JSON.stringify(balancerDoc, null, 2);

  const formatPreviews: CompiledFormatPreview[] = [
    ...(await Promise.all(
      CLIENT_REGISTRY.map(async (c) => {
        const formatIr = await buildIR(id, c.format);
        const compiled = compile(previewIr, c.format);
        return {
          format: c.format,
          label: c.label,
          contentType: compiled.contentType,
          admittedCount: formatIr.paths.length,
          excludedReasons: formatIr.excluded,
          compiledBody: compiled.body,
          sha256: sha256(compiled.body),
        };
      }),
    )),
    {
      format: "balancer",
      label: "Balancer & Observatory",
      contentType: "application/json",
      admittedCount: balancerDoc.memberTags.length,
      excludedReasons: [],
      compiledBody: balancerJson,
      sha256: balancerDoc.digest,
    },
  ];

  const userinfoHeader = subscriptionUserinfo({
    uploadBytes: usage.up,
    downloadBytes: usage.down,
    quotaBytes: plan?.quotaBytes ?? null,
    expiresAt: u.expiresAt,
    expiryPresentation: profileCfg.expiryPresentation,
  });

  const etagValue = computeSubscriptionEtag({
    compiledBody: formatPreviews[0]?.compiledBody ?? "",
    userinfoHeader,
    format: formatPreviews[0]?.format ?? "singbox",
    updateIntervalHours: profileCfg.updateIntervalHours,
  });

  const headersPreview: Record<string, string> = {
    etag: etagValue,
    "subscription-userinfo": userinfoHeader,
    "profile-update-interval": String(profileCfg.updateIntervalHours),
    ...profileMetadataHeaders({
      title: `${profileCfg.profileTitlePrefix} ${u.name}`,
      supportUrl: profileCfg.supportUrl || undefined,
      webPageUrl: profileCfg.profileWebPageUrl || undefined,
      announce: profileCfg.announce || undefined,
    }),
  };

  return (
    <>
      <PageHeader
        breadcrumbs={
          <>
            <Link href="/users" className="hover:text-slate-900">
              Users
            </Link>
            <span>/</span>
            <span className="text-slate-900">{u.name}</span>
          </>
        }
        title={u.name}
        subtitle={`${u.email ?? "No email"} · ${plan?.name ?? "Plan"} · Created ${fmtDate(u.createdAt)}`}
        actions={
          <div className="flex items-center gap-2">
            <Link
              href={`/portal/${tok ? tok.prefix : u.id}`}
              className="inline-flex h-8 items-center rounded-lg bg-indigo-600 px-3 text-xs font-medium text-white shadow-xs hover:bg-indigo-700"
            >
              Open Shareable Portal →
            </Link>
            <Badge variant={statusTone(u.status)}>
              {u.status}
              {u.suspendReason ? ` (${u.suspendReason})` : ""}
            </Badge>
          </div>
        }
      />

      {/* Row 1: Client Configs & Shareable Portal (Front and center for personal use) */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="text-base">Client Configs & Subscription Links</CardTitle>
          <CardDescription>
            Copy ready-to-use configs for Sing-box, Clash Meta (Mihomo), Xray, or Hysteria2, or open the shareable portal for QR codes.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50/70 p-3.5">
            <div className="text-xs text-slate-600 space-y-1">
              <p>
                Active token prefix:{" "}
                <code className="rounded bg-white px-2 py-0.5 font-mono font-semibold text-slate-900 border border-slate-200">
                  {tok ? `${tok.prefix}…` : "none"}
                </code>{" "}
                {tok?.lastUsedAt ? `· last fetched ${ago(tok.lastUsedAt)}` : "· ready to connect"}
              </p>
              <p className="text-slate-500">
                Clients: {CLIENT_REGISTRY.map((c) => c.label).join(" · ")}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Link
                href={`/portal/${tok ? tok.prefix : u.id}`}
                className="inline-flex h-8 items-center rounded-lg border border-indigo-200 bg-indigo-50 px-3 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
              >
                Open Self-Service Portal →
              </Link>
              {canEdit && (
                <ActionForm
                  action={rotateTokenAction}
                  submitLabel="Rotate Subscription URL"
                  variant="outline"
                  size="sm"
                >
                  <input type="hidden" name="userId" value={u.id} />
                </ActionForm>
              )}
            </div>
          </div>

          <SubscriptionInspector formats={formatPreviews} headersPreview={headersPreview} />
        </CardContent>
      </Card>

      {/* Row 2: Usage & Profile Settings */}
      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Traffic Usage This Period</CardTitle>
            <CardDescription>
              Measured uplink and downlink bytes across all nodes.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-2">
              <span className="text-3xl font-bold tracking-tight text-slate-900 tabular-nums">
                {fmtBytes(usage.total)}
              </span>
            </div>
            <p className="mt-1 font-mono text-xs text-slate-600 tabular-nums">
              ↑ {fmtBytes(usage.up)} · ↓ {fmtBytes(usage.down)}
              {plan?.quotaBytes ? ` · quota ${fmtBytes(plan.quotaBytes)} (${pct.toFixed(1)}%)` : " · unlimited quota"}
            </p>
            {plan?.quotaBytes ? (
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-100">
                <div
                  className={`h-full transition-all ${
                    pct >= 100 ? "bg-rose-500" : pct > 80 ? "bg-amber-500" : "bg-indigo-600"
                  }`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            ) : null}
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-500">Accounting quality:</span>
              <Badge variant={statusTone(usage.quality)}>{usage.quality}</Badge>
              <Badge variant="outline">{plan?.enforcement} enforcement</Badge>
            </div>
            {usage.gaps.length > 0 && (
              <ul className="mt-3 space-y-1 rounded-lg bg-amber-50 p-3 text-xs text-amber-900">
                {usage.gaps.slice(0, 5).map((g) => (
                  <li key={g.id}>
                    <strong>{g.kind}</strong> · {g.note} · {ago(g.detectedAt)}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Profile & Plan Settings</CardTitle>
            <CardDescription>Update name, plan assignment, or account status.</CardDescription>
          </CardHeader>
          <CardContent>
            {canEdit ? (
              <ActionForm action={updateUserAction} submitLabel="Save Profile Changes">
                <input type="hidden" name="userId" value={u.id} />
                <input type="hidden" name="version" value={u.version} />
                <div className="grid gap-3 md:grid-cols-2">
                  <Field label="Name">
                    <Input name="name" defaultValue={u.name} required />
                  </Field>
                  <Field label="Email (optional)">
                    <Input name="email" type="email" defaultValue={u.email ?? ""} />
                  </Field>
                  <Field label="Plan">
                    <Select name="planId" defaultValue={u.planId}>
                      {allPlans.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.enforcement})
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field label="Expiration Date (optional)">
                    <Input
                      name="expiresAt"
                      type="date"
                      defaultValue={u.expiresAt?.toISOString().slice(0, 10) ?? ""}
                      className="font-mono"
                    />
                  </Field>
                </div>
              </ActionForm>
            ) : (
              <p className="text-sm text-slate-600">
                Plan: {plan?.name}. Expires {fmtDate(u.expiresAt)}.
              </p>
            )}
            {canEdit && (
              <div className="mt-4 flex flex-wrap gap-3 border-t border-slate-100 pt-4">
                {u.status === "active" ? (
                  <ActionForm action={userStatusAction} submitLabel="Suspend User" variant="destructive" size="sm">
                    <input type="hidden" name="userId" value={u.id} />
                    <input type="hidden" name="status" value="suspended" />
                  </ActionForm>
                ) : (
                  <ActionForm action={userStatusAction} submitLabel="Resume User" variant="outline" size="sm">
                    <input type="hidden" name="userId" value={u.id} />
                    <input type="hidden" name="status" value="active" />
                  </ActionForm>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 3: Per-Endpoint Credentials */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Per-Endpoint Credentials</CardTitle>
          <CardDescription>
            Unique UUID/credential per endpoint, encrypted at rest with AES-256-GCM.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Endpoint</TableHead>
                  <TableHead>Hosting Node</TableHead>
                  <TableHead>Attribution Key</TableHead>
                  <TableHead>Provisioned</TableHead>
                  <TableHead>Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {principals.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5}>
                      <EmptyState
                        title="No credentials provisioned"
                        description="No endpoint credentials exist for this user yet."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  principals.map(({ p, ib, node }) => (
                    <TableRow key={p.id}>
                      <TableCell className="font-mono text-xs font-semibold text-slate-900">{ib.name}</TableCell>
                      <TableCell>
                        <Link href={`/nodes/${node.id}`} className="font-mono text-xs text-indigo-600 hover:underline">
                          {node.name}
                        </Link>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{p.attributionKey}</TableCell>
                      <TableCell className="text-xs text-slate-500 tabular-nums">{ago(p.createdAt)}</TableCell>
                      <TableCell>
                        {canEdit && (
                          <ActionForm action={rotateEndpointAction} submitLabel="Rotate Key" variant="outline" size="sm">
                            <input type="hidden" name="principalId" value={p.id} />
                          </ActionForm>
                        )}
                      </TableCell>
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
