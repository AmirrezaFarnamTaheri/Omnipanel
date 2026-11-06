import Link from "next/link";
import { notFound } from "next/navigation";
import { and, desc, eq } from "drizzle-orm";
import { Activity, ArrowLeft, CheckCircle2, Globe, Lock, ShieldCheck, Wifi } from "lucide-react";
import { db } from "@/db";
import {
  endpointPrincipals,
  healthObservations,
  inbounds,
  nodes,
  plans,
  subscriptionTokens,
  users,
} from "@/db/schema";
import { decryptSecret, sha256 } from "@/lib/crypto";
import { buildIR, compile, type AccessPath, type IR } from "@/lib/subscription";
import {
  compileClientBalancerDocument,
  computeAdaptiveBalancerParameters,
} from "@/lib/subscription-balancer";
import { subscriptionUserinfo } from "@/lib/subscription-profile";
import { getSubscriptionProfileConfig } from "@/lib/governance-store";
import { computeSubscriptionEtag } from "@/lib/enterprise-hardening";
import { usageForUser } from "@/lib/users";
import { CLIENT_REGISTRY } from "@/lib/capabilities";
import { ago, fmtBytes, fmtDate } from "@/lib/format";
import { SubscriptionInspector, type CompiledFormatPreview } from "@/components/SubscriptionInspector";
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
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

export default async function SubscriberSelfServicePortalPage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;

  // Resolve subscriber either by token prefix (e.g. omni_xxxx) or subscriber numeric ID for self-service preview
  let userRow = null;
  let tokenRow = null;

  if (/^\d+$/.test(token)) {
    const uid = Number(token);
    const [u] = await db.select().from(users).where(eq(users.id, uid));
    userRow = u ?? null;
    if (userRow) {
      const toks = await db
        .select()
        .from(subscriptionTokens)
        .where(eq(subscriptionTokens.userId, userRow.id));
      tokenRow = toks.filter((t) => !t.revokedAt).slice(-1)[0] ?? null;
    }
  } else {
    const cleanPrefix = token.slice(0, 9);
    const allTokens = await db.select().from(subscriptionTokens);
    tokenRow =
      allTokens.find((t) => !t.revokedAt && (t.prefix === cleanPrefix || t.tokenHash === sha256(token))) ??
      null;
    if (tokenRow) {
      const [u] = await db.select().from(users).where(eq(users.id, tokenRow.userId));
      userRow = u ?? null;
    }
  }

  if (!userRow) notFound();

  const allPlans = await db.select().from(plans);
  const plan = allPlans.find((p) => p.id === userRow.planId);
  const usage = await usageForUser(db, userRow.id);
  const profileCfg = await getSubscriptionProfileConfig();
  const ir = await buildIR(userRow.id);

  const principals = await db
    .select({ p: endpointPrincipals, ib: inbounds, node: nodes })
    .from(endpointPrincipals)
    .innerJoin(inbounds, eq(inbounds.id, endpointPrincipals.inboundId))
    .innerJoin(nodes, eq(nodes.id, inbounds.nodeId))
    .where(and(eq(endpointPrincipals.userId, userRow.id), eq(endpointPrincipals.state, "active")))
    .orderBy(endpointPrincipals.id);

  const recentObs = await db
    .select()
    .from(healthObservations)
    .orderBy(desc(healthObservations.id))
    .limit(20);

  const adaptiveTuning = computeAdaptiveBalancerParameters(
    recentObs.map((o) => o.latencyMs).filter((ms): ms is number => ms != null),
  );

  const provisionedPaths: AccessPath[] = principals
    .filter(({ ib, node }) => ib.enabled && node.status === "active" && ib.protocol === "vless-reality-vision")
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
    user: { id: userRow.id, name: userRow.name, status: userRow.status },
    paths: ir.paths.length > 0 ? ir.paths : provisionedPaths,
    excluded: ir.excluded,
    diagnostics: ir.diagnostics,
    quotaBytes: plan?.quotaBytes ?? null,
    expiresAt: userRow.expiresAt,
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

  const userinfoHeader = subscriptionUserinfo({
    uploadBytes: usage.up,
    downloadBytes: usage.down,
    quotaBytes: plan?.quotaBytes ?? null,
    expiresAt: userRow.expiresAt,
    expiryPresentation: profileCfg.expiryPresentation,
  });

  const formatPreviews: CompiledFormatPreview[] = [
    ...(await Promise.all(
      CLIENT_REGISTRY.map(async (c) => {
        const formatIr = await buildIR(userRow.id, c.format);
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
      label: "Adaptive Client Balancer",
      contentType: "application/json",
      admittedCount: balancerDoc.memberTags.length,
      excludedReasons: [],
      compiledBody: JSON.stringify(balancerDoc, null, 2),
      sha256: balancerDoc.digest,
    },
  ];

  const etag = computeSubscriptionEtag({
    format: "singbox",
    compiledBody: formatPreviews[0]?.compiledBody ?? "",
    userinfoHeader,
    updateIntervalHours: profileCfg.updateIntervalHours,
  });

  const headersPreview: Record<string, string> = {
    etag,
    "subscription-userinfo": userinfoHeader,
    "profile-update-interval": String(profileCfg.updateIntervalHours),
  };

  const pct = plan?.quotaBytes ? Math.min(100, (usage.total / plan.quotaBytes) * 100) : 0;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3.5 sm:px-6">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-xs font-bold text-white">
              OP
            </div>
            <div>
              <span className="block text-sm font-semibold text-slate-900">
                {profileCfg.profileTitlePrefix} · Subscriber Self-Service Portal
              </span>
              <span className="block font-mono text-[11px] text-slate-500">
                Zero-Knowledge Token-Scoped View · Conditional ETag Enabled
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={statusTone(userRow.status)}>{userRow.status}</Badge>
            <Link
              href={`/users/${userRow.id}`}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Operator View
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl space-y-6 p-4 sm:p-6">
        {profileCfg.announce && (
          <div className="flex items-center gap-2.5 rounded-xl border border-indigo-200 bg-indigo-50/80 px-4 py-3 text-xs text-indigo-950">
            <ShieldCheck className="h-4 w-4 text-indigo-600 shrink-0" />
            <span>{profileCfg.announce}</span>
          </div>
        )}

        <div className="grid gap-6 md:grid-cols-3">
          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle className="text-base">{userRow.name}</CardTitle>
              <CardDescription>
                Plan: <strong>{plan?.name ?? "Standard"}</strong> ({plan?.enforcement ?? "metered"}) · Expires{" "}
                {fmtDate(userRow.expiresAt)}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold tracking-tight text-slate-900 tabular-nums">
                  {fmtBytes(usage.total)}
                </span>
                <span className="font-mono text-xs text-slate-600 tabular-nums">
                  ↑ {fmtBytes(usage.up)} · ↓ {fmtBytes(usage.down)}
                </span>
              </div>
              {plan?.quotaBytes ? (
                <>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-100">
                    <div
                      className={`h-full ${pct >= 100 ? "bg-rose-500" : pct > 80 ? "bg-amber-500" : "bg-indigo-600"}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <p className="text-xs text-slate-500 tabular-nums">
                    {pct.toFixed(1)}% of {fmtBytes(plan.quotaBytes)} period allowance used · Accounting quality:{" "}
                    <strong>{usage.quality}</strong>
                  </p>
                </>
              ) : (
                <p className="text-xs text-slate-500">
                  Unmetered research plan · Accounting quality: <strong>{usage.quality}</strong>
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Activity className="h-4 w-4 text-indigo-600" />
                Adaptive Balancer & ETag
              </CardTitle>
              <CardDescription>Battery-aware client probing & HTTP 304 caching</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-xs font-mono">
              <div className="flex justify-between">
                <span className="font-sans text-slate-500">Tuning Profile:</span>
                <Badge variant="info">{adaptiveTuning.tuningProfile}</Badge>
              </div>
              <div className="flex justify-between tabular-nums">
                <span className="font-sans text-slate-500">Probe Interval:</span>
                <span>{adaptiveTuning.intervalSeconds}s</span>
              </div>
              <div className="flex justify-between tabular-nums">
                <span className="font-sans text-slate-500">Switch Tolerance:</span>
                <span>{adaptiveTuning.toleranceMs} ms</span>
              </div>
              <div className="flex justify-between tabular-nums">
                <span className="font-sans text-slate-500">Observed p50 / p95:</span>
                <span>
                  {adaptiveTuning.p50LatencyMs}ms / {adaptiveTuning.p95LatencyMs}ms
                </span>
              </div>
              <div className="pt-1 border-t border-slate-100 truncate text-[11px] text-slate-600" title={etag}>
                ETag: {etag}
              </div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Globe className="h-4 w-4 text-indigo-600" />
              Active Regional Access Endpoints
            </CardTitle>
            <CardDescription>
              Only active, healthy endpoints assigned to your subscription are shown. Raw node management addresses remain isolated.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TableWrapper>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Endpoint Tag</TableHead>
                    <TableHead>Region / Provider</TableHead>
                    <TableHead>Protocol & Transport</TableHead>
                    <TableHead>SNI / TLS Model</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {principals.map(({ p, ib, node }) => (
                    <TableRow key={p.id}>
                      <TableCell className="font-mono text-xs font-semibold text-slate-900">
                        {node.name}-{ib.name}
                      </TableCell>
                      <TableCell className="text-xs">
                        {node.region || "Global"} ({node.provider})
                      </TableCell>
                      <TableCell className="font-mono text-xs tabular-nums">
                        {ib.protocol} ({ib.transport.toUpperCase()} :{ib.port})
                      </TableCell>
                      <TableCell className="font-mono text-xs">{ib.sni}</TableCell>
                      <TableCell>
                        <Badge variant="success">
                          <Wifi className="mr-1 h-3 w-3" />
                          {p.state}
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
            <CardTitle className="flex items-center gap-2 text-base">
              <Lock className="h-4 w-4 text-indigo-600" />
              Client Configuration & Subscription Inspector
            </CardTitle>
            <CardDescription>
              Token prefix: <code className="font-mono font-semibold">{tokenRow?.prefix ?? "omni_preview"}…</code> · Last synced{" "}
              {tokenRow?.lastUsedAt ? ago(tokenRow.lastUsedAt) : "recently"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <SubscriptionInspector formats={formatPreviews} headersPreview={headersPreview} />
          </CardContent>
        </Card>
      </main>
    </div>
  );
}
