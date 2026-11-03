import { notFound } from "next/navigation";
import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { endpointPrincipals, inbounds, nodes, plans, subscriptionTokens, users } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { buildIR } from "@/lib/subscription";
import { usageForUser } from "@/lib/users";
import { CLIENT_REGISTRY } from "@/lib/capabilities";
import { ago, fmtBytes, fmtDate } from "@/lib/format";
import { rotateEndpointAction, rotateTokenAction, updateUserAction, userStatusAction } from "@/app/actions/people";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader, statusTone, Table, Td } from "@/components/ui";

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
    .limit(50)
    .then((r) => r.filter((t) => !t.revokedAt).slice(-1));
  const pct = plan?.quotaBytes ? Math.min(100, (usage.total / plan.quotaBytes) * 100) : 0;

  return (
    <>
      <PageHeader
        title={u.name}
        subtitle={`${u.email ?? "no email"} · version ${u.version} · created ${fmtDate(u.createdAt)}`}
        actions={<Badge tone={statusTone(u.status)}>{u.status}{u.suspendReason ? ` (${u.suspendReason})` : ""}</Badge>}
      />

      <div className="mb-6 grid gap-6 lg:grid-cols-2">
        <Card title="Usage this period">
          <p className="text-3xl font-semibold">{fmtBytes(usage.total)}</p>
          <p className="text-sm text-slate-600">
            ↑ {fmtBytes(usage.up)} · ↓ {fmtBytes(usage.down)}{plan?.quotaBytes ? ` · quota ${fmtBytes(plan.quotaBytes)}` : " · unlimited"}
          </p>
          {plan?.quotaBytes ? (
            <div className="mt-3 h-2 overflow-hidden rounded bg-slate-100">
              <div className={`h-full ${pct >= 100 ? "bg-rose-500" : pct > 80 ? "bg-amber-500" : "bg-indigo-500"}`} style={{ width: `${pct}%` }} />
            </div>
          ) : null}
          <div className="mt-3 flex items-center gap-2 text-sm">
            Accounting quality: <Badge tone={statusTone(usage.quality)}>{usage.quality}</Badge>
            <Badge tone={plan?.enforcement === "hard" ? "blue" : "slate"}>{plan?.enforcement} enforcement</Badge>
          </div>
          {usage.gaps.length > 0 && (
            <ul className="mt-3 space-y-1 rounded-lg bg-amber-50 p-3 text-xs text-amber-900">
              {usage.gaps.slice(0, 5).map((g) => (
                <li key={g.id}><strong>{g.kind}</strong> · {g.note} · {ago(g.detectedAt)}</li>
              ))}
              <li className="pt-1 text-amber-800">Unknown intervals are never converted into usage or charges.</li>
            </ul>
          )}
        </Card>

        <Card title="Profile & plan">
          {canEdit ? (
            <ActionForm action={updateUserAction} submit="Save changes">
              <input type="hidden" name="userId" value={u.id} />
              <input type="hidden" name="version" value={u.version} />
              <div className="grid gap-3 md:grid-cols-2">
                <Field label="Name"><input name="name" defaultValue={u.name} required className={inputCls} /></Field>
                <Field label="Email"><input name="email" type="email" defaultValue={u.email ?? ""} className={inputCls} /></Field>
                <Field label="Plan">
                  <select name="planId" defaultValue={u.planId} className={inputCls}>
                    {allPlans.map((p) => <option key={p.id} value={p.id}>{p.name} ({p.enforcement})</option>)}
                  </select>
                </Field>
                <Field label="Expires"><input name="expiresAt" type="date" defaultValue={u.expiresAt?.toISOString().slice(0, 10) ?? ""} className={inputCls} /></Field>
              </div>
              <p className="mt-2 text-xs text-slate-500">Saved with optimistic concurrency (version {u.version}); a concurrent edit is rejected rather than overwritten.</p>
            </ActionForm>
          ) : (
            <p className="text-sm text-slate-600">Plan: {plan?.name}. Expires {fmtDate(u.expiresAt)}.</p>
          )}
          {canEdit && (
            <div className="mt-4 flex flex-wrap gap-3 border-t border-slate-100 pt-4">
              {u.status === "active" ? (
                <ActionForm action={userStatusAction} submit="Suspend user" variant="danger">
                  <input type="hidden" name="userId" value={u.id} />
                  <input type="hidden" name="status" value="suspended" />
                </ActionForm>
              ) : (
                <ActionForm action={userStatusAction} submit="Resume user" variant="ghost">
                  <input type="hidden" name="userId" value={u.id} />
                  <input type="hidden" name="status" value="active" />
                </ActionForm>
              )}
            </div>
          )}
        </Card>
      </div>

      <Card title="Subscription" className="mb-6">
        <p className="text-sm text-slate-600">
          Active token: <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">{tok ? `${tok.prefix}…` : "none"}</code>{" "}
          {tok?.lastUsedAt ? `· last fetched ${ago(tok.lastUsedAt)}` : "· never fetched"}. Only a hash is stored, so the URL cannot be recovered; rotate to issue a new one.
        </p>
        <p className="mt-1 text-xs text-slate-500">Formats: {CLIENT_REGISTRY.map((c) => c.label).join(" · ")}. Responses are <code>private, no-store</code>.</p>
        {canEdit && (
          <ActionForm action={rotateTokenAction} submit="Rotate subscription URL" variant="ghost" className="mt-3">
            <input type="hidden" name="userId" value={u.id} />
          </ActionForm>
        )}
        <div className="mt-5">
          <h3 className="mb-2 text-sm font-semibold text-slate-800">Why each endpoint is included or excluded</h3>
          <ul className="space-y-1 text-sm">
            {ir.paths.map((p) => (
              <li key={p.inboundId} className="flex flex-wrap items-center gap-2">
                <Badge tone="green">included</Badge>
                <span className="font-medium">{p.tag}</span>
                <span className="text-slate-500">{p.protocol} · {p.transport.toUpperCase()} {p.port} · {p.tlsModel} · {p.route} · {p.enforceability}</span>
              </li>
            ))}
            {ir.excluded.map((e) => (
              <li key={e.inboundId} className="flex flex-wrap items-center gap-2">
                <Badge tone="amber">excluded</Badge>
                <span className="font-medium">{e.name}</span>
                <span className="text-slate-500">{e.reason}</span>
              </li>
            ))}
            {ir.paths.length + ir.excluded.length === 0 && <li className="text-slate-500">No endpoints exist yet.</li>}
          </ul>
          {u.status !== "active" && <p className="mt-2 text-sm text-amber-700">User is {u.status}: the subscription URL returns 403 with no credentials.</p>}
        </div>
      </Card>

      <Card title="Endpoint credentials">
        <Table head={["Endpoint", "Node", "Attribution key", "Created", ""]} empty={principals.length ? undefined : "No credentials provisioned."}>
          {principals.map(({ p, ib, node }) => (
            <tr key={p.id}>
              <Td className="font-medium">{ib.name}</Td>
              <Td>{node.name}</Td>
              <Td className="font-mono text-xs">{p.attributionKey}</Td>
              <Td className="text-xs">{ago(p.createdAt)}</Td>
              <Td>
                {canEdit && (
                  <ActionForm action={rotateEndpointAction} submit="Rotate" variant="ghost">
                    <input type="hidden" name="principalId" value={p.id} />
                  </ActionForm>
                )}
              </Td>
            </tr>
          ))}
        </Table>
        <p className="mt-3 text-xs text-slate-500">Credentials are unique per user and endpoint, encrypted at rest, and delivered only to the node that hosts the endpoint. They are never displayed.</p>
      </Card>
    </>
  );
}
