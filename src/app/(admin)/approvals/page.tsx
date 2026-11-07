import Link from "next/link";
import { CheckCircle2, FileSignature } from "lucide-react";
import { db } from "@/db";
import { nodes } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { ago } from "@/lib/format";
import { listDesiredStateProposals } from "@/lib/governance-store";
import { getEpoch } from "@/lib/revisions";
import {
  approveProposalAction,
  createProposalAction,
  publishProposalAction,
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
} from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function ApprovalsPage() {
  const me = await requirePage("viewer");
  const epoch = await getEpoch();
  const allNodes = await db.select().from(nodes).orderBy(nodes.id);
  const proposals = await listDesiredStateProposals();

  const awaitingReview = proposals.filter((p) => !p.decision);
  const readyToPublish = proposals.filter((p) => p.decision && p.decision.consumedAt === null);
  const publishedCount = proposals.filter((p) => p.decision && p.decision.consumedAt !== null).length;

  return (
    <>
      <PageHeader
        title="Revisions & Signed Snapshots"
        subtitle="Endpoint changes are staged until a distinct owner reviews the signed proposal. Publication is a separate, one-time action."
      />

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat
          label="Staged Snapshots"
          value={awaitingReview.length}
          hint="Requires a different owner to review"
        />
        <Stat
          label="Approved · Ready"
          value={readyToPublish.length}
          hint="Bounded one-time publication window"
        />
        <Stat
          label="Published Revisions"
          value={publishedCount}
          hint={`Control-Plane Epoch #${epoch}`}
        />
      </div>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <FileSignature className="h-4 w-4 text-indigo-600" />
            Create Signed Desired-State Snapshot
          </CardTitle>
          <CardDescription>
            Compiles the selected node&apos;s current enabled endpoints and egress rules into a canonical{" "}
            <code className="font-mono text-xs">ed25519-jcs-v1</code> envelope.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {me.role === "owner" ? (
            <ActionForm
              action={createProposalAction}
              submitLabel="Create Signed Snapshot"
              className="grid grid-cols-1 gap-4 sm:grid-cols-3"
            >
              <Field label="Target Node">
                <Select name="nodeId" required defaultValue={allNodes[0]?.id ?? 1}>
                  {allNodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name} (seq #{n.structuralSeq} → next #{n.structuralSeq + 1})
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Snapshot Window">
                <Select name="ttlSeconds" defaultValue="300">
                  <option value="180">3 minutes</option>
                  <option value="300">5 minutes</option>
                  <option value="600">10 minutes</option>
                </Select>
              </Field>
              <Field label="Note (optional)">
                <Input
                  name="note"
                  defaultValue="Publish verified listener snapshot"
                  placeholder="Optional note"
                />
              </Field>
            </ActionForm>
          ) : (
            <p className="text-sm text-slate-600">
              Creating signed snapshots requires an owner account.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Signed Snapshots & Revision History</CardTitle>
          <CardDescription>
            Publish staged snapshots in one click or inspect the canonical Ed25519 envelope.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {proposals.length === 0 ? (
            <EmptyState
              title="No signed snapshots staged"
              description="Create a signed snapshot above or add endpoints directly on any node."
            />
          ) : (
            proposals.map((p) => {
              const isPublished = !!p.decision?.consumedAt;
              const isApproved = !!p.decision && !p.decision.consumedAt;
              const isPending = !p.decision;

              const stateLabel = isPublished
                ? "published"
                : isApproved
                  ? "approved"
                  : "staged";

              return (
                <div
                  key={p.proposalId}
                  className="rounded-xl border border-slate-200 bg-white p-4 sm:p-5 transition-colors hover:border-slate-300"
                >
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-semibold text-slate-900">{p.proposalId}</span>
                        <Badge variant={statusTone(isPending ? "proposed" : stateLabel)}>{stateLabel.toUpperCase()}</Badge>
                        <Link
                          href={`/nodes/${p.nodeId}`}
                          className="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 font-mono text-xs font-medium text-indigo-600 hover:bg-indigo-50"
                        >
                          {p.nodeName} · seq #{p.structuralSequence}
                        </Link>
                        <Badge variant="outline" className="font-mono text-xs tabular-nums">
                          Epoch #{p.controlPlaneEpoch}
                        </Badge>
                      </div>
                      <p className="text-sm text-slate-700">{p.note}</p>
                    </div>

                    <div className="text-xs text-slate-500 sm:text-right tabular-nums shrink-0">
                      <p>
                        Created by <span className="font-mono font-medium text-slate-800">{p.proposerEmail}</span>{" "}
                        ({ago(new Date(p.createdAt))})
                      </p>
                      <p className="mt-0.5 font-mono text-[11px] text-slate-400">
                        sha256:{p.envelopeSha256.slice(0, 20)}…
                      </p>
                    </div>
                  </div>

                  {isPending && me.role === "owner" && me.id !== p.proposerAdminId && (
                    <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
                      <p className="text-xs text-slate-600">
                        Review signed revision <strong>#{p.structuralSequence}</strong> to{" "}
                        <strong>{p.nodeName}</strong>.
                      </p>
                      <div className="flex flex-wrap items-center gap-2">
                        <ActionForm
                          action={approveProposalAction}
                          submitLabel={`Approve Revision #${p.structuralSequence}`}
                          size="sm"
                        >
                          <input type="hidden" name="proposalId" value={p.proposalId} />
                          <input type="hidden" name="expectedSha256" value={p.envelopeSha256} />
                          <Field label="Current password">
                            <Input type="password" name="password" autoComplete="current-password" required />
                          </Field>
                          <Field label="Authenticator code (if enrolled)">
                            <Input name="code" inputMode="numeric" pattern="[0-9]{6}" placeholder="123456" />
                          </Field>
                          <input type="hidden" name="autoPublish" value="1" />
                        </ActionForm>
                      </div>
                    </div>
                  )}

                  {isApproved && me.role === "owner" && (
                    <div className="mt-4 border-t border-slate-100 pt-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      <p className="text-xs text-slate-600">
                        Approved by <code className="font-mono">{p.decision?.approverEmail}</code>. Publish to advance{" "}
                        <strong>{p.nodeName}</strong> to revision <strong>#{p.structuralSequence}</strong>.
                      </p>
                      <ActionForm
                        action={publishProposalAction}
                        submitLabel={`Publish Revision #${p.structuralSequence}`}
                        size="sm"
                      >
                        <input type="hidden" name="proposalId" value={p.proposalId} />
                        <Field label="Current password">
                          <Input type="password" name="password" autoComplete="current-password" required />
                        </Field>
                        <Field label="Authenticator code (if enrolled)">
                          <Input name="code" inputMode="numeric" pattern="[0-9]{6}" placeholder="123456" />
                        </Field>
                      </ActionForm>
                    </div>
                  )}

                  {isPublished && p.decision && (
                    <div className="mt-3 flex items-center gap-2 text-xs text-emerald-700">
                      <CheckCircle2 className="h-4 w-4 shrink-0" />
                      <span>
                        Published as Revision #{p.decision.publishedRevisionSeq ?? p.structuralSequence} ({ago(new Date(p.decision.consumedAt!))})
                      </span>
                    </div>
                  )}

                  <details className="mt-3">
                    <summary className="cursor-pointer text-xs font-medium text-indigo-600 hover:text-indigo-700">
                      Inspect signed canonical JCS envelope (ed25519-jcs-v1)
                    </summary>
                    <pre className="mt-2 max-h-56 overflow-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100">
                      {JSON.stringify(JSON.parse(p.envelopeJson), null, 2)}
                    </pre>
                  </details>
                </div>
              );
            })
          )}
        </CardContent>
      </Card>
    </>
  );
}
