import Link from "next/link";
import { CheckCircle2, FileSignature, Lock, ShieldAlert, ShieldCheck, UserCheck } from "lucide-react";
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
  switchOperatorIdentityAction,
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
        title="Dual-Operator Signed Publication"
        subtitle="Two-stage Ed25519 desired-state governance. Staging a revision creates an immutable canonical JCS envelope; an independent second owner must confirm the exact SHA-256 digest before atomic publication."
      />

      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Awaiting 2nd-Owner Review"
          value={awaitingReview.length}
          hint="Requires distinct owner SHA-256 sign-off"
        />
        <Stat
          label="Approved · Ready to Publish"
          value={readyToPublish.length}
          hint="Bounded <= 300s one-time publication window"
        />
        <Stat
          label="Published & Consumed"
          value={publishedCount}
          hint={`Authorized Control-Plane Epoch #${epoch}`}
        />
        <Stat
          label="Active Session Identity"
          value={me.email.split("@")[0]}
          hint={`Role: ${me.role.toUpperCase()} (ID #${me.id})`}
        />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <FileSignature className="h-4 w-4 text-indigo-600" />
              Stage Signed Desired-State Proposal (Stage 1)
            </CardTitle>
            <CardDescription>
              Compiles the node&apos;s current enabled inbounds and egress guard into a canonical{" "}
              <code className="font-mono text-xs">ed25519-jcs-v1</code> envelope signed by the control-plane key.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {me.role === "owner" ? (
              <ActionForm
                action={createProposalAction}
                submitLabel="Sign & Stage Proposal"
                className="grid grid-cols-1 gap-4 sm:grid-cols-3"
              >
                <Field label="Target Node">
                  <Select name="nodeId" required defaultValue={allNodes[0]?.id ?? 1}>
                    {allNodes.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name} (head seq #{n.structuralSeq} → next #{n.structuralSeq + 1})
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="Proposal Lifetime (TTL)" hint="Bounded 60s–600s per contract">
                  <Select name="ttlSeconds" defaultValue="300">
                    <option value="180">180 seconds (3 min)</option>
                    <option value="300">300 seconds (5 min)</option>
                    <option value="600">600 seconds (10 min max)</option>
                  </Select>
                </Field>
                <Field label="Change Rationale / Ticket" className="sm:col-span-3">
                  <Input
                    name="note"
                    required
                    defaultValue="Rotate Reality shortId and publish verified listener manifest"
                    placeholder="Describe why this desired-state revision is being staged"
                  />
                </Field>
              </ActionForm>
            ) : (
              <p className="text-sm text-slate-600">
                Staging a desired-state publication proposal requires the <strong>owner</strong> role. Use the operator
                switcher in the sidebar to switch to <code className="font-mono text-xs">owner@omnipanel.internal</code>.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-indigo-600" />
              Two-Person Rule Invariants
            </CardTitle>
            <CardDescription>
              Enforced by <code className="font-mono text-xs">desired-approvals</code> contract
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5 text-xs text-slate-600">
            <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50 p-2.5">
              <Lock className="h-4 w-4 text-indigo-600 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-slate-900">1. Distinct Owner Separation</p>
                <p className="mt-0.5">
                  <code className="font-mono">proposerAdminId !== approverAdminId</code>. Self-approval is deterministically refused.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50 p-2.5">
              <UserCheck className="h-4 w-4 text-indigo-600 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-slate-900">2. SHA-256 Envelope Confirmation</p>
                <p className="mt-0.5">
                  Reviewer must confirm the exact 64-character hex digest of the Ed25519-signed envelope.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2 rounded-lg border border-slate-200 bg-slate-50 p-2.5">
              <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-slate-900">3. One-Time Monotonic Consumption</p>
                <p className="mt-0.5">
                  Publication verifies <code className="font-mono">seq === head + 1</code> and marks the approval consumed to prevent replay.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Signed Desired-State Proposals & Approval Decisions</CardTitle>
          <CardDescription>
            Review canonical envelopes, verify Ed25519 signatures and SHA-256 digests, and execute second-owner approvals.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {proposals.length === 0 ? (
            <EmptyState
              title="No desired-state proposals staged"
              description="Stage a signed proposal above to begin a dual-operator publication ceremony."
            />
          ) : (
            proposals.map((p) => {
              const isPublished = !!p.decision?.consumedAt;
              const isApproved = !!p.decision && !p.decision.consumedAt;
              const isPending = !p.decision;
              const isProposerSelf = me.id === p.proposerAdminId;

              const stateLabel = isPublished
                ? "published"
                : isApproved
                  ? "approved"
                  : "proposed";

              return (
                <div
                  key={p.proposalId}
                  className="rounded-xl border border-slate-200 bg-white p-4 sm:p-5 transition-colors hover:border-slate-300"
                >
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-semibold text-slate-900">{p.proposalId}</span>
                        <Badge variant={statusTone(stateLabel)}>{stateLabel.toUpperCase()}</Badge>
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
                        Proposed by <span className="font-mono font-medium text-slate-800">{p.proposerEmail}</span>{" "}
                        ({ago(new Date(p.createdAt))})
                      </p>
                      <p className="mt-0.5">Expires: {new Date(p.expiresAt).toISOString().slice(0, 19).replace("T", " ")} UTC</p>
                    </div>
                  </div>

                  <div className="mt-3 grid grid-cols-1 gap-3 rounded-lg border border-slate-200 bg-slate-50/80 p-3 text-xs sm:grid-cols-2">
                    <div>
                      <span className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Envelope SHA-256 Digest (Confirmation Target)
                      </span>
                      <code className="mt-0.5 block break-all font-mono text-xs font-medium text-slate-900 select-all">
                        {p.envelopeSha256}
                      </code>
                    </div>
                    <div>
                      <span className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                        Governance Status
                      </span>
                      {isPublished && p.decision ? (
                        <p className="mt-0.5 text-emerald-800 font-medium">
                          Approved by <span className="font-mono">{p.decision.approverEmail}</span> · Published as Revision #
                          {p.decision.publishedRevisionSeq ?? p.structuralSequence} ({ago(new Date(p.decision.consumedAt!))})
                        </p>
                      ) : isApproved && p.decision ? (
                        <p className="mt-0.5 text-indigo-800 font-medium">
                          Dual-approved by <span className="font-mono">{p.decision.approverEmail}</span> ({ago(new Date(p.decision.approvedAt))}) · Window open until{" "}
                          {new Date(p.decision.approvalExpiresAt).toISOString().slice(11, 19)} UTC
                        </p>
                      ) : (
                        <p className="mt-0.5 text-amber-800 font-medium">
                          Staged by <span className="font-mono">{p.proposerEmail}</span> · Waiting for independent second owner review
                        </p>
                      )}
                    </div>
                  </div>

                  {isPending && (
                    <div className="mt-4 border-t border-slate-100 pt-4">
                      {isProposerSelf && (
                        <div className="mb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 rounded-lg border border-amber-200 bg-amber-50/70 px-3 py-2 text-xs text-amber-900">
                          <div className="flex items-center gap-2">
                            <ShieldAlert className="h-4 w-4 text-amber-700 shrink-0" />
                            <span>
                              You (<code className="font-mono font-semibold">{me.email}</code>) staged this proposal. The two-person rule requires a distinct second owner (<code className="font-mono font-semibold">reviewer@omnipanel.internal</code>) to approve.
                            </span>
                          </div>
                          <form action={switchOperatorIdentityAction} className="shrink-0">
                            <input type="hidden" name="adminId" value={2} />
                            <button
                              type="submit"
                              className="inline-flex items-center gap-1.5 rounded-md border border-amber-300 bg-white px-2.5 py-1 text-xs font-semibold text-amber-900 hover:bg-amber-100"
                            >
                              Switch to reviewer@omnipanel.internal
                            </button>
                          </form>
                        </div>
                      )}

                      <ActionForm
                        action={approveProposalAction}
                        submitLabel={
                          isProposerSelf
                            ? "Attempt Self-Approval (Test Fail-Closed Rejection)"
                            : "Confirm SHA-256 & Grant 2nd-Owner Approval"
                        }
                        className="flex flex-col sm:flex-row sm:items-end gap-3"
                      >
                        <input type="hidden" name="proposalId" value={p.proposalId} />
                        <Field
                          label="Confirm Reviewed Envelope SHA-256 Digest (64 hex chars)"
                          className="flex-1"
                        >
                          <Input
                            name="expectedSha256"
                            required
                            defaultValue={p.envelopeSha256}
                            className="font-mono text-xs"
                          />
                        </Field>
                      </ActionForm>
                    </div>
                  )}

                  {isApproved && (
                    <div className="mt-4 border-t border-slate-100 pt-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      <p className="text-xs text-slate-600">
                        Second-owner review complete (<code className="font-mono">{p.decision?.approverEmail}</code>). Execute one-time atomic publication to advance{" "}
                        <strong>{p.nodeName}</strong> to revision <strong>#{p.structuralSequence}</strong>.
                      </p>
                      <ActionForm
                        action={publishProposalAction}
                        submitLabel={`Publish Revision #${p.structuralSequence} Atomically`}
                      >
                        <input type="hidden" name="proposalId" value={p.proposalId} />
                      </ActionForm>
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
