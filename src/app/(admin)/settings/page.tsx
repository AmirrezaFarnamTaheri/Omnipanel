import { eq } from "drizzle-orm";
import { db } from "@/db";
import { admins } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { getSigner } from "@/lib/crypto";
import { getEpoch } from "@/lib/revisions";
import { declareEpochAction, purgeRetentionAction } from "@/app/actions/system";
import { totpBeginAction, totpConfirmAction } from "@/app/actions/auth";
import { ActionForm } from "@/components/ActionForm";
import { Badge, Card, Field, inputCls, PageHeader } from "@/components/ui";

export default async function SettingsPage() {
  const me = await requirePage("viewer");
  const [a] = await db.select().from(admins).where(eq(admins.id, me.id));
  const epoch = await getEpoch();
  const signer = await getSigner();
  return (
    <>
      <PageHeader title="Settings & recovery" subtitle="Operator security, manifest signing identity, recovery epochs and data retention." />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Multi-factor authentication">
          <p className="mb-3 text-sm">
            TOTP: <Badge tone={a.totpEnabled ? "green" : "amber"}>{a.totpEnabled ? "enabled" : "not enabled"}</Badge>
          </p>
          <ActionForm action={totpBeginAction} submit={a.totpEnabled ? "Re-enroll authenticator" : "Begin enrollment"} variant="ghost" />
          <ActionForm action={totpConfirmAction} submit="Confirm code" className="mt-4 border-t border-slate-100 pt-4">
            <Field label="Code from your authenticator app"><input name="code" inputMode="numeric" className={inputCls} placeholder="123456" /></Field>
          </ActionForm>
        </Card>

        <Card title="Desired-state signing identity">
          <p className="text-sm text-slate-600">Agents verify every structural and membership manifest against this Ed25519 key, independently of the TLS server identity.</p>
          <p className="mt-2 text-sm">Key id: <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">{signer.keyId}</code></p>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-50 p-2 text-xs text-slate-700">{signer.publicKeyPem}</pre>
        </Card>

        {me.role === "owner" && (
          <Card title={`Control-plane epoch: ${epoch}`}>
            <p className="mb-3 text-sm text-slate-600">
              After a point-in-time database restore, authorize a new epoch. Every node receives a freshly signed revision and a membership
              snapshot, so no agent accepts a conflicting lower revision as current.
            </p>
            <ActionForm action={declareEpochAction} submit="Declare recovery epoch" variant="danger">
              <div className="grid gap-3">
                <Field label="Reason"><input name="reason" required minLength={10} placeholder="PITR to 2026-11-03 09:10 UTC after storage fault" className={inputCls} /></Field>
                <Field label="Confirm password (step-up)"><input name="password" type="password" required className={inputCls} /></Field>
                {a.totpEnabled && <Field label="Authenticator code"><input name="code" inputMode="numeric" className={inputCls} /></Field>}
              </div>
            </ActionForm>
          </Card>
        )}

        {me.role === "owner" && (
          <Card title="Data retention">
            <ul className="mb-3 list-disc space-y-1 pl-5 text-sm text-slate-600">
              <li>Raw authenticated usage events: 30 days</li>
              <li>Hourly usage aggregates: 180 days</li>
              <li>Health samples: 7 days</li>
              <li>Audit records: retained; destination-level browsing data is never collected</li>
            </ul>
            <ActionForm action={purgeRetentionAction} submit="Apply retention now" variant="ghost" />
          </Card>
        )}
      </div>
    </>
  );
}
