import { count, desc, ilike, or } from "drizzle-orm";
import { CheckCircle2, Search, ShieldAlert, ShieldCheck } from "lucide-react";
import { db } from "@/db";
import { auditLog } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { verifyAuditChain } from "@/lib/audit";
import { ago } from "@/lib/format";
import { AuditChainVerifier } from "@/components/AuditChainVerifier";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  Input,
  PageHeader,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TableWrapper,
} from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function AuditPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  await requirePage("viewer");
  const { q } = await searchParams;
  const filters: any[] = [];
  if (q) {
    filters.push(
      or(
        ilike(auditLog.action, `%${q}%`),
        ilike(auditLog.actor, `%${q}%`),
        ilike(auditLog.objectId, `%${q}%`),
      ),
    );
  }
  const rows = await db
    .select()
    .from(auditLog)
    .where(filters.length ? or(...filters) : undefined)
    .orderBy(desc(auditLog.id))
    .limit(100);
  const [{ total }] = await db.select({ total: count() }).from(auditLog);
  const chain = await verifyAuditChain();
  const headHash = rows[0]?.hash ?? "genesis";

  const serializedRows = rows.map((r) => ({
    id: r.id,
    tsIso: r.ts.toISOString(),
    actor: r.actor,
    action: r.action,
    objectType: r.objectType,
    objectId: r.objectId,
    detail: (r.detail ?? {}) as Record<string, unknown>,
    prevHash: r.prevHash,
    hash: r.hash,
  }));

  return (
    <>
      <PageHeader
        title="Cryptographic Audit Log"
        subtitle={`${total} record(s), SHA-256 hash-chained from genesis. Audit entries are append-only and never purged by retention policies.`}
      />

      <div
        className={`mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 rounded-xl border p-4 ${
          chain.ok
            ? "border-emerald-200 bg-emerald-50/70 text-emerald-950"
            : "border-rose-200 bg-rose-50 text-rose-950"
        }`}
      >
        <div className="flex items-start gap-3">
          {chain.ok ? (
            <ShieldCheck className="h-5 w-5 text-emerald-600 shrink-0 mt-0.5" />
          ) : (
            <ShieldAlert className="h-5 w-5 text-rose-600 shrink-0 mt-0.5" />
          )}
          <div className="text-xs space-y-0.5">
            <p className="text-sm font-semibold">
              {chain.ok
                ? `Genesis Hash-Chain Verified (${chain.count} contiguous records)`
                : `Hash-Chain Integrity Violation at Record #${chain.brokenAt}`}
            </p>
            <p className="font-mono text-slate-600 break-all">
              Head SHA-256: <span className="font-semibold text-slate-900">{headHash}</span>
            </p>
          </div>
        </div>
        <Badge variant={chain.ok ? "success" : "error"} className="shrink-0 self-start sm:self-center">
          {chain.ok ? "CHAIN INTACT" : "TAMPER DETECTED"}
        </Badge>
      </div>

      <AuditChainVerifier
        rows={serializedRows}
        totalCount={total}
        serverVerified={chain.ok}
        headHash={headHash}
      />

      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <CardTitle className="text-base">Committed Events</CardTitle>
              <CardDescription>
                Showing {rows.length} of {total} record(s)
              </CardDescription>
            </div>
            <form method="GET" className="flex items-center gap-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-slate-400" />
                <Input
                  name="q"
                  defaultValue={q ?? ""}
                  placeholder="Filter actor, action, object…"
                  className="h-9 pl-8 w-64 text-xs"
                />
              </div>
              <Button type="submit" variant="outline" size="sm">
                Filter
              </Button>
            </form>
          </div>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">Seq</TableHead>
                  <TableHead className="w-28">Time</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Target Object</TableHead>
                  <TableHead>Detail</TableHead>
                  <TableHead className="w-44">Prev → Record Hash</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7}>
                      <EmptyState
                        title="No matching audit records"
                        description="Audit entries appear here as platform actions are committed."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  rows.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs font-semibold text-slate-700 tabular-nums">
                        #{r.id}
                      </TableCell>
                      <TableCell className="text-xs text-slate-500 tabular-nums">{ago(r.ts)}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-800">{r.actor}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs">
                          {r.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-600">
                        {r.objectType}:{r.objectId}
                      </TableCell>
                      <TableCell className="max-w-xs truncate font-mono text-[11px] text-slate-500" title={JSON.stringify(r.detail)}>
                        {JSON.stringify(r.detail)}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-slate-500 tabular-nums">
                        <span className="inline-flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3 text-emerald-600 shrink-0" />
                          {r.prevHash.slice(0, 7)}… → {r.hash.slice(0, 7)}…
                        </span>
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
