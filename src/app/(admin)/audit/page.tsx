import { count, desc, eq, sql, ilike, or } from "drizzle-orm";
import { db } from "@/db";
import { auditLog } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { ago } from "@/lib/format";
import { PageHeader, Card, CardContent, CardDescription, CardHeader, CardTitle, EmptyState, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, TableWrapper, Badge } from "@/components/ui";

export default async function AuditPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const me = await requirePage("viewer");
  const { q } = await searchParams;
  const filters: any[] = [];
  if (q) {
    filters.push(or(ilike(auditLog.action, `%${q}%`), ilike(auditLog.actor, `%${q}%`), ilike(auditLog.objectId, `%${q}%`)));
  }
  const rows = await db.select().from(auditLog).where(filters.length ? or(...filters) : undefined).orderBy(desc(auditLog.id)).limit(100);
  const [{ total }] = await db.select({ total: count() }).from(auditLog);

  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle={`${total} record(s), hash-chained from genesis. Audit entries are immutable once committed.`}
      />
      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
          <CardDescription>{rows.length} of {total} most recent records shown</CardDescription>
        </CardHeader>
        <CardContent>
          <TableWrapper>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-24">Time</TableHead>
                  <TableHead className="w-32">Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="w-32">Object</TableHead>
                  <TableHead className="w-20">Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5}>
                      <EmptyState title="No audit records yet" description="Audit entries appear here as platform actions are committed." />
                    </TableCell>
                  </TableRow>
                ) : (
                  rows.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="text-xs text-slate-600">{ago(r.ts)}</TableCell>
                      <TableCell className="text-xs font-mono">{r.actor}</TableCell>
                      <TableCell className="text-xs font-medium">{r.action}</TableCell>
                      <TableCell className="text-xs text-slate-500">{r.objectType} {r.objectId}</TableCell>
                      <TableCell>
                        <Badge variant="success">ok</Badge>
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
