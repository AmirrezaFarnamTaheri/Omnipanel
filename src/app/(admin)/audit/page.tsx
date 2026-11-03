import { desc } from "drizzle-orm";
import { db } from "@/db";
import { auditLog } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { verifyAuditChain } from "@/lib/audit";
import { fmtDate } from "@/lib/format";
import { Badge, Card, PageHeader, Table, Td } from "@/components/ui";

export default async function AuditPage() {
  await requirePage("viewer");
  const rows = await db.select().from(auditLog).orderBy(desc(auditLog.id)).limit(100);
  const chain = await verifyAuditChain();
  return (
    <>
      <PageHeader
        title="Audit log"
        subtitle="Every administrative mutation is recorded in the same transaction as the change and linked into a hash chain."
        actions={<Badge tone={chain.ok ? "green" : "red"}>{chain.ok ? `chain intact · ${chain.count} records` : `chain broken at #${chain.brokenAt}`}</Badge>}
      />
      <Card>
        <Table head={["#", "Time", "Actor", "Action", "Object", "Detail", "Hash"]} empty={rows.length ? undefined : "No records."}>
          {rows.map((r) => (
            <tr key={r.id}>
              <Td>{r.id}</Td>
              <Td className="whitespace-nowrap text-xs">{fmtDate(r.ts)}</Td>
              <Td className="text-xs">{r.actor}</Td>
              <Td className="font-medium">{r.action}</Td>
              <Td className="text-xs">{r.objectType}:{r.objectId}</Td>
              <Td className="max-w-xs truncate text-xs text-slate-500" >{JSON.stringify(r.detail)}</Td>
              <Td className="font-mono text-xs text-slate-400">{r.hash.slice(0, 8)}</Td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
