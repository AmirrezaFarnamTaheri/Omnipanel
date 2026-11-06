import type { ReactNode } from "react";
import Link from "next/link";
import { ShieldCheck, LogOut, Plus } from "lucide-react";
import { requirePage } from "@/lib/auth";
import { verifyAuditChain } from "@/lib/audit";
import { getEpoch } from "@/lib/revisions";
import { listDesiredStateProposals } from "@/lib/governance-store";
import { logoutAction } from "@/app/actions/auth";
import { Badge, Button } from "@/components/ui";
import { ClientNav, MobileNavDrawer, type NavItem } from "@/components/ClientNav";

export const dynamic = "force-dynamic";

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const me = await requirePage("viewer");
  const epoch = await getEpoch();
  const auditChain = await verifyAuditChain();
  const proposals = await listDesiredStateProposals();
  const pendingApprovals = proposals.filter((p) => !p.decision || p.decision.consumedAt === null).length;

  const navItems: readonly NavItem[] = [
    { href: "/", label: "Overview", icon: "overview" },
    { href: "/nodes", label: "Nodes", icon: "nodes" },
    { href: "/users", label: "Users", icon: "users" },
    { href: "/plans", label: "Plans", icon: "plans" },
    { href: "/settings", label: "Settings", icon: "settings" },
    { href: "/approvals", label: "Revisions", icon: "approvals", badge: pendingApprovals },
    { href: "/capabilities", label: "Runtimes", icon: "capabilities" },
    { href: "/audit", label: "Audit log", icon: "audit" },
  ];

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-slate-200 bg-white md:flex">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-xs font-bold tracking-wider text-white shadow-xs">
              OP
            </div>
            <div>
              <span className="block text-sm font-semibold tracking-tight text-slate-900">OmniPanel</span>
              <span className="block text-[11px] text-slate-500">Personal Control Plane</span>
            </div>
          </Link>
        </div>

        <ClientNav items={navItems} />

        <div className="border-t border-slate-100 bg-slate-50/50 p-4 space-y-2.5">
          <div className="flex items-center justify-between gap-2 px-1">
            <span className="truncate font-mono text-xs font-medium text-slate-700" title={me.email}>
              {me.email}
            </span>
            <Badge variant="outline" className="text-[10px] uppercase">
              {me.role}
            </Badge>
          </div>

          <form action={logoutAction}>
            <Button variant="outline" size="sm" className="w-full gap-2 text-xs">
              <LogOut className="h-3.5 w-3.5" />
              Sign out
            </Button>
          </form>
        </div>
      </aside>

      <div className="flex flex-1 flex-col min-w-0">
        <header className="sticky top-0 z-20 flex items-center justify-between gap-4 border-b border-slate-200 bg-white/95 backdrop-blur-xs px-4 py-2.5 sm:px-6">
          <div className="flex items-center gap-3">
            <MobileNavDrawer items={navItems} userEmail={me.email} userRole={me.role} />
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="text-sm font-semibold text-slate-900 md:hidden">OmniPanel</span>
              <span className="font-mono tabular-nums text-slate-600">Epoch #{epoch}</span>
              <span aria-hidden="true">·</span>
              <span className="inline-flex items-center gap-1 text-emerald-700 font-medium tabular-nums">
                <ShieldCheck className="h-3.5 w-3.5" />
                {auditChain.ok ? `${auditChain.count} audited events` : `Chain alert #${auditChain.brokenAt}`}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Link
              href="/users"
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors whitespace-nowrap"
            >
              <Plus className="h-3.5 w-3.5 text-indigo-600" />
              Add User
            </Link>
            <Link
              href="/nodes"
              className="inline-flex items-center gap-1 rounded-lg bg-indigo-600 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 transition-colors whitespace-nowrap"
            >
              <Plus className="h-3.5 w-3.5" />
              Add Node
            </Link>
          </div>
        </header>

        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-slate-50 p-4 sm:p-6 lg:p-8 max-w-[1500px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
