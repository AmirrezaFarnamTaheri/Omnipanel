import type { ReactNode } from "react";
import { ShieldCheck, Lock, UserCheck, LogOut } from "lucide-react";
import { db } from "@/db";
import { admins } from "@/db/schema";
import { requirePage } from "@/lib/auth";
import { verifyAuditChain } from "@/lib/audit";
import { getEpoch } from "@/lib/revisions";
import { listDesiredStateProposals } from "@/lib/governance-store";
import { logoutAction } from "@/app/actions/auth";
import { switchOperatorIdentityAction } from "@/app/actions/system";
import { Badge, Button } from "@/components/ui";
import { ClientNav, MobileNavDrawer, type NavItem } from "@/components/ClientNav";

export const dynamic = "force-dynamic";

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const me = await requirePage("viewer");
  const epoch = await getEpoch();
  const auditChain = await verifyAuditChain();
  const proposals = await listDesiredStateProposals();
  const pendingApprovals = proposals.filter((p) => !p.decision || p.decision.consumedAt === null).length;
  const allAdmins = await db.select().from(admins).orderBy(admins.id);

  const navItems: readonly NavItem[] = [
    { href: "/", label: "Overview", icon: "overview" },
    { href: "/nodes", label: "Nodes", icon: "nodes" },
    { href: "/approvals", label: "Approvals", icon: "approvals", badge: pendingApprovals },
    { href: "/users", label: "Users", icon: "users" },
    { href: "/plans", label: "Plans", icon: "plans" },
    { href: "/capabilities", label: "Capabilities", icon: "capabilities" },
    { href: "/audit", label: "Audit log", icon: "audit" },
    { href: "/settings", label: "Settings", icon: "settings" },
  ];

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      <aside className="hidden w-64 shrink-0 flex-col border-r border-slate-200 bg-white md:flex">
        <div className="flex items-center justify-between border-b border-slate-100 px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 text-xs font-bold tracking-wider text-white shadow-xs">
              OP
            </div>
            <div>
              <span className="block text-sm font-semibold tracking-tight text-slate-900">OmniPanel</span>
              <span className="block text-[11px] font-mono text-slate-500">v2.0 · Control Plane</span>
            </div>
          </div>
          <Badge variant="outline" className="font-mono text-[11px] tabular-nums">
            E{epoch}
          </Badge>
        </div>

        <ClientNav items={navItems} />

        <div className="border-t border-slate-200 bg-slate-50/60 p-4 space-y-3">
          <div className="rounded-lg border border-slate-200 bg-white p-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Active Operator
              </span>
              <Badge variant={me.role === "owner" ? "info" : "secondary"} className="text-[10px] uppercase">
                {me.role}
              </Badge>
            </div>
            <p className="mt-1 truncate font-mono text-xs font-medium text-slate-900" title={me.email}>
              {me.email}
            </p>
            {allAdmins.length > 1 && (
              <div className="mt-2.5 pt-2 border-t border-slate-100">
                <p className="text-[10px] font-medium text-slate-500 mb-1.5">
                  Switch operator (2-person review / RBAC):
                </p>
                <div className="flex flex-col gap-1">
                  {allAdmins.map((a) => {
                    const isCurrent = a.id === me.id;
                    return (
                      <form key={a.id} action={switchOperatorIdentityAction}>
                        <input type="hidden" name="adminId" value={a.id} />
                        <button
                          type="submit"
                          disabled={isCurrent}
                          className={`w-full flex items-center justify-between rounded px-2 py-1 text-left text-[11px] transition-colors ${
                            isCurrent
                              ? "bg-indigo-50 font-semibold text-indigo-700 cursor-default"
                              : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                          }`}
                        >
                          <span className="truncate font-mono">{a.email.split("@")[0]}</span>
                          <span className="text-[10px] uppercase text-slate-400">{a.role}</span>
                        </button>
                      </form>
                    );
                  })}
                </div>
              </div>
            )}
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
        <header className="sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-slate-200 bg-white/95 backdrop-blur-xs px-4 py-2.5 sm:px-6">
          <div className="flex items-center gap-3">
            <MobileNavDrawer items={navItems} userEmail={me.email} userRole={me.role} />
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-900 md:hidden">OmniPanel</span>
              <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700 tabular-nums">
                <Lock className="h-3.5 w-3.5 text-indigo-600" />
                Epoch #{epoch}
              </span>
              <span
                className={`hidden sm:inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium tabular-nums ${
                  auditChain.ok
                    ? "border-emerald-200 bg-emerald-50/70 text-emerald-800"
                    : "border-rose-200 bg-rose-50 text-rose-800"
                }`}
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                {auditChain.ok ? `Audit Chain (${auditChain.count})` : `Chain Broken @ #${auditChain.brokenAt}`}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/70 px-2.5 py-1">
              <UserCheck className="h-3.5 w-3.5 text-indigo-600 shrink-0" />
              <span className="text-xs font-mono font-medium text-slate-900 max-w-[160px] truncate">{me.email}</span>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{me.role}</span>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-slate-50 p-4 sm:p-6 lg:p-8 max-w-[1600px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
