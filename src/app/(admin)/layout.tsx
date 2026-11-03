import Link from "next/link";
import type { ReactNode } from "react";
import { requirePage } from "@/lib/auth";
import { logoutAction } from "@/app/actions/auth";
import { Button } from "@/components/ui";
import { ClientNav } from "@/components/ClientNav";

export const dynamic = "force-dynamic";

const NAV = [
  { href: "/", label: "Overview", icon: "📊" },
  { href: "/nodes", label: "Nodes", icon: "🖥️" },
  { href: "/users", label: "Users", icon: "👥" },
  { href: "/plans", label: "Plans", icon: "📋" },
  { href: "/capabilities", label: "Capabilities", icon: "🔐" },
  { href: "/m2/cdn", label: "CDN", icon: "🌐" },
  { href: "/m2/relay", label: "Relay", icon: "🔀" },
  { href: "/m2/warp", label: "WARP", icon: "🔗" },
  { href: "/m2/bpb", label: "BPB", icon: "⚡" },
  { href: "/audit", label: "Audit log", icon: "📜" },
  { href: "/settings", label: "Settings", icon: "⚙️" },
] as const;

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const me = await requirePage("viewer");

  return (
    <div className="flex min-h-screen bg-slate-50 text-slate-900">
      {/* Sidebar */}
      <aside className="hidden w-64 shrink-0 flex-col bg-white border-r border-slate-200 md:flex">
        <div className="flex items-center gap-2 px-6 py-5">
          <span className="text-xl">🔺</span>
          <span className="font-semibold text-slate-900 tracking-tight">OmniPanel</span>
        </div>
        <ClientNav items={NAV} />
        <div className="border-t border-slate-200 pt-4 px-6">
          <p className="text-xs font-medium text-slate-900 truncate px-2">{me.email}</p>
          <p className="text-xs text-slate-500 px-2 pb-2">{me.role}</p>
          <form action={logoutAction}>
            <Button variant="outline" size="sm" className="w-full text-left">
              Sign out
            </Button>
          </form>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="flex items-center justify-between border-b border-slate-200 bg-white px-6 py-4 sticky top-0 z-10">
          <div className="flex items-center gap-2">
            <button className="text-slate-400 hover:text-slate-600 md:hidden">
              <span className="text-xl">☰</span>
            </button>
            <span className="font-semibold text-slate-900 hidden sm:block">OmniPanel</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden sm:flex items-center gap-2 text-xs text-slate-500">
              <span className="w-2 h-2 rounded-full bg-emerald-500" /> System operational
            </span>
            <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white p-1">
              <Avatar src={`https://api.dicebear.com/7bottts/seed/${encodeURIComponent(me.email)}.svg`} alt={me.email} />
              <div className="hidden sm:block text-left">
                <p className="text-sm font-medium text-slate-900">{me.email}</p>
                <p className="text-xs text-slate-500">{me.role}</p>
              </div>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-x-hidden overflow-y-auto bg-slate-50 p-6 sm:p-8 lg:p-10">
          {children}
        </main>
      </div>
    </div>
  );
}

function Avatar({ className, src, alt }: { className?: string; src: string; alt: string }) {
  return (
    <span className={`relative flex shrink-0 overflow-hidden rounded-full ${className ?? ""}`}>
      <img src={src} alt={alt} className="aspect-square h-full w-full object-cover" />
    </span>
  );
}
