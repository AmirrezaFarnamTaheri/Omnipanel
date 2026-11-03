import Link from "next/link";
import type { ReactNode } from "react";
import { requirePage } from "@/lib/auth";
import { logoutAction } from "@/app/actions/auth";

export const dynamic = "force-dynamic";

const NAV = [
  ["/", "Overview"],
  ["/nodes", "Nodes & revisions"],
  ["/users", "Users"],
  ["/plans", "Plans"],
  ["/capabilities", "Capabilities"],
  ["/audit", "Audit log"],
  ["/settings", "Settings & recovery"],
] as const;

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const me = await requirePage("viewer");
  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col bg-slate-900 p-4 text-slate-300 md:flex">
        <p className="px-2 pb-6 pt-2 text-lg font-semibold tracking-tight text-white">OmniPanel</p>
        <nav className="flex flex-1 flex-col gap-1">
          {NAV.map(([href, label]) => (
            <Link key={href} href={href} className="rounded-md px-3 py-2 text-sm transition hover:bg-slate-800 hover:text-white">
              {label}
            </Link>
          ))}
        </nav>
        <div className="border-t border-slate-800 pt-3 text-xs">
          <p className="truncate px-2 text-slate-400">{me.email}</p>
          <p className="px-2 pb-2 text-slate-500">{me.role}</p>
          <form action={logoutAction}>
            <button className="w-full rounded-md px-3 py-2 text-left text-sm hover:bg-slate-800 hover:text-white">Sign out</button>
          </form>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <nav className="flex gap-3 overflow-x-auto bg-slate-900 px-4 py-2 text-sm text-slate-200 md:hidden">
          {NAV.map(([href, label]) => (
            <Link key={href} href={href} className="whitespace-nowrap">
              {label}
            </Link>
          ))}
        </nav>
        <main className="mx-auto max-w-6xl px-5 py-8">{children}</main>
      </div>
    </div>
  );
}
