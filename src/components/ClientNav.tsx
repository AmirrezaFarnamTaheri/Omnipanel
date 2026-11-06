"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Cpu,
  Layers,
  LayoutDashboard,
  Menu,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import { cn } from "@/components/ui";

export type NavItem = {
  href: string;
  label: string;
  icon: string;
  badge?: number;
};

function renderNavIcon(icon: string, active: boolean) {
  const cls = cn("h-4 w-4 shrink-0 transition-colors", active ? "text-indigo-600" : "text-slate-400 group-hover:text-slate-600");
  switch (icon) {
    case "overview":
      return <LayoutDashboard className={cls} />;
    case "nodes":
      return <Server className={cls} />;
    case "approvals":
      return <ShieldCheck className={cls} />;
    case "users":
      return <Users className={cls} />;
    case "plans":
      return <Layers className={cls} />;
    case "capabilities":
      return <Cpu className={cls} />;
    case "audit":
      return <ScrollText className={cls} />;
    case "settings":
      return <Settings className={cls} />;
    default:
      return <LayoutDashboard className={cls} />;
  }
}

export function ClientNav({
  items,
  onNavigate,
}: {
  items: readonly NavItem[];
  onNavigate?: () => void;
}) {
  const pathname = usePathname();

  return (
    <nav className="flex flex-1 flex-col gap-1 px-3 py-3" aria-label="Primary Navigation">
      {items.map((item) => {
        const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(`${item.href}/`));
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onNavigate}
            className={cn(
              "group flex items-center justify-between rounded-lg px-3 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-indigo-50/90 text-indigo-700 ring-1 ring-indigo-200/70"
                : "text-slate-600 hover:bg-slate-100 hover:text-slate-900",
            )}
          >
            <span className="flex items-center gap-2.5">
              {renderNavIcon(item.icon, isActive)}
              <span>{item.label}</span>
            </span>
            {typeof item.badge === "number" && item.badge > 0 && (
              <span
                className={cn(
                  "inline-flex h-5 min-w-5 items-center justify-center rounded-full px-1.5 text-[11px] font-semibold tabular-nums",
                  isActive ? "bg-indigo-600 text-white" : "bg-amber-100 text-amber-800",
                )}
              >
                {item.badge}
              </span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}

export function MobileNavDrawer({ items, userEmail, userRole }: { items: readonly NavItem[]; userEmail: string; userRole: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="md:hidden">
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Open navigation menu"
        className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
      >
        <Menu className="h-4 w-4" />
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex">
          <div
            className="fixed inset-0 bg-slate-900/50 backdrop-blur-xs"
            onClick={() => setOpen(false)}
          />
          <div className="relative z-10 flex w-72 max-w-[85vw] flex-col bg-white shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
              <div className="flex items-center gap-2.5">
                <div className="flex h-7 w-7 items-center justify-center rounded-md bg-indigo-600 text-xs font-bold text-white">
                  OP
                </div>
                <span className="font-semibold tracking-tight text-slate-900">OmniPanel</span>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close navigation menu"
                className="inline-flex h-8 w-8 items-center justify-center rounded-md text-slate-500 hover:bg-slate-100"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <ClientNav items={items} onNavigate={() => setOpen(false)} />
            <div className="border-t border-slate-200 p-4 text-xs text-slate-500">
              <p className="font-medium text-slate-900 truncate">{userEmail}</p>
              <p className="uppercase tracking-wider text-[11px] text-slate-500 mt-0.5">{userRole}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
