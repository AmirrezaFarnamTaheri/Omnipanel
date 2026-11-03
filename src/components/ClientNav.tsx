"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { cn } from "@/components/ui";

type NavItem = { href: string; label: string; icon: string };

export function ClientNav({ items }: { items: readonly NavItem[] }) {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <nav className="flex flex-1 flex-col gap-0.5 px-3 py-3">
      {items.map((item) => {
        const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={() => router.push(item.href)}
            className={cn(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
              isActive
                ? "bg-indigo-600/10 text-indigo-700 border-r-2 border-indigo-600"
                : "text-slate-600 hover:bg-slate-100 hover:text-slate-900",
            )}
          >
            <span>{item.icon}</span>
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
