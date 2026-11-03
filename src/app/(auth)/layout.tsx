import type { ReactNode } from "react";

export default function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <main className="grid min-h-screen place-items-center bg-slate-900 px-4">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <p className="text-2xl font-semibold tracking-tight text-white">OmniPanel</p>
          <p className="text-sm text-slate-400">Control plane for multi-protocol proxy infrastructure</p>
        </div>
        <div className="rounded-2xl bg-white p-7 shadow-2xl">{children}</div>
      </div>
    </main>
  );
}
