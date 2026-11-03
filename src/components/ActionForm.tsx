"use client";

import { useActionState, useState, type ReactNode } from "react";
import type { ActionState } from "@/lib/action-helpers";
import { btnCls, btnDanger, btnGhost } from "@/components/ui";

type Props = {
  action: (prev: ActionState, fd: FormData) => Promise<ActionState>;
  children?: ReactNode;
  submit: string;
  variant?: "primary" | "ghost" | "danger";
  className?: string;
};

function SecretBox({ label, value, hint }: { label: string; value: string; hint?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-3">
      <p className="text-xs font-semibold text-amber-900">{label}</p>
      <code className="mt-1 block break-all rounded bg-white px-2 py-1.5 text-xs text-slate-900">{value}</code>
      {hint && <p className="mt-1 break-all text-xs text-amber-800">{hint}</p>}
      <div className="mt-2 flex items-center gap-3">
        <button
          type="button"
          className={btnGhost}
          onClick={() => {
            navigator.clipboard?.writeText(value).then(() => setCopied(true));
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
        <span className="text-xs text-amber-800">Store it now. It cannot be shown again.</span>
      </div>
    </div>
  );
}

export function ActionForm({ action, children, submit, variant = "primary", className = "" }: Props) {
  const [state, formAction, pending] = useActionState(action, {} as ActionState);
  const cls = variant === "danger" ? btnDanger : variant === "ghost" ? btnGhost : btnCls;
  return (
    <form action={formAction} className={className}>
      {children}
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button type="submit" disabled={pending} className={cls}>
          {pending ? "Working…" : submit}
        </button>
        {state.error && (
          <p role="alert" className="text-sm font-medium text-rose-700">
            {state.error}
          </p>
        )}
        {state.ok && state.message && <p className="text-sm text-emerald-700">{state.message}</p>}
      </div>
      {state.secret && <SecretBox {...state.secret} />}
    </form>
  );
}
