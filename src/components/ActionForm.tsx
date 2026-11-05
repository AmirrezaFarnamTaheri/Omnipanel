"use client";

import { useActionState, useState, type ReactNode } from "react";
import type { ActionState } from "@/lib/action-helpers";
import { Button } from "@/components/ui";

type Props = {
  action: (prev: ActionState, fd: FormData) => Promise<ActionState>;
  children?: ReactNode;
  submit: string;
  variant?: "default" | "outline" | "destructive" | "ghost";
  size?: "default" | "sm" | "lg" | "icon";
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
          className="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 text-indigo-600 hover:bg-slate-100 hover:text-indigo-700 h-10 w-10"
          onClick={() => {
            navigator.clipboard?.writeText(value).then(() => setCopied(true));
          }}
        >
          {copied ? "✓" : "⎘"}
        </button>
        <span className="text-xs text-amber-800">Store it now. It cannot be shown again.</span>
      </div>
    </div>
  );
}

export function ActionForm({ action, children, submit, variant = "default", size, className = "" }: Props) {
  const [state, formAction, pending] = useActionState(action, {} as ActionState);
  return (
    <form action={formAction} className={className}>
      {children}
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Button variant={variant} size={size} disabled={pending}>
          {pending ? "Working…" : submit}
        </Button>
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
