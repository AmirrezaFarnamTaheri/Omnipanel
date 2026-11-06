"use client";

import { useActionState, useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import type { ActionState } from "@/lib/action-helpers";
import { Button } from "@/components/ui";

type Props = {
  action: (prev: ActionState, fd: FormData) => Promise<ActionState>;
  children?: ReactNode;
  submit?: string;
  submitLabel?: string;
  variant?: "default" | "outline" | "destructive" | "ghost";
  size?: "default" | "sm" | "lg" | "icon";
  className?: string;
};

function SecretBox({ label, value, hint }: { label: string; value: string; hint?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-3">
      <p className="text-xs font-semibold text-amber-900">{label}</p>
      <code className="mt-1 block break-all rounded bg-white px-2 py-1.5 font-mono text-xs text-slate-900">{value}</code>
      {hint && <p className="mt-1 break-all text-xs text-amber-800">{hint}</p>}
      <div className="mt-2 flex items-center gap-3">
        <button
          type="button"
          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-amber-200 bg-white text-indigo-600 transition-colors hover:bg-amber-100 hover:text-indigo-700"
          onClick={() => {
            navigator.clipboard?.writeText(value).then(() => setCopied(true));
          }}
          aria-label="Copy secret to clipboard"
        >
          {copied ? <Check className="h-4 w-4 text-emerald-600" /> : <Copy className="h-4 w-4" />}
        </button>
        <span className="text-xs text-amber-800">Store it now. It cannot be shown again.</span>
      </div>
    </div>
  );
}

export function ActionForm({
  action,
  children,
  submit,
  submitLabel,
  variant = "default",
  size,
  className = "",
}: Props) {
  const [state, formAction, pending] = useActionState(action, {} as ActionState);
  const label = submitLabel ?? submit ?? "Submit";
  return (
    <form action={formAction} className={className}>
      {children}
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Button variant={variant} size={size} disabled={pending}>
          {pending ? "Working…" : label}
        </Button>
        {state.error && (
          <p role="alert" className="text-sm font-medium text-rose-700">
            {state.error}
          </p>
        )}
        {state.ok && state.message && <p className="text-sm font-medium text-emerald-700">{state.message}</p>}
      </div>
      {state.secret && <SecretBox {...state.secret} />}
    </form>
  );
}
