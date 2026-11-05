"use client";

import * as React from "react";
import type { ReactNode } from "react";

/* ========================================================================
   Design tokens & shared utilities
   ======================================================================== */

export const cn = (...classes: (string | undefined | null | false)[]): string =>
  classes.filter(Boolean).join(" ");

export const inputCls =
  "flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50";

export const btnBase =
  "inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50";

export const btnVariants: Record<string, string> = {
  default: `${btnBase} bg-indigo-600 text-white hover:bg-indigo-700`,
  secondary: `${btnBase} bg-slate-100 text-slate-900 hover:bg-slate-200`,
  destructive: `${btnBase} bg-rose-600 text-white hover:bg-rose-700`,
  outline: `${btnBase} border border-slate-200 bg-white hover:bg-slate-50`,
  ghost: `${btnBase} hover:bg-slate-100`,
  link: `${btnBase} text-indigo-600 underline-offset-4 hover:underline`,
};

/* ========================================================================
   Button
   ======================================================================== */

export function Button({
  className,
  variant = "default",
  size = "default",
  ...props
}: React.ComponentPropsWithRef<"button"> & {
  variant?: keyof typeof btnVariants;
  size?: "default" | "sm" | "lg" | "icon";
}) {
  const sizes: Record<string, string> = {
    default: "h-10 px-4 py-2",
    sm: "h-9 rounded-md px-3",
    lg: "h-11 rounded-md px-8",
    icon: "h-10 w-10",
  };
  return (
    <button
      className={cn(btnVariants[variant], sizes[size], className)}
      {...props}
    />
  );
}

/* ========================================================================
   Input
   ======================================================================== */

export function Input({
  className,
  ...props
}: React.ComponentPropsWithRef<"input">) {
  return <input className={cn(inputCls, className)} {...props} />;
}

/* ========================================================================
   Label
   ======================================================================== */

export function Label({
  className,
  ...props
}: React.ComponentPropsWithRef<"label">) {
  return (
    <label
      className={cn("text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70", className)}
      {...props}
    />
  );
}

/* ========================================================================
   Field (Label + Input + hint + error)
   ======================================================================== */

export function Field({
  label,
  children,
  hint,
  error,
  className,
}: {
  label?: string;
  children: ReactNode;
  hint?: string;
  error?: string;
  className?: string;
}) {
  return (
    <div className={cn("space-y-1", className)}>
      {label && <Label>{label}</Label>}
      <div className="relative">{children}</div>
      {error && <p className="text-sm text-rose-600">{error}</p>}
      {hint && !error && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

/* ========================================================================
   Select
   ======================================================================== */

export function Select({
  className,
  ...props
}: React.ComponentPropsWithRef<"select">) {
  return (
    <select
      className={cn(inputCls, className)}
      {...props}
    />
  );
}

/* ========================================================================
   Card
   ======================================================================== */

export function Card({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"div"> & { children?: ReactNode }) {
  return (
    <div
      className={cn("rounded-xl border border-slate-200 bg-white shadow-sm", className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"div"> & { children?: ReactNode }) {
  return (
    <div className={cn("flex flex-col space-y-1.5 p-6", className)} {...props}>
      {children}
    </div>
  );
}

export function CardTitle({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"h2"> & { children?: ReactNode }) {
  return (
    <h2 className={cn("text-xl font-semibold leading-none tracking-tight", className)} {...props}>
      {children}
    </h2>
  );
}

export function CardDescription({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"p"> & { children?: ReactNode }) {
  return (
    <p className={cn("text-sm text-slate-600", className)} {...props}>
      {children}
    </p>
  );
}

export function CardContent({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"div"> & { children?: ReactNode }) {
  return (
    <div className={cn("p-6 pt-0", className)} {...props}>
      {children}
    </div>
  );
}

export function CardFooter({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"div"> & { children?: ReactNode }) {
  return (
    <div className={cn("flex items-center p-6 pt-0", className)} {...props}>
      {children}
    </div>
  );
}

/* ========================================================================
   Badge
   ======================================================================== */

const badgeVariants: Record<string, string> = {
  default: "border-transparent bg-indigo-600 text-white hover:bg-indigo-700",
  secondary: "border-transparent bg-slate-100 text-slate-900 hover:bg-slate-200",
  destructive: "border-transparent bg-rose-600 text-white hover:bg-rose-700",
  outline: "border border-slate-200 bg-white",
  success: "border-transparent bg-emerald-500/10 text-emerald-700 ring-1 ring-emerald-200",
  warning: "border-transparent bg-amber-500/10 text-amber-700 ring-1 ring-amber-200",
  error: "border-transparent bg-rose-500/10 text-rose-700 ring-1 ring-rose-200",
  info: "border-transparent bg-indigo-500/10 text-indigo-700 ring-1 ring-indigo-200",
};

export function Badge({
  className,
  variant = "default",
  ...props
}: React.ComponentPropsWithRef<"span"> & { variant?: keyof typeof badgeVariants }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-1",
        badgeVariants[variant],
        className,
      )}
      {...props}
    />
  );
}

/* ========================================================================
   Stat
   ======================================================================== */

export function Stat({
  label,
  value,
  hint,
  trend,
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  trend?: "up" | "down" | "neutral";
  className?: string;
}) {
  const trendIcon = trend === "up" ? "▲" : trend === "down" ? "▼" : "–";
  const trendColor = trend === "up" ? "text-emerald-600" : trend === "down" ? "text-rose-600" : "text-slate-400";
  return (
    <div
      className={cn("rounded-xl border border-slate-200 bg-white p-5 shadow-sm", className)}
    >
      <div className="flex items-baseline space-x-2">
        <span className="text-2xl font-semibold">{value}</span>
        {trend && (
          <span className={`ml-1 text-xs font-medium ${trendColor}`}>{trendIcon}</span>
        )}
      </div>
      <p className="mt-0.5 text-xs text-slate-500">{label}</p>
      {hint && <p className="mt-0.5 text-xs text-slate-500">{hint}</p>}
    </div>
  );
}

/* ========================================================================
   Table
   ======================================================================== */

export const TableWrapper = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"div">) => (
  <div className={cn("rounded-md border border-slate-200 overflow-hidden shadow-sm", className)} {...props}>
    {children}
  </div>
);

export const Table = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"table">) => (
  <table className={cn("w-full text-sm text-left", className)} {...props}>
    {children}
  </table>
);

export const TableHeader = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"thead">) => (
  <thead className={cn("bg-slate-50 text-xs", className)} {...props}>
    {children}
  </thead>
);

export const TableRow = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"tr">) => (
  <tr
    className={cn("border-b border-slate-100 transition-colors hover:bg-slate-50", className)}
    {...props}
  >
    {children}
  </tr>
);

export const TableHead = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"th">) => (
  <th
    className={cn(
      "border-b font-medium text-slate-500 px-3 py-2",
      className,
    )}
    {...props}
  >
    {children}
  </th>
);

export const TableBody = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"tbody">) => (
  <tbody className={cn("[&_tr]:last:border-b-0", className)} {...props}>
    {children}
  </tbody>
);

export const TableCell = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"td">) => (
  <td
    className={cn("p-3 align-middle", className)}
    {...props}
  >
    {children}
  </td>
);

/* ========================================================================
   PageHeader
   ======================================================================== */

export function PageHeader({
  title,
  subtitle,
  actions,
  breadcrumbs,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  breadcrumbs?: ReactNode;
}) {
  return (
    <div className="mb-8 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
      <div>
        {breadcrumbs && (
          <nav className="flex items-center gap-1 text-xs text-slate-500" aria-label="Breadcrumb">
            {breadcrumbs}
          </nav>
        )}
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">{title}</h1>
        {subtitle && <p className="text-sm text-slate-600">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ========================================================================
   Alert
   ======================================================================== */

const alertVariants: Record<string, string> = {
  default: "border-slate-200 bg-slate-50 text-slate-900",
  destructive: "border-rose-200 bg-rose-50 text-rose-900",
  success: "border-emerald-200 bg-emerald-50 text-emerald-900",
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  info: "border-indigo-200 bg-indigo-50 text-indigo-900",
};

export function Alert({
  variant = "default",
  className,
  title,
  description,
  ...props
}: React.ComponentPropsWithRef<"div"> & {
  variant?: keyof typeof alertVariants;
  title?: ReactNode;
  description?: ReactNode;
}) {
  return (
    <div
      role="alert"
      className={cn(
        "relative w-full rounded-lg border p-4 text-sm [&>svg+div]:pl-10",
        alertVariants[variant],
        className,
      )}
      {...props}
    >
      {title && <h3 className="mb-1 font-medium leading-none tracking-tight">{title}</h3>}
      {description && <p className="text-muted-foreground">{description}</p>}
    </div>
  );
}

/* ========================================================================
   Avatar
   ======================================================================== */

export function Avatar({
  className,
  src,
  alt,
  ...props
}: React.ComponentPropsWithRef<"img"> & { src?: string; alt?: string }) {
  return (
    <span
      className={cn(
        "relative flex h-10 w-10 shrink-0 overflow-hidden rounded-full",
        className,
      )}
      {...props}
    >
      <img src={src} alt={alt} className="aspect-square h-full w-full object-cover" />
    </span>
  );
}

/* ========================================================================
   Spinner
   ======================================================================== */

export function Spinner({
  className,
  size = "5",
  ...props
}: React.ComponentPropsWithRef<"svg"> & { size?: string }) {
  return (
    <svg
      className={cn(`h-${size} w-${size} animate-spin`, className)}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      {...props}
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

/* ========================================================================
   EmptyState
   ======================================================================== */

export function EmptyState({
  title,
  description,
  icon,
  action,
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-12">
      {icon && <div className="mb-4 opacity-50">{icon}</div>}
      <h3 className="mb-2 text-lg font-medium text-slate-900">{title}</h3>
      {description && <p className="mb-6 max-w-xs text-sm text-slate-500">{description}</p>}
      {action}
    </div>
  );
}

/* ========================================================================
   ConfirmDialog
   ======================================================================== */

/* ========================================================================
   Td (table cell shim for legacy pages)
   ======================================================================== */

export function Td({
  className,
  children,
  colSpan,
  ...props
}: React.ComponentPropsWithRef<"td"> & { colSpan?: number }) {
  return (
    <td
      className={cn("p-3 align-middle", className)}
      colSpan={colSpan}
      {...props}
    >
      {children}
    </td>
  );
}

/* ========================================================================
   statusTone helper
   ======================================================================== */

export function statusTone(state: string): "success" | "error" | "warning" | "secondary" {
  const s = (state ?? "").toLowerCase();
  if (s.includes("healthy") || s.includes("active") || s.includes("ok")) return "success";
  if (s.includes("error") || s.includes("fail") || s.includes("quarantine")) return "error";
  if (s.includes("pending") || s.includes("draining") || s.includes("unverified")) return "warning";
  return "secondary";
}

/* ========================================================================
   ConfirmDialog
   ======================================================================== */

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  onConfirm,
  destructive = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  destructive?: boolean;
}) {
  return (
    <div
      className={cn("fixed inset-0 z-50 flex items-center justify-center", !open && "hidden")}
      onClick={(e) => { if (e.target === e.currentTarget) onOpenChange(false); }}
    >
      <div className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity" />
      <div className="relative w-full max-w-md bg-white rounded-lg border p-6 shadow-xl">
        <h3 className="mb-1 text-lg font-medium text-slate-900">{title}</h3>
        {description && <p className="text-sm text-slate-600">{description}</p>}
        <div className="mt-6 flex flex-row-reverse gap-3">
          <Button variant={destructive ? "destructive" : "default"} onClick={() => { onConfirm(); onOpenChange(false); }}>
            {confirmLabel}
          </Button>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {cancelLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
