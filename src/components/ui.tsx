import * as React from "react";
import type { ReactNode } from "react";
import { Minus, TrendingDown, TrendingUp } from "lucide-react";

/* ========================================================================
   Design tokens & shared utilities
   ======================================================================== */

export const cn = (...classes: (string | undefined | null | false)[]): string =>
  classes.filter(Boolean).join(" ");

export const inputCls =
  "flex h-10 w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 ring-offset-white file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50";

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
  const trendColor = trend === "up" ? "text-emerald-600" : trend === "down" ? "text-rose-600" : "text-slate-400";
  return (
    <div
      className={cn("rounded-xl border border-slate-200 bg-white p-5 shadow-xs", className)}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-2xl font-semibold tracking-tight text-slate-900 tabular-nums">{value}</span>
        {trend && (
          <span className={cn("inline-flex items-center text-xs font-medium", trendColor)}>
            {trend === "up" ? <TrendingUp className="h-3.5 w-3.5" /> : trend === "down" ? <TrendingDown className="h-3.5 w-3.5" /> : <Minus className="h-3.5 w-3.5" />}
          </span>
        )}
      </div>
      <p className="mt-1 text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p>
      {hint && <p className="mt-1 text-xs text-slate-500 tabular-nums">{hint}</p>}
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
  <div className={cn("rounded-lg border border-slate-200 bg-white overflow-x-auto", className)} {...props}>
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
  <thead className={cn("bg-slate-50/80 text-xs uppercase tracking-wider text-slate-500", className)} {...props}>
    {children}
  </thead>
);

export const TableRow = ({
  className,
  children,
  ...props
}: React.ComponentPropsWithRef<"tr">) => (
  <tr
    className={cn("border-b border-slate-100 transition-colors hover:bg-slate-50/80", className)}
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
      "border-b border-slate-200 font-semibold text-slate-500 px-3.5 py-2.5 text-xs",
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
    className={cn("px-3.5 py-2.5 align-middle", className)}
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
    <div className="mb-6 flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
      <div>
        {breadcrumbs && (
          <nav className="mb-1 flex items-center gap-1 text-xs font-medium text-slate-500" aria-label="Breadcrumb">
            {breadcrumbs}
          </nav>
        )}
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-600 max-w-3xl">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2 shrink-0">{actions}</div>}
    </div>
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
    <div className="flex flex-col items-center justify-center text-center py-10 px-4">
      {icon && <div className="mb-3 text-slate-400">{icon}</div>}
      <h3 className="mb-1 text-base font-semibold text-slate-900">{title}</h3>
      {description && <p className="mb-4 max-w-md text-xs text-slate-500">{description}</p>}
      {action}
    </div>
  );
}

/* ========================================================================
   statusTone helper
   ======================================================================== */

export function statusTone(state: string): "success" | "error" | "warning" | "info" | "secondary" {
  const s = (state ?? "").toLowerCase();
  if (
    s.includes("healthy") ||
    s.includes("active") ||
    s.includes("verified") ||
    s.includes("succeeded") ||
    s.includes("restored") ||
    s.includes("fresh") ||
    s.includes("published") ||
    s.includes("approved") ||
    s.includes("complete") ||
    s === "ok"
  ) {
    return "success";
  }
  if (
    s.includes("error") ||
    s.includes("fail") ||
    s.includes("quarantine") ||
    s.includes("suspended") ||
    s.includes("expired") ||
    s.includes("broken") ||
    s.includes("critical")
  ) {
    return "error";
  }
  if (
    s.includes("pending") ||
    s.includes("draining") ||
    s.includes("unverified") ||
    s.includes("proposed") ||
    s.includes("running") ||
    s.includes("queued") ||
    s.includes("stale") ||
    s.includes("warning") ||
    s.includes("partial")
  ) {
    return "warning";
  }
  if (s.includes("metered") || s.includes("info")) {
    return "info";
  }
  return "secondary";
}
