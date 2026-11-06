"use client";

import { useState } from "react";
import { Check, Copy, FileCode2, QrCode, ShieldCheck } from "lucide-react";
import { Badge, Button, cn } from "@/components/ui";

export type CompiledFormatPreview = {
  format: "singbox" | "mihomo" | "xray" | "uri" | "balancer";
  label: string;
  contentType: string;
  admittedCount: number;
  excludedReasons: Array<{ inboundId: number; name: string; reason: string }>;
  compiledBody: string;
  sha256: string;
};

/**
 * Generates a deterministic 21x21 visual matrix from a SHA-256 hex digest with standard
 * 7x7 finder patterns in the three corners for offline air-gapped visual verification.
 */
function buildDeterministicMatrix(sha256Hex: string): boolean[][] {
  const size = 21;
  const grid: boolean[][] = Array.from({ length: size }, () => Array(size).fill(false));

  const placeFinder = (rowOffset: number, colOffset: number) => {
    for (let r = 0; r < 7; r++) {
      for (let c = 0; c < 7; c++) {
        const isBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const isInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        grid[rowOffset + r][colOffset + c] = isBorder || isInner;
      }
    }
  };

  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    grid[6][i] = i % 2 === 0;
    grid[i][6] = i % 2 === 0;
  }

  let bitIndex = 0;
  const cleanHex = (sha256Hex || "a5".repeat(32)).padEnd(64, "0");

  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      const inTopLeft = r < 8 && c < 8;
      const inTopRight = r < 8 && c >= size - 8;
      const inBottomLeft = r >= size - 8 && c < 8;
      if (inTopLeft || inTopRight || inBottomLeft || r === 6 || c === 6) continue;

      const hexChar = cleanHex[Math.floor(bitIndex / 4) % cleanHex.length];
      const nibble = parseInt(hexChar, 16) || 0;
      const bit = (nibble >> (bitIndex % 4)) & 1;
      grid[r][c] = bit === 1;
      bitIndex += 1;
    }
  }

  return grid;
}

export function SubscriptionInspector({
  formats,
  headersPreview,
}: {
  formats: CompiledFormatPreview[];
  headersPreview: Record<string, string>;
}) {
  const [selected, setSelected] = useState<CompiledFormatPreview["format"]>("singbox");
  const [copied, setCopied] = useState(false);

  const active = formats.find((f) => f.format === selected) ?? formats[0];

  const handleCopy = () => {
    if (!active) return;
    navigator.clipboard?.writeText(active.compiledBody).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  if (!active) return null;

  const matrix = buildDeterministicMatrix(active.sha256);

  return (
    <div className="mt-5 space-y-4 border-t border-slate-100 pt-5">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-900">
            <FileCode2 className="h-4 w-4 text-indigo-600" />
            Deterministic Multi-Client Subscription Compiler & Header Inspector
          </h3>
          <p className="text-xs text-slate-500">
            Inspect byte-stable emitter output (<code className="font-mono">singbox</code>,{" "}
            <code className="font-mono">mihomo</code>, <code className="font-mono">xray</code>,{" "}
            <code className="font-mono">uri</code>, <code className="font-mono">balancer</code>) and RFC-encoded HTTP response headers.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {formats.map((f) => (
            <button
              key={f.format}
              type="button"
              onClick={() => setSelected(f.format)}
              className={cn(
                "rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors",
                selected === f.format
                  ? "border-indigo-600 bg-indigo-600 text-white shadow-xs"
                  : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 rounded-xl border border-slate-200 bg-slate-900 p-4 text-slate-100">
          <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5 text-xs">
            <div className="flex items-center gap-2 font-mono">
              <span className="text-indigo-400 font-semibold">{active.label}</span>
              <span className="text-slate-500">·</span>
              <span className="text-slate-400">{active.contentType}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-slate-400" title={active.sha256}>
                sha256:{active.sha256.slice(0, 16)}…
              </span>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={handleCopy}
                className="h-7 border-slate-700 bg-slate-800 px-2.5 text-xs text-slate-200 hover:bg-slate-700"
              >
                {copied ? <Check className="h-3.5 w-3.5 mr-1 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 mr-1" />}
                {copied ? "Copied" : "Copy Output"}
              </Button>
            </div>
          </div>
          <pre className="max-h-72 overflow-auto font-mono text-xs leading-relaxed text-slate-100">
            {active.compiledBody}
          </pre>
        </div>

        <div className="space-y-3">
          <div className="rounded-xl border border-slate-200 bg-slate-50/80 p-3.5 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-900">HTTP Response Headers</span>
              <Badge variant="outline" className="font-mono text-[10px]">
                private, no-store
              </Badge>
            </div>
            <div className="space-y-1.5 rounded-lg bg-slate-900 p-2.5 font-mono text-[11px] text-slate-200 overflow-x-auto">
              {Object.entries(headersPreview).map(([k, v]) => (
                <div key={k} className="break-all">
                  <span className="text-indigo-400">{k}:</span> {v}
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-3.5 text-xs space-y-2">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5 font-semibold text-slate-900">
                <QrCode className="h-4 w-4 text-indigo-600" />
                <span>Offline Profile Matrix ({active.label})</span>
              </span>
              <Badge variant="info" className="font-mono text-[10px]">
                Air-Gapped SVG
              </Badge>
            </div>
            <div className="flex items-center gap-3">
              <svg
                viewBox="0 0 21 21"
                className="h-20 w-20 shrink-0 rounded border border-slate-200 bg-white p-1"
                aria-label="Deterministic Profile Matrix"
              >
                {matrix.map((row, rIdx) =>
                  row.map((cell, cIdx) =>
                    cell ? (
                      <rect
                        key={`${rIdx}-${cIdx}`}
                        x={cIdx}
                        y={rIdx}
                        width={1}
                        height={1}
                        fill="#0f172a"
                      />
                    ) : null
                  )
                )}
              </svg>
              <div className="space-y-1 text-[11px] text-slate-600">
                <p className="font-medium text-slate-800">
                  Zero external QR/image calls
                </p>
                <p>
                  Rendered locally in SVG from profile digest <code className="font-mono">{active.sha256.slice(0, 10)}…</code> so subscriber tokens never leak to third-party endpoints.
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-3.5 text-xs space-y-2">
            <div className="flex items-center gap-1.5 font-semibold text-slate-900">
              <ShieldCheck className="h-4 w-4 text-indigo-600" />
              <span>Fail-Closed Format Gate ({active.label})</span>
            </div>
            {active.excludedReasons.length === 0 ? (
              <p className="text-emerald-700">
                All {active.admittedCount} endpoint path(s) admitted for {active.label}.
              </p>
            ) : (
              <ul className="space-y-1.5 text-slate-600">
                {active.excludedReasons.map((ex) => (
                  <li key={ex.inboundId} className="rounded border border-amber-200 bg-amber-50/60 p-2 text-[11px]">
                    <span className="font-mono font-semibold text-amber-900">{ex.name}:</span>{" "}
                    <span className="text-amber-800">{ex.reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
