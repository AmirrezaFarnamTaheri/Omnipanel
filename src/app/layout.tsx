import type { Metadata } from "next";
import { Plus_Jakarta_Sans, JetBrains_Mono } from "next/font/google";
import type { ReactNode } from "react";
import "./globals.css";

const sans = Plus_Jakarta_Sans({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "OmniPanel — Unified Proxy Runtime & Node Control Plane",
  description:
    "Fail-closed control plane for Sing-box, Xray, and Hysteria2 runtimes with dual-operator signed desired-state publication, durable metering, and deterministic client subscription compilation.",
  openGraph: {
    title: "OmniPanel — Unified Proxy Runtime & Node Control Plane",
    description:
      "Fail-closed control plane for Sing-box, Xray, and Hysteria2 runtimes with dual-operator signed desired-state publication, durable metering, and deterministic client subscription compilation.",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="bg-slate-50 font-sans text-slate-900 antialiased selection:bg-indigo-600 selection:text-white">
        {children}
      </body>
    </html>
  );
}
