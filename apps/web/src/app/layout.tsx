// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from "next";
import { headers } from "next/headers";

import { resolveAppOrigin } from "@/lib/app-origin";
import { NONCE_HEADER } from "@/lib/constants";
import { Inter, JetBrains_Mono } from "next/font/google";

import { SidebarScript } from "@/components/sidebar-script";
import { ThemeScript } from "@/components/theme-script";

import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL(
    resolveAppOrigin([process.env.APP_URL, process.env.NEXT_PUBLIC_APP_URL]) ?? "http://localhost:3000",
  ),
  title: {
    default: "Kestrel",
    template: "%s · Kestrel",
  },
  description: "Open-source security for SaaS.",
  manifest: "/site.webmanifest",
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "32x32", type: "image/x-icon" },
    ],
    shortcut: "/favicon.svg",
    apple: [{ url: "/brand/kestrel-app-icon-light.png", sizes: "512x512", type: "image/png" }],
  },
  openGraph: {
    title: "Kestrel",
    description: "Open-source security for SaaS.",
    siteName: "Kestrel",
    type: "website",
    images: [
      {
        url: "/brand/kestrel-open-graph-dark.png",
        width: 1200,
        height: 630,
        alt: "Kestrel — Open-source security for SaaS.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Kestrel",
    description: "Open-source security for SaaS.",
    images: ["/brand/kestrel-open-graph-dark.png"],
  },
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // The CSP nonce proxy.ts issued for this request (see lib/csp.ts);
  // absent only where the proxy does not run.
  const nonce = (await headers()).get(NONCE_HEADER) ?? undefined;
  return (
    <html lang="en" className={`dark ${inter.variable} ${jetbrainsMono.variable}`} suppressHydrationWarning>
      <body className="min-h-screen font-sans antialiased">
        <ThemeScript nonce={nonce} />
        <SidebarScript nonce={nonce} />
        {children}
      </body>
    </html>
  );
}
