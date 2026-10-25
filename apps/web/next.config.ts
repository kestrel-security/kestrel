// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { NextConfig } from "next";

// Baseline response headers for every route. The app renders provider-supplied
// strings (finding titles, identity names, connector setup text) and opens
// provider links in new tabs, so it must not be framed and must not leak the
// operator's page URL in the Referer. The Content-Security-Policy (and HSTS)
// are per-request, nonce-based, and set by proxy.ts (see lib/csp.ts).
const SECURITY_HEADERS = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Emits .next/standalone with a self-contained server.js and only the
  // production node_modules it actually traced. Lets the Docker image ship
  // just that output instead of the whole workspace plus pnpm and the build
  // toolchain -- see deployments/docker/web.Dockerfile.
  output: "standalone",
  async headers() {
    return [{ source: "/(.*)", headers: SECURITY_HEADERS }];
  },
  // Today's UI kit (Radix, lucide, recharts) is barrel-exported.
  // Without this, webpack/turbopack walk thousands of unused modules on
  // every compile — the main reason `next dev` felt frozen after the
  // dashboard + shadcn work.
  experimental: {
    optimizePackageImports: [
      "lucide-react",
      "recharts",
      "@radix-ui/react-checkbox",
      "@radix-ui/react-dialog",
      "@radix-ui/react-dropdown-menu",
      "@radix-ui/react-label",
      "@radix-ui/react-popover",
      "@radix-ui/react-scroll-area",
      "@radix-ui/react-select",
      "@radix-ui/react-separator",
      "@radix-ui/react-slot",
      "@radix-ui/react-tabs",
      "@radix-ui/react-tooltip",
    ],
  },
};

export default nextConfig;
