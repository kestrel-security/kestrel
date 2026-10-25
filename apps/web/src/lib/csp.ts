// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Content-Security-Policy for every page, built per request by proxy.ts
 * with a fresh nonce (Next's documented nonce pattern). Edge-safe: no Node
 * imports.
 *
 * - Scripts: only those carrying the nonce, and what they load
 *   ('strict-dynamic'). Next stamps the nonce on its own scripts when it sees
 *   this header on the request; the theme and sidebar boot scripts get it from
 *   the root layout. Dev adds 'unsafe-eval' for React's dev tooling and HMR.
 * - Styles: 'unsafe-inline'. Monaco, Recharts and React Flow set inline
 *   styles and inject <style> tags; nonce-ing those is not possible.
 * - Workers: Monaco's bundled module workers are same-origin chunks.
 * - Images and fonts: the app ships its own; data:/blob: cover inline SVG
 *   icons, Monaco's codicon font and generated images.
 * - No framing, no plugins, and forms post only to this origin.
 */
export function contentSecurityPolicy({ nonce, dev }: { nonce: string; dev: boolean }): string {
  const directives: Record<string, string[]> = {
    "default-src": ["'self'"],
    "script-src": ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(dev ? ["'unsafe-eval'"] : [])],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'", "data:"],
    "connect-src": ["'self'", ...(dev ? ["ws:"] : [])],
    "worker-src": ["'self'", "blob:"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "object-src": ["'none'"],
  };
  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(" ")}`)
    .join("; ");
}

/** A per-request nonce: 128 random bits, base64. */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Strict-Transport-Security for a deployment whose public origin is HTTPS.
 * Null otherwise: on plain HTTP (local dev, a LAN install) the header is
 * ignored at best and, once a browser has seen it on an https hop, would lock
 * the host out of plain HTTP. No includeSubDomains: the operator's other hosts
 * are not ours to pin.
 */
export function strictTransportSecurity(appOrigin: string | null | undefined): string | null {
  return appOrigin?.startsWith("https://") ? "max-age=31536000" : null;
}
