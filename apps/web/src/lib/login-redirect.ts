// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Where to send the browser after sign-in.
 *
 * The proxy and the API client's 401 handler send anonymous visitors to
 * `/login?next=<path>`; the login action reads `next` back. That value comes
 * from the query string, so anyone can craft a link with it, and following it
 * blindly is an open redirect (`?next=https://evil.example`, or the
 * protocol-relative `//evil.example`). Only a same-origin path survives.
 */

export const DEFAULT_AFTER_LOGIN = "/dashboard";

// Any origin works: a value that resolves somewhere else was not a plain path.
const PROBE_ORIGIN = "http://kestrel.invalid";

/**
 * `raw` as a path to redirect to, or null when it isn't a safe same-origin
 * path. Rejects absolute and protocol-relative URLs, backslashes (browsers
 * treat `/\evil.example` like `//evil.example`), control characters, and
 * `/login` itself so a sign-in can't loop back to the form.
 */
export function safeNextPath(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) return null;
  if (!raw.startsWith("/") || raw.startsWith("//")) return null;
  if (raw.includes("\\")) return null;
  if (/[\u0000-\u001f\u007f]/.test(raw)) return null;
  let url: URL;
  try {
    url = new URL(raw, PROBE_ORIGIN);
  } catch {
    return null;
  }
  if (url.origin !== PROBE_ORIGIN) return null;
  // Normalisation can turn `/.//evil.example` into a protocol-relative path.
  if (url.pathname.startsWith("//")) return null;
  if (url.pathname === "/login" || url.pathname.startsWith("/login/")) return null;
  return `${url.pathname}${url.search}${url.hash}`;
}

/** `/login`, carrying `next` when it is worth returning to. */
export function loginPath(next: string | null | undefined): string {
  const safe = safeNextPath(next);
  if (!safe || safe === "/" || safe === DEFAULT_AFTER_LOGIN) return "/login";
  // The /api/* routes are download and action proxies, not pages; landing on
  // one after sign-in would start a file download instead of showing the app.
  if (safe === "/api" || safe.startsWith("/api/")) return "/login";
  return `/login?${new URLSearchParams({ next: safe }).toString()}`;
}
