// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { resolveAppOrigin } from "@/lib/app-origin";
import { NONCE_HEADER, REQUEST_PATH_HEADER, SESSION_COOKIE_NAME } from "@/lib/constants";
import { contentSecurityPolicy, generateNonce, strictTransportSecurity } from "@/lib/csp";
import { loginPath } from "@/lib/login-redirect";

// Resolved once per runtime instance rather than per request, so a
// misconfigured value is warned about once rather than on every anonymous
// hit. See lib/app-origin.ts for why this cannot come from the request.
//
// `request.url` is the wrong base for the login redirect behind a reverse
// proxy. The standalone server builds the URL the proxy sees from the
// address it *binds* (HOSTNAME/PORT), not from the Host header, so a
// container listening on 127.0.0.1:3000 sends the browser to
// `https://localhost:3000/login` whatever host it was actually asked for.
// (Next normally rewrites an absolute same-origin Location to a relative one
// on the way out, which hides this -- but it compares against a URL built
// from the bind address, and 127.0.0.1 is normalized to `localhost` on one
// side of that comparison only, so the rewrite misses and the internal
// origin reaches the browser.)
//
// Emitting a relative `Location` would sidestep host derivation entirely, but
// is not available: Next parses whatever the proxy sets through `NextURL`,
// which has no base to resolve against and throws `TypeError: Invalid URL`,
// turning the redirect into a 500 (verified against Next 15.5.25).
const APP_ORIGIN = resolveAppOrigin([process.env.APP_URL, process.env.NEXT_PUBLIC_APP_URL]);
const HSTS = strictTransportSecurity(APP_ORIGIN);
const DEV = process.env.NODE_ENV === "development";

// Pages reachable without a session: the sign-in form and its MFA step.
// Anchored to whole segments, so "/login-anything" is not exempt.
const PUBLIC_PATH = /^\/login(?:\/|$)/;

function withSecurityHeaders(response: NextResponse, csp: string): NextResponse {
  response.headers.set("Content-Security-Policy", csp);
  if (HSTS) response.headers.set("Strict-Transport-Security", HSTS);
  return response;
}

// A presence-only check -- doesn't validate the token itself, just avoids
// an unnecessary round trip to the API for the common case of "no cookie
// at all". An expired/revoked token still gets caught downstream: any
// page's data fetch will get a 401 from the API and lib/api.ts's
// request() redirects to /login from there. That redirect is relative and
// so is unaffected by any of the above.
//
// Both redirects carry `?next=<path>` so sign-in returns to the page that was
// asked for. request() has no request URL of its own, so the path reaches it
// in REQUEST_PATH_HEADER, set here (overwriting anything the client sent).
//
// Every page also gets a nonce-based Content-Security-Policy (lib/csp.ts),
// including the sign-in pages, which is why those run through here too and
// are exempted from the session check in code rather than by the matcher.
// The policy goes on the request as well as the response: Next reads it from
// the request to stamp the nonce on its own scripts, and the root layout
// reads NONCE_HEADER for the inline boot scripts. Reading the nonce makes
// every page dynamically rendered, which they already were (each one reads
// the session cookie).
export function proxy(request: NextRequest) {
  const nonce = generateNonce();
  const csp = contentSecurityPolicy({ nonce, dev: DEV });
  const search = new URLSearchParams(request.nextUrl.search);
  search.delete("_rsc"); // client-navigation cache buster, not part of the page
  const query = search.toString();
  const requested = `${request.nextUrl.pathname}${query ? `?${query}` : ""}`;
  const hasSession = request.cookies.has(SESSION_COOKIE_NAME);
  if (!hasSession && !PUBLIC_PATH.test(request.nextUrl.pathname)) {
    return withSecurityHeaders(
      NextResponse.redirect(new URL(loginPath(requested), APP_ORIGIN ?? request.url)),
      csp,
    );
  }
  const headers = new Headers(request.headers);
  headers.set(REQUEST_PATH_HEADER, requested);
  headers.set(NONCE_HEADER, nonce);
  headers.set("Content-Security-Policy", csp);
  return withSecurityHeaders(NextResponse.next({ request: { headers } }), csp);
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|favicon.svg|site.webmanifest|brand/).*)",
  ],
};
