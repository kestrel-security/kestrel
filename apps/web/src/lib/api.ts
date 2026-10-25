// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { cookies, headers as requestHeaders } from "next/headers";
import { redirect, unstable_rethrow } from "next/navigation";
import { cache } from "react";

import { API_UNREACHABLE, API_UNREACHABLE_STATUS } from "@/lib/api-state";
import { resolveAppOrigin } from "@/lib/app-origin";
import { REQUEST_PATH_HEADER, SESSION_COOKIE_NAME } from "@/lib/constants";
import { loginPath, safeNextPath } from "@/lib/login-redirect";
import { apiErrorCode, withNext } from "@/lib/mfa";
import { isSlug, isUuid } from "@/lib/route-params";

// Server-only (no NEXT_PUBLIC_ prefix): every fetch in this app runs from a
// Server Component or Server Action, never the browser bundle, so the app
// always reaches the API over whatever URL is valid *from the Next.js
// server's own network position* -- localhost:8010 when running `next dev`
// directly on the host, or http://api:8000/api/v1 inside docker-compose
// (set via API_URL in .env), where "localhost" would otherwise resolve to
// the web container itself rather than the api container.
//
// The API only ever sees a bearer token, never the browser's cookie --
// this is what makes CSRF tractable (see apps/api's OriginCheckMiddleware
// docstring): a cross-site request can't forge the Authorization header
// the way it auto-attaches cookies.
export const API_BASE_URL = process.env.API_URL ?? "http://localhost:8010/api/v1";

/** Absolute API URL for `path` (which starts with `/`). Route handlers that
 * proxy downloads use this instead of re-reading API_URL themselves. */
export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`;
}

/** Where a route handler sends an anonymous or expired session. Built from
 * the configured public origin, never `request.url`: behind a reverse proxy
 * the latter is the container's bind address (see proxy.ts). */
export function loginRedirectUrl(request: { url: string }, next?: string | null): URL {
  const origin = resolveAppOrigin([process.env.APP_URL, process.env.NEXT_PUBLIC_APP_URL]);
  return new URL(loginPath(next), origin ?? request.url);
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** Set by this client for failures with no API response (see lib/api-state.ts). */
    public code?: string,
  ) {
    super(message);
  }
}

const NOT_FOUND_BODY = JSON.stringify({ detail: "Not found" });

/**
 * A record id (UUID) as one URL path segment for an API call. Every id the
 * API takes in a path is a UUID; anything else -- "..", "a/b", a stray "?" --
 * would retarget the request, so it never reaches the URL. Throws the 404 the
 * API would give for an unknown id, so pages map it to notFound() and actions
 * report it like any other API error.
 */
export function segment(id: string): string {
  if (typeof id !== "string" || !isUuid(id)) {
    throw new ApiError(404, NOT_FOUND_BODY);
  }
  return encodeURIComponent(id);
}

/** segment() for the one non-UUID path identifier: a policy pack name. */
export function slugSegment(name: string): string {
  if (typeof name !== "string" || !isSlug(name)) {
    throw new ApiError(404, NOT_FOUND_BODY);
  }
  return encodeURIComponent(name);
}

/**
 * `.catch` handler for optional data a page can render without: `value` on a
 * failed API call, while Next's own control flow -- the `redirect()` request()
 * issues for an expired session or MFA enrolment, `notFound()` -- still
 * propagates instead of being swallowed into the fallback.
 */
export function orFallback<T>(value: T): (err: unknown) => T {
  return (err: unknown) => {
    unstable_rethrow(err);
    return value;
  };
}

export async function clientForwardedFor(): Promise<string | null> {
  try {
    const incoming = await requestHeaders();
    const value = incoming.get("x-forwarded-for");
    return value && value.length <= 1024 ? value : null;
  } catch {
    // Outside a request scope (build-time render): nothing to forward.
    return null;
  }
}

// For route handlers that call the API with their own fetch: the same
// X-Forwarded-For `request` sends (see the comment there).
export async function forwardedForHeader(): Promise<Record<string, string>> {
  const value = await clientForwardedFor();
  return value ? { "X-Forwarded-For": value } : {};
}

// On these a 401 is the endpoint's own answer (a wrong password; a spent MFA
// challenge), which the caller handles, not "your session is gone".
const OWN_401_PATHS = new Set(["/auth/login", "/auth/login/mfa"]);

/**
 * `bearer` replaces the session cookie as the credential, for the one call
 * made with something else (the MFA challenge token on /auth/login/mfa).
 */
async function request<T>(path: string, init?: RequestInit, bearer?: string): Promise<T> {
  const cookieStore = await cookies();
  const token = bearer ?? cookieStore.get(SESSION_COOKIE_NAME)?.value;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  // Every call reaches the API from this server, so without this the API
  // would see one client IP for all users: login and pre-auth rate limits
  // would be one shared bucket. Next sets X-Forwarded-For to the socket peer
  // when no proxy did; a reverse proxy in front appends the address it saw.
  // The API honours the header only from KESTREL_TRUSTED_PROXIES and reads
  // it right to left, so with a proxy in front a browser-injected value is
  // ignored. Next keeps a client-supplied header as is, which is one more
  // reason not to expose it without a proxy (docs/deployment.md).
  const forwardedFor = await clientForwardedFor();
  if (forwardedFor) {
    headers["X-Forwarded-For"] = forwardedFor;
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers,
      cache: "no-store",
    });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    // The internal address and the socket error belong in the server log, not
    // in a page anyone holding a cookie can render.
    console.error(`Cannot reach the API at ${API_BASE_URL}: ${detail}`);
    // Not a 503: that is the API's own "not initialized" answer, and pages
    // map it to the run-`kestrel init` screen (lib/api-state.ts).
    throw new ApiError(
      API_UNREACHABLE_STATUS,
      "The Kestrel API is not reachable from the web server. Check that the api service is running and that API_URL points at it (see the web server log for the address tried).",
      API_UNREACHABLE,
    );
  }

  // On /auth/login a 401 means "wrong password",
  // not "you're not logged in" -- it must not trigger this redirect, or a
  // mistyped password would silently bounce to the login page instead of
  // showing an error.
  if (response.status === 401 && !OWN_401_PATHS.has(path)) {
    redirect(loginPath((await requestHeaders()).get(REQUEST_PATH_HEADER)));
  }

  if (!response.ok) {
    const body = await response.text();
    // A session the organization's MFA requirement limited to enrolment:
    // every route but /auth/me, logout and the setup routes answers it with
    // this 403, so whatever page asked, the operator belongs on /mfa/setup.
    if (response.status === 403 && !bearer && apiErrorCode(body) === "mfa_enrollment_required") {
      redirect(withNext("/mfa/setup", safeNextPath((await requestHeaders()).get(REQUEST_PATH_HEADER))));
    }
    throw new ApiError(response.status, body || response.statusText);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

// Layout + page + settings layout all call GET /auth/me (and other GETs)
// during one RSC render. `cache: "no-store"` disables the Next fetch cache,
// so without React.cache those become N sequential HTTP round-trips.
const getOnce = cache((path: string) => request<unknown>(path));

export const api = {
  get: <T>(path: string) => getOnce(path) as Promise<T>,
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  /** A POST authenticated by `token` instead of the session cookie. */
  postWithToken: <T>(path: string, token: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }, token),
};
