// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
// The public origin this deployment is reached on, taken from configuration
// rather than from the request.
//
// Anything that has to build an absolute URL for the browser needs this.
// A request cannot supply it: behind a reverse proxy the only request-side
// evidence of the public host is `Host` / `X-Forwarded-Host`, and both are
// attacker-controlled -- a proxy that forwards them verbatim, or any client
// that reaches the app port directly, can set them to whatever it likes.
// Reflecting one into a `Location` header is an open redirect, so the value
// comes from an operator-set environment variable instead.

/**
 * First candidate that parses as an absolute http(s) URL, reduced to its
 * origin (scheme + host + port). Returns null when nothing is configured,
 * leaving the caller to fall back to the request's own origin -- correct for
 * local development, where the app is reached directly at the address it
 * binds.
 *
 * Blank candidates are skipped silently (an unset variable and a variable set
 * to "" mean the same thing to an operator). A non-blank candidate that does
 * not parse is a misconfiguration and is reported, not swallowed: it is the
 * only signal the operator gets that their setting is being ignored.
 */
export function resolveAppOrigin(candidates: (string | undefined)[]): string | null {
  for (const candidate of candidates) {
    if (!candidate || !candidate.trim()) {
      continue;
    }
    let parsed: URL;
    try {
      parsed = new URL(candidate.trim());
    } catch {
      console.warn(`Ignoring configured app URL ${JSON.stringify(candidate)}: not a valid URL.`);
      continue;
    }
    // A URL like `javascript:...` or `mailto:...` parses but has no usable
    // origin ("null"), and would put a nonsense value in a Location header.
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      console.warn(
        `Ignoring configured app URL ${JSON.stringify(candidate)}: expected an http(s) URL.`,
      );
      continue;
    }
    return parsed.origin;
  }
  return null;
}
