// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
// Whether the session cookie carries the `Secure` attribute.
//
// A Secure cookie is only sent over HTTPS (browsers make an exception for
// `localhost`). Always setting it in production silently broke sign-in for
// anyone evaluating Kestrel over plain HTTP on a LAN address or hostname: the
// login succeeded, the browser dropped the cookie, and the next request
// bounced back to /login with no error.
//
// So the flag follows the deployment's own public origin. `APP_URL` is what
// browsers use to reach the app, which makes its scheme the right signal: an
// https origin gets a Secure cookie, an http one does not. Production behind
// TLS -- the only supported way to run Kestrel for real -- is unchanged.

type CookieEnv = {
  KESTREL_COOKIE_SECURE?: string;
  APP_URL?: string;
  NODE_ENV?: string;
};

const TRUE = new Set(["1", "true", "yes", "on"]);
const FALSE = new Set(["0", "false", "no", "off"]);

/**
 * In order: an explicit `KESTREL_COOKIE_SECURE`; then the scheme of
 * `APP_URL`; then `NODE_ENV === "production"`, the previous behaviour. An
 * unrecognised override value is ignored with a warning rather than guessed at.
 */
export function sessionCookieSecure(env: CookieEnv): boolean {
  const override = env.KESTREL_COOKIE_SECURE?.trim().toLowerCase();
  if (override) {
    if (TRUE.has(override)) return true;
    if (FALSE.has(override)) return false;
    console.warn(
      `Ignoring KESTREL_COOKIE_SECURE=${JSON.stringify(env.KESTREL_COOKIE_SECURE)}: expected true or false.`,
    );
  }
  const appUrl = env.APP_URL?.trim();
  if (appUrl) {
    try {
      const protocol = new URL(appUrl).protocol;
      if (protocol === "https:") return true;
      if (protocol === "http:") return false;
    } catch {
      // Not a URL; resolveAppOrigin already warns about it.
    }
  }
  return env.NODE_ENV === "production";
}
