// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

// The internal URL a standalone server hands the proxy behind a reverse
// proxy: the address the container binds, never the host the browser asked
// for. Every request below carries the public host in the headers a proxy
// would set, so a `localhost` Location means the host was derived from the
// wrong place.
const INTERNAL_URL = "http://localhost:3000/findings";
const PUBLIC_HOST = "kestrel.example.com";

function proxiedRequest(headers: Record<string, string> = {}) {
  return new NextRequest(INTERNAL_URL, {
    headers: {
      host: PUBLIC_HOST,
      "x-forwarded-host": PUBLIC_HOST,
      "x-forwarded-proto": "https",
      ...headers,
    },
  });
}

// proxy.ts reads the configured origin once, at module scope, so each
// case needs a fresh module registry with its own environment.
async function loadProxy(env: Record<string, string | undefined>) {
  vi.resetModules();
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) {
      vi.stubEnv(key, "");
      delete process.env[key];
    } else {
      vi.stubEnv(key, value);
    }
  }
  return (await import("@/proxy")).proxy;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("proxy", () => {
  it("sends an anonymous request to the login page", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const response = proxy(proxiedRequest());

    expect(response.status).toBe(307);
    expect(new URL(response.headers.get("location")!).pathname).toBe("/login");
  });

  // The regression this file exists for: the deployed app redirected every
  // anonymous request to https://localhost:3000/login, which no browser can
  // follow, making sign-in impossible.
  it("does not redirect to the address the server binds", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const location = new URL(proxy(proxiedRequest()).headers.get("location")!);

    expect(location.hostname).not.toBe("localhost");
    expect(location.origin).toBe(`https://${PUBLIC_HOST}`);
  });

  it("keeps the configured origin when a request forges a forwarded host", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const location = new URL(
      proxy(
        proxiedRequest({ host: "evil.example", "x-forwarded-host": "evil.example" }),
      ).headers.get("location")!,
    );

    expect(location.origin).toBe(`https://${PUBLIC_HOST}`);
  });

  // Unconfigured, the redirect is same-origin with the request as the server
  // saw it -- correct when the app is reached directly, and still never a
  // host taken from a header.
  it("never reflects a forwarded host when no origin is configured", async () => {
    const proxy = await loadProxy({ APP_URL: undefined, NEXT_PUBLIC_APP_URL: undefined });

    const location = new URL(
      proxy(
        proxiedRequest({ host: "evil.example", "x-forwarded-host": "evil.example" }),
      ).headers.get("location")!,
    );

    expect(location.origin).toBe(new URL(INTERNAL_URL).origin);
  });

  it("falls back to NEXT_PUBLIC_APP_URL when APP_URL is unset", async () => {
    const proxy = await loadProxy({
      APP_URL: undefined,
      NEXT_PUBLIC_APP_URL: `https://${PUBLIC_HOST}`,
    });

    const location = new URL(proxy(proxiedRequest()).headers.get("location")!);

    expect(location.origin).toBe(`https://${PUBLIC_HOST}`);
  });

  it("falls back to the request origin when the configured URL is unusable", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const proxy = await loadProxy({
      APP_URL: "kestrel.example.com",
      NEXT_PUBLIC_APP_URL: undefined,
    });

    const location = new URL(proxy(proxiedRequest()).headers.get("location")!);

    expect(location.origin).toBe(new URL(INTERNAL_URL).origin);
    expect(console.warn).toHaveBeenCalledOnce();
  });

  it("lets a request carrying a session cookie through", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const response = proxy(proxiedRequest({ cookie: "kestrel_session=token" }));

    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
  });

  it("asks the login page to return to the requested path", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const response = proxy(
      new NextRequest("http://localhost:3000/findings?status=open&_rsc=abc", {
        headers: { host: PUBLIC_HOST },
      }),
    );

    const location = new URL(response.headers.get("location")!);
    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("next")).toBe("/findings?status=open");
  });

  it("forwards the requested path to server code for its own 401 redirect", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const response = proxy(
      proxiedRequest({ cookie: "kestrel_session=token", "x-kestrel-request-path": "//evil.example" }),
    );

    expect(response.headers.get("x-middleware-request-x-kestrel-request-path")).toBe("/findings");
  });

  it("skips the session check on the sign-in pages, including the MFA step, but guards MFA setup", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });
    const anonymous = (path: string) =>
      proxy(new NextRequest(`http://localhost:3000${path}`, { headers: { host: PUBLIC_HOST } }));

    expect(anonymous("/login").status).toBe(200);
    expect(anonymous("/login?next=%2Ffindings").status).toBe(200);
    expect(anonymous("/login/mfa").status).toBe(200);
    expect(anonymous("/mfa/setup").status).toBe(307);
    expect(anonymous("/dashboard").status).toBe(307);
    // Only the whole segment is exempt.
    expect(anonymous("/loginfoo").status).toBe(307);
    expect(anonymous("/login-admin").status).toBe(307);
  });

  it("runs on pages, including sign-in, but not on static assets", async () => {
    const { config } = await import("@/proxy");
    // Next anchors each matcher source to the whole pathname.
    const matches = (path: string) =>
      config.matcher.some((source) => new RegExp(`^${source}$`).test(path));

    expect(matches("/login")).toBe(true);
    expect(matches("/login/mfa")).toBe(true);
    expect(matches("/dashboard")).toBe(true);
    expect(matches("/_next/static/chunks/app.js")).toBe(false);
    expect(matches("/brand/kestrel-mark-color.svg")).toBe(false);
  });

  it("sets a nonce-based CSP on the response and the request", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const response = proxy(proxiedRequest({ cookie: "kestrel_session=token" }));

    const csp = response.headers.get("content-security-policy")!;
    const nonce = response.headers.get("x-middleware-request-x-nonce")!;
    expect(nonce).toBeTruthy();
    expect(csp).toContain(`'nonce-${nonce}'`);
    expect(response.headers.get("x-middleware-request-content-security-policy")).toBe(csp);
    expect(response.headers.get("strict-transport-security")).toBe("max-age=31536000");
  });

  it("issues a fresh nonce per request and overwrites a client-sent one", async () => {
    const proxy = await loadProxy({ APP_URL: `https://${PUBLIC_HOST}` });

    const first = proxy(proxiedRequest({ cookie: "kestrel_session=token", "x-nonce": "forged" }));
    const second = proxy(proxiedRequest({ cookie: "kestrel_session=token" }));

    const a = first.headers.get("x-middleware-request-x-nonce");
    expect(a).not.toBe("forged");
    expect(a).not.toBe(second.headers.get("x-middleware-request-x-nonce"));
  });

  it("omits HSTS for a plain-http origin", async () => {
    const proxy = await loadProxy({ APP_URL: "http://localhost:3000" });

    const response = proxy(proxiedRequest({ cookie: "kestrel_session=token" }));

    expect(response.headers.get("strict-transport-security")).toBeNull();
    expect(response.headers.get("content-security-policy")).toContain("default-src 'self'");
  });
});
