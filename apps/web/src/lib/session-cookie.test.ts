// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it, vi } from "vitest";

import { sessionCookieSecure } from "@/lib/session-cookie";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("sessionCookieSecure", () => {
  it("is secure for an https public origin", () => {
    expect(
      sessionCookieSecure({
        APP_URL: "https://kestrel.example.com",
        NODE_ENV: "production",
      }),
    ).toBe(true);
  });

  it("is not secure for an http public origin, even in production", () => {
    expect(
      sessionCookieSecure({
        APP_URL: "http://192.168.1.20:3000",
        NODE_ENV: "production",
      }),
    ).toBe(false);
  });

  it("lets an explicit override win over APP_URL", () => {
    expect(
      sessionCookieSecure({
        KESTREL_COOKIE_SECURE: "true",
        APP_URL: "http://kestrel.lan:3000",
      }),
    ).toBe(true);
    expect(
      sessionCookieSecure({
        KESTREL_COOKIE_SECURE: "false",
        APP_URL: "https://kestrel.example.com",
      }),
    ).toBe(false);
  });

  it("falls back to NODE_ENV when nothing else is configured", () => {
    expect(sessionCookieSecure({ NODE_ENV: "production" })).toBe(true);
    expect(sessionCookieSecure({ NODE_ENV: "development" })).toBe(false);
  });

  it("ignores an unrecognised override with a warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(
      sessionCookieSecure({
        KESTREL_COOKIE_SECURE: "maybe",
        NODE_ENV: "production",
      }),
    ).toBe(true);
    expect(warn).toHaveBeenCalledOnce();
  });

  it("ignores an APP_URL that does not parse", () => {
    expect(
      sessionCookieSecure({ APP_URL: "not a url", NODE_ENV: "production" }),
    ).toBe(true);
  });
});
