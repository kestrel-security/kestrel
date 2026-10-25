// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { contentSecurityPolicy, generateNonce, strictTransportSecurity } from "@/lib/csp";

function directives(policy: string): Map<string, string[]> {
  return new Map(
    policy.split(";").map((part) => {
      const [name, ...values] = part.trim().split(/\s+/);
      return [name, values] as const;
    }),
  );
}

describe("contentSecurityPolicy", () => {
  it("allows only nonce'd scripts in production", () => {
    const d = directives(contentSecurityPolicy({ nonce: "abc123", dev: false }));
    expect(d.get("script-src")).toEqual(["'self'", "'nonce-abc123'", "'strict-dynamic'"]);
    expect(d.get("default-src")).toEqual(["'self'"]);
    expect(d.get("frame-ancestors")).toEqual(["'none'"]);
    expect(d.get("object-src")).toEqual(["'none'"]);
    expect(d.get("base-uri")).toEqual(["'self'"]);
    expect(d.get("form-action")).toEqual(["'self'"]);
    expect(d.get("worker-src")).toEqual(["'self'", "blob:"]);
    expect(d.get("connect-src")).toEqual(["'self'"]);
  });

  it("adds 'unsafe-eval' only in development", () => {
    expect(contentSecurityPolicy({ nonce: "n", dev: false })).not.toContain("unsafe-eval");
    expect(directives(contentSecurityPolicy({ nonce: "n", dev: true })).get("script-src")).toContain(
      "'unsafe-eval'",
    );
  });

  it("names no third-party origin", () => {
    expect(contentSecurityPolicy({ nonce: "n", dev: false })).not.toMatch(/https?:/);
  });
});

describe("generateNonce", () => {
  it("is fresh, base64 and long enough", () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9+/]{22}==$/);
  });
});

describe("strictTransportSecurity", () => {
  it("is set only for an https origin", () => {
    expect(strictTransportSecurity("https://kestrel.example.com")).toBe("max-age=31536000");
    expect(strictTransportSecurity("http://localhost:3000")).toBeNull();
    expect(strictTransportSecurity(null)).toBeNull();
  });
});
