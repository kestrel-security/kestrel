// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { loginPath, safeNextPath } from "./login-redirect";

describe("safeNextPath", () => {
  it("keeps same-origin paths with their query and hash", () => {
    expect(safeNextPath("/findings")).toBe("/findings");
    expect(safeNextPath("/findings?status=open&severity=high")).toBe(
      "/findings?status=open&severity=high",
    );
    expect(safeNextPath("/policies/abc#source")).toBe("/policies/abc#source");
  });

  it.each([
    ["absolute URL", "https://evil.example/findings"],
    ["protocol-relative URL", "//evil.example"],
    ["backslash trick", "/\\evil.example"],
    ["leading backslash", "\\\\evil.example"],
    ["javascript URL", "javascript:alert(1)"],
    ["relative path", "findings"],
    ["empty string", ""],
    ["tab before host", "/\t/evil.example"],
    ["newline", "/findings\n"],
    ["login page", "/login"],
    ["login with query", "/login?next=/findings"],
    ["dot segment to protocol-relative", "/.//evil.example"],
    ["parent segment to protocol-relative", "/..//evil.example"],
    ["nested parent segment", "/a/..//evil.example"],
    ["encoded dot segment", "/%2e//evil.example"],
  ])("rejects %s", (_label, value) => {
    expect(safeNextPath(value)).toBeNull();
  });

  it("rejects non-strings", () => {
    expect(safeNextPath(undefined)).toBeNull();
    expect(safeNextPath(null)).toBeNull();
    expect(safeNextPath(["/findings"])).toBeNull();
  });

  it("normalises dot segments without leaving the origin", () => {
    expect(safeNextPath("/a/../findings")).toBe("/findings");
    expect(safeNextPath("/../../etc")).toBe("/etc");
  });
});

describe("loginPath", () => {
  it("carries a safe path as next", () => {
    expect(loginPath("/findings?status=open")).toBe("/login?next=%2Ffindings%3Fstatus%3Dopen");
  });

  it("drops unsafe or pointless values", () => {
    expect(loginPath("//evil.example")).toBe("/login");
    expect(loginPath("/")).toBe("/login");
    expect(loginPath("/dashboard")).toBe("/login");
    expect(loginPath(null)).toBe("/login");
  });
});
