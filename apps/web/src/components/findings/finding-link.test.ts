// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { inAppFindingLink, isExternalHref, isInAppHref } from "./finding-link";

describe("inAppFindingLink", () => {
  it("passes identity detail and Explore links through", () => {
    expect(inAppFindingLink("/identities/abc")).toBe("/identities/abc");
    expect(inAppFindingLink("/explore?focus=abc&focus_type=identity&direction=out")).toBe(
      "/explore?focus=abc&focus_type=identity&direction=out",
    );
  });

  it("drops empty and external links", () => {
    expect(inAppFindingLink(null)).toBeNull();
    expect(inAppFindingLink("")).toBeNull();
    expect(inAppFindingLink("https://admin.example.com")).toBeNull();
    expect(isExternalHref("https://admin.example.com")).toBe(true);
  });

  it("treats protocol-relative and other non-path hrefs as not in-app", () => {
    for (const href of ["//evil.example/x", "/\\evil.example", "javascript:alert(1)", "findings/1", "mailto:a@b"]) {
      expect(isInAppHref(href)).toBe(false);
      expect(inAppFindingLink(href)).toBeNull();
    }
    expect(isExternalHref("//evil.example/x")).toBe(false);
    expect(isExternalHref("javascript:alert(1)")).toBe(false);
    expect(isInAppHref("/findings/1")).toBe(true);
  });
});
