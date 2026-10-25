// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  DEFAULT_POLICY_TAB,
  POLICY_TABS,
  isPolicyTab,
  parsePolicyTab,
  policyTabHref,
} from "./policy-tabs.ts";

describe("parsePolicyTab", () => {
  it("accepts every declared tab", () => {
    for (const tab of POLICY_TABS) {
      expect(parsePolicyTab(tab)).toBe(tab);
    }
  });

  it("falls back to overview for absent, unknown, or empty input", () => {
    expect(parsePolicyTab(undefined)).toBe(DEFAULT_POLICY_TAB);
    expect(parsePolicyTab("")).toBe(DEFAULT_POLICY_TAB);
    expect(parsePolicyTab("bogus")).toBe(DEFAULT_POLICY_TAB);
    expect(parsePolicyTab("Overview")).toBe(DEFAULT_POLICY_TAB, "is case-sensitive");
  });

  it("takes the first value when Next hands back a repeated param", () => {
    expect(parsePolicyTab(["versions", "code"])).toBe("versions");
    expect(parsePolicyTab([])).toBe(DEFAULT_POLICY_TAB);
  });
});

describe("isPolicyTab", () => {
  it("narrows only known tabs", () => {
    expect(isPolicyTab("code")).toBe(true);
    expect(isPolicyTab("nope")).toBe(false);
    expect(isPolicyTab(undefined)).toBe(false);
    expect(isPolicyTab(42)).toBe(false);
  });
});

describe("policyTabHref", () => {
  it("uses the bare path for overview and ?tab= for the rest", () => {
    expect(policyTabHref("p1", "overview")).toBe("/policies/p1");
    expect(policyTabHref("p1", "versions")).toBe("/policies/p1?tab=versions");
  });

  it("drops one-shot banner params so they do not survive a tab click", () => {
    const current = new URLSearchParams({
      tab: "code",
      evaluated: "1",
      matches: "3",
      status: "success",
      error: "forbidden",
    });
    expect(policyTabHref("p1", "findings", current)).toBe("/policies/p1?tab=findings");
    expect(policyTabHref("p1", "overview", current)).toBe("/policies/p1");
  });

  it("preserves unrelated params across a tab switch", () => {
    const current = new URLSearchParams({ tab: "overview", highlight: "abc" });
    expect(policyTabHref("p1", "code", current)).toBe("/policies/p1?highlight=abc&tab=code");
    expect(policyTabHref("p1", "overview", current)).toBe("/policies/p1?highlight=abc");
  });

  it("replaces rather than appends an existing tab param", () => {
    const current = new URLSearchParams({ tab: "code" });
    const href = policyTabHref("p1", "versions", current);
    expect(href).toBe("/policies/p1?tab=versions");
    expect(new URLSearchParams(href.split("?")[1]).getAll("tab").length).toBe(1);
  });
});
