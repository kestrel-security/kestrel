// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  resolveAppMark,
  resolveAppMarkFromNode,
  resolveAppMarksFromTypes,
} from "./app-mark";

describe("resolveAppMark", () => {
  it("maps connector application_type to vendor marks", () => {
    for (const [type, key] of [
      ["github", "github"],
      ["slack", "slack"],
      ["okta", "okta"],
      ["google_workspace", "google_workspace"],
      ["microsoft_365", "microsoft_365"],
      ["gws", "google_workspace"],
      ["entra", "microsoft_365"],
    ] as const) {
      const mark = resolveAppMark({ applicationType: type });
      expect(mark.kind).toBe("vendor");
      if (mark.kind === "vendor") expect(mark.key).toBe(key);
    }
  });

  it("prefers OAuth name aliases over the IdP application_type", () => {
    const mark = resolveAppMark({
      nodeType: "oauth_application",
      applicationType: "okta",
      label: "Slack",
    });
    expect(mark.kind).toBe("vendor");
    if (mark.kind === "vendor") expect(mark.key).toBe("slack");
  });

  it("matches GitHub / Microsoft aliases on OAuth names", () => {
    const gh = resolveAppMark({
      nodeType: "oauth_application",
      applicationType: "okta",
      name: "GitHub Enterprise",
    });
    expect(gh.kind).toBe("vendor");
    if (gh.kind === "vendor") expect(gh.key).toBe("github");

    const m365 = resolveAppMark({
      nodeType: "oauth_application",
      applicationType: "okta",
      label: "Office 365",
    });
    expect(m365.kind).toBe("vendor");
    if (m365.kind === "vendor") expect(m365.key).toBe("microsoft_365");
  });

  it("falls back to letter-mark for custom / unknown", () => {
    const mark = resolveAppMark({
      applicationType: "custom",
      label: "Harbor Ledger",
    });
    expect(mark).toEqual({ kind: "letter", letter: "H", label: "Harbor Ledger" });
  });

  it("letter-marks unrecognized OAuth apps still on Okta", () => {
    const mark = resolveAppMark({
      nodeType: "oauth_application",
      applicationType: "okta",
      label: "Acme Internal Tool",
    });
    // No alias → fall through to application_type (Okta IdP stamp).
    expect(mark.kind).toBe("vendor");
    if (mark.kind === "vendor") expect(mark.key).toBe("okta");
  });

  it("uses publisher when application_type is missing on OAuth apps", () => {
    const mark = resolveAppMark({
      nodeType: "oauth_application",
      label: "Kestrel Lab Chat",
      publisher: "okta",
    });
    expect(mark.kind).toBe("vendor");
    if (mark.kind === "vendor") expect(mark.key).toBe("okta");
  });

  it("defaults the label to 'App' and letter-marks it when nothing is given", () => {
    const mark = resolveAppMark({});
    expect(mark).toEqual({ kind: "letter", letter: "A", label: "App" });
  });

  it("strips non-alphanumeric characters before taking the first letter", () => {
    const mark = resolveAppMark({ applicationType: "custom", label: "  (unlisted) tool" });
    // asString() trims the label before it becomes the display label.
    expect(mark).toEqual({ kind: "letter", letter: "U", label: "(unlisted) tool" });
  });
});

describe("resolveAppMarksFromTypes", () => {
  it("dedupes and reports overflow", () => {
    const { marks, overflow } = resolveAppMarksFromTypes(
      ["github", "okta", "slack", "google_workspace", "github"],
      3,
    );
    expect(marks.length).toBe(3);
    expect(overflow).toBe(1);
  });

  it("returns no marks and no overflow for an empty/undefined list", () => {
    expect(resolveAppMarksFromTypes(undefined)).toEqual({ marks: [], overflow: 0 });
    expect(resolveAppMarksFromTypes([])).toEqual({ marks: [], overflow: 0 });
  });

  it("dedupes letter marks by their letter, not by input string", () => {
    const { marks, overflow } = resolveAppMarksFromTypes(["custom-crm", "custom-cms"], 5);
    // Both fall back to a "C" letter mark and should collapse to one.
    expect(marks.length).toBe(1);
    expect(overflow).toBe(0);
  });
});

describe("resolveAppMarkFromNode", () => {
  it("reads application_type from properties", () => {
    const mark = resolveAppMarkFromNode({
      nodeType: "role",
      label: "org:admin",
      properties: { application_type: "github" },
    });
    expect(mark.kind).toBe("vendor");
    if (mark.kind === "vendor") expect(mark.key).toBe("github");
  });

  it("tolerates missing/null properties", () => {
    const mark = resolveAppMarkFromNode({
      nodeType: "setting",
      label: "Some Setting",
      properties: null,
    });
    expect(mark).toEqual({ kind: "letter", letter: "S", label: "Some Setting" });
  });
});
