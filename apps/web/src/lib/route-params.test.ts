// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { dashboardExportFormat, isSlug, isUuid } from "./route-params";

describe("isUuid", () => {
  it("accepts a UUID in either case", () => {
    expect(isUuid("0b6f4c1e-2a7d-4c8e-9f10-1a2b3c4d5e6f")).toBe(true);
    expect(isUuid("0B6F4C1E-2A7D-4C8E-9F10-1A2B3C4D5E6F")).toBe(true);
  });

  it("rejects anything that could change the upstream path", () => {
    expect(isUuid("../packs/core/disable?")).toBe(false);
    expect(isUuid("0b6f4c1e-2a7d-4c8e-9f10-1a2b3c4d5e6f/../x")).toBe(false);
    expect(isUuid("")).toBe(false);
  });
});

describe("isSlug", () => {
  it("accepts pack names", () => {
    expect(isSlug("okta-posture")).toBe(true);
    expect(isSlug("cross-app")).toBe(true);
  });

  it("rejects path-changing names", () => {
    expect(isSlug("..")).toBe(false);
    expect(isSlug("a/b")).toBe(false);
    expect(isSlug("a?b")).toBe(false);
    expect(isSlug("")).toBe(false);
  });
});

describe("dashboardExportFormat", () => {
  it("defaults to PDF and passes known formats through", () => {
    expect(dashboardExportFormat(null)).toBe("pdf");
    expect(dashboardExportFormat("csv")).toBe("csv");
  });

  it("rejects unknown formats", () => {
    expect(dashboardExportFormat("pdf&x=1")).toBeNull();
    expect(dashboardExportFormat("webhook")).toBeNull();
  });
});
