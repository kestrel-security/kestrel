// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { absoluteTime, relativeTime } from "./utils";

const NOW = new Date("2026-09-04T12:00:00.000Z");

describe("relativeTime", () => {
  it("returns an em dash for a missing value", () => {
    expect(relativeTime(null, NOW)).toBe("—");
    expect(relativeTime(undefined, NOW)).toBe("—");
    expect(relativeTime("", NOW)).toBe("—");
  });

  it("returns an em dash for an unparseable value rather than Invalid Date", () => {
    expect(relativeTime("not a timestamp", NOW)).toBe("—");
  });

  it("collapses the last minute to 'just now'", () => {
    expect(relativeTime("2026-09-04T11:59:30.000Z", NOW)).toBe("just now");
  });

  it("describes minutes, hours, and days in the past", () => {
    expect(relativeTime("2026-09-04T11:56:00.000Z", NOW)).toBe("4 minutes ago");
    expect(relativeTime("2026-09-04T09:00:00.000Z", NOW)).toBe("3 hours ago");
    expect(relativeTime("2026-09-01T12:00:00.000Z", NOW)).toBe("3 days ago");
  });

  it("describes a future timestamp without pretending it is past", () => {
    expect(relativeTime("2026-09-04T13:00:00.000Z", NOW)).toBe("in 1 hour");
  });

  it("accepts a Date as well as an ISO string", () => {
    expect(relativeTime(new Date("2026-09-04T11:00:00.000Z"), NOW)).toBe("1 hour ago");
  });
});

describe("relativeTime fallback", () => {
  it("uses the caller's fallback for a missing value", () => {
    expect(relativeTime(null, NOW, "Never")).toBe("Never");
  });
});

describe("absoluteTime", () => {
  it("is undefined for a missing or unparseable value", () => {
    expect(absoluteTime(null)).toBeUndefined();
    expect(absoluteTime("not a timestamp")).toBeUndefined();
  });

  it("renders a full local timestamp for a real value", () => {
    const out = absoluteTime("2026-09-04T12:00:00.000Z");
    expect(out).toBeTypeOf("string");
    expect(out).toMatch(/2026/);
  });
});
