// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { utcTime } from "./local-time";

describe("utcTime", () => {
  it("renders the same string regardless of the process timezone", () => {
    expect(utcTime("2026-10-05T14:03:59.123Z", "datetime")).toBe("2026-10-05 14:03 UTC");
    expect(utcTime("2026-10-05T23:30:00-02:00", "datetime")).toBe("2026-10-06 01:30 UTC");
  });

  it("drops the time for date-only values", () => {
    expect(utcTime("2026-10-05T14:03:59Z", "date")).toBe("2026-10-05");
  });

  it("uses the absolute form for relative values until the browser takes over", () => {
    expect(utcTime(new Date("2026-01-02T03:04:05Z"), "relative")).toBe("2026-01-02 03:04 UTC");
  });
});
