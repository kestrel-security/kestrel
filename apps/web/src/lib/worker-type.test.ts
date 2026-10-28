// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { describeWorkerTypeSource, isWorkerTypeFilter, workerTypeBadge } from "./worker-type";

describe("worker-type", () => {
  it("forwards only known worker types as a filter", () => {
    expect(isWorkerTypeFilter("contractor")).toBe(true);
    expect(isWorkerTypeFilter("wizard")).toBe(false);
    expect(isWorkerTypeFilter(undefined)).toBe(false);
  });

  it("badges contingent workers and guests, not employees or unknowns", () => {
    expect(workerTypeBadge("contractor")).toBe("secondary");
    expect(workerTypeBadge("vendor_or_partner")).toBe("secondary");
    expect(workerTypeBadge("guest")).toBe("outline");
    expect(workerTypeBadge("employee")).toBeNull();
    expect(workerTypeBadge("unknown")).toBeNull();
    expect(workerTypeBadge(null)).toBeNull();
  });

  it("describes where a classification came from", () => {
    expect(describeWorkerTypeSource(null)).toBe("not classified");
    expect(describeWorkerTypeSource("connector")).toBe("from the provider's profile");
    expect(describeWorkerTypeSource("rule:abc")).toBe("from a classification rule");
  });
});
