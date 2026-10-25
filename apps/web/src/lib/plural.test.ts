// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { countOf, plural } from "./plural";

describe("plural", () => {
  it("uses the singular only for exactly one", () => {
    expect(plural(1, "hop")).toBe("hop");
    expect(plural(0, "hop")).toBe("hops");
    expect(plural(2, "hop")).toBe("hops");
  });

  it("takes an irregular plural form", () => {
    expect(plural(1, "delivery", "deliveries")).toBe("delivery");
    expect(plural(901, "delivery", "deliveries")).toBe("deliveries");
    expect(plural(3, "match", "matches")).toBe("matches");
  });
});

describe("countOf", () => {
  it("prefixes the count", () => {
    expect(countOf(901, "failed delivery", "failed deliveries")).toBe("901 failed deliveries");
    expect(countOf(1, "endpoint")).toBe("1 endpoint");
    expect(countOf(0, "policy", "policies")).toBe("0 policies");
  });
});
