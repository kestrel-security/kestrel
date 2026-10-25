// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { notFound, redirect } from "next/navigation";
import { describe, expect, it } from "vitest";

import { ApiError, orFallback, segment, slugSegment } from "@/lib/api";

const ID = "0b6f4c1e-2a7d-4c8e-9f10-1a2b3c4d5e6f";

function caught(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  throw new Error("expected a throw");
}

describe("segment", () => {
  it("passes a UUID through", () => {
    expect(segment(ID)).toBe(ID);
  });

  it("rejects anything else with a 404 ApiError", () => {
    for (const bad of ["", "..", "../packs/core/disable", `${ID}/../x`, `${ID}?x=1`, "a%2Fb"]) {
      const err = caught(() => segment(bad));
      expect(err).toBeInstanceOf(ApiError);
      expect((err as ApiError).status).toBe(404);
    }
  });
});

describe("slugSegment", () => {
  it("passes pack names through", () => {
    expect(slugSegment("okta-posture")).toBe("okta-posture");
    expect(slugSegment("cross_app2")).toBe("cross_app2");
  });

  it("rejects dots, slashes and empty names", () => {
    for (const bad of ["", ".", "..", "a/b", "a.b", "-x", "x?y"]) {
      expect(() => slugSegment(bad)).toThrow(ApiError);
    }
  });
});

describe("orFallback", () => {
  it("returns the fallback for an API error", () => {
    expect(orFallback([])(new ApiError(500, "x"))).toEqual([]);
  });

  it("lets redirect() and notFound() through", () => {
    const redirectErr = caught(() => redirect("/login"));
    expect(() => orFallback(null)(redirectErr)).toThrow(redirectErr as Error);
    const notFoundErr = caught(() => notFound());
    expect(() => orFallback(null)(notFoundErr)).toThrow(notFoundErr as Error);
  });
});
