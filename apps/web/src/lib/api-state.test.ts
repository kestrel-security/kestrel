// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api";
import { API_UNREACHABLE, isApiUnreachable, isNotInitialized } from "@/lib/api-state";

describe("isNotInitialized", () => {
  it("matches the API's first-run 503s", () => {
    const noOrg = JSON.stringify({ detail: "No organization configured yet -- run `kestrel init` first." });
    const noDb = JSON.stringify({
      detail: "Database is not initialized yet -- run migrations and `kestrel init` first.",
    });
    expect(isNotInitialized(new ApiError(503, noOrg))).toBe(true);
    expect(isNotInitialized(new ApiError(503, noDb))).toBe(true);
  });

  it("does not match other 503s or an unreachable API", () => {
    const worker = JSON.stringify({ detail: "Could not enqueue sync (is the worker/broker running?): x" });
    expect(isNotInitialized(new ApiError(503, worker))).toBe(false);
    expect(isNotInitialized(new ApiError(503, "Service Unavailable"))).toBe(false);
    expect(isNotInitialized(new ApiError(502, "x", API_UNREACHABLE))).toBe(false);
    expect(isNotInitialized(new Error("x"))).toBe(false);
  });
});

describe("isApiUnreachable", () => {
  it("matches only the network-failure marker", () => {
    expect(isApiUnreachable(new ApiError(502, "x", API_UNREACHABLE))).toBe(true);
    expect(isApiUnreachable(new ApiError(502, "Bad Gateway"))).toBe(false);
    expect(isApiUnreachable(null)).toBe(false);
  });
});
