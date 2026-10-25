// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { afterEach, describe, expect, it, vi } from "vitest";

import { resolveAppOrigin } from "@/lib/app-origin";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("resolveAppOrigin", () => {
  it("reduces a configured URL to its origin", () => {
    expect(resolveAppOrigin(["https://kestrel.example.com"])).toBe(
      "https://kestrel.example.com",
    );
  });

  it("keeps a non-default port", () => {
    expect(resolveAppOrigin(["http://kestrel.internal:3010"])).toBe("http://kestrel.internal:3010");
  });

  it("drops path, query, and fragment", () => {
    expect(resolveAppOrigin(["https://kestrel.example.com/findings?a=1#b"])).toBe(
      "https://kestrel.example.com",
    );
  });

  it("takes the first usable candidate", () => {
    expect(resolveAppOrigin(["https://first.example", "https://second.example"])).toBe(
      "https://first.example",
    );
  });

  it("treats unset and blank candidates as absent", () => {
    expect(resolveAppOrigin([undefined, "", "   ", "https://kestrel.example.com"])).toBe(
      "https://kestrel.example.com",
    );
    expect(resolveAppOrigin([undefined, ""])).toBeNull();
  });

  it("tolerates surrounding whitespace", () => {
    expect(resolveAppOrigin([" https://kestrel.example.com \n"])).toBe(
      "https://kestrel.example.com",
    );
  });

  it("returns null when nothing is configured", () => {
    expect(resolveAppOrigin([])).toBeNull();
  });

  // A bare hostname is the likely operator mistake; it must not silently
  // become a relative-ish URL or a "null" origin in a Location header.
  it("rejects a value that is not an absolute URL, and says so", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(resolveAppOrigin(["kestrel.example.com"])).toBeNull();
    expect(console.warn).toHaveBeenCalledOnce();
  });

  it("rejects a non-http scheme, and says so", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(resolveAppOrigin(["javascript:alert(1)"])).toBeNull();
    expect(console.warn).toHaveBeenCalledOnce();
  });

  it("moves on to the next candidate when one is unusable", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(resolveAppOrigin(["not a url", "https://kestrel.example.com"])).toBe(
      "https://kestrel.example.com",
    );
  });
});
