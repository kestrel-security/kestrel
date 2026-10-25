// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { localDateTimeToIso, parseExpiresAt } from "@/lib/expiry";

describe("localDateTimeToIso", () => {
  it("reads the value in the local zone", () => {
    const iso = localDateTimeToIso("2026-10-27T09:00");
    expect(iso).not.toBeNull();
    const back = new Date(iso!);
    expect(back.getFullYear()).toBe(2026);
    expect(back.getMonth()).toBe(9);
    expect(back.getDate()).toBe(27);
    expect(back.getHours()).toBe(9);
    expect(iso!.endsWith("Z")).toBe(true);
  });

  it("is null for anything that is not a datetime-local value", () => {
    expect(localDateTimeToIso("")).toBeNull();
    expect(localDateTimeToIso("tomorrow")).toBeNull();
    expect(localDateTimeToIso("2026-13-45T99:99")).toBeNull();
    expect(localDateTimeToIso("2026-10-27")).toBeNull();
  });
});

describe("parseExpiresAt", () => {
  it("treats a blank expiry as none", () => {
    expect(parseExpiresAt("", "")).toEqual({ ok: true, expiresAt: null });
    expect(parseExpiresAt(null)).toEqual({ ok: true, expiresAt: null });
  });

  it("accepts ISO timestamps with an offset", () => {
    expect(parseExpiresAt("2026-10-27T16:00:00.000Z")).toEqual({
      ok: true,
      expiresAt: "2026-10-27T16:00:00.000Z",
    });
    expect(parseExpiresAt("2026-10-27T09:00-07:00")).toEqual({
      ok: true,
      expiresAt: "2026-10-27T16:00:00.000Z",
    });
  });

  it("rejects zone-less or invalid values instead of throwing", () => {
    expect(parseExpiresAt("2026-10-27T09:00").ok).toBe(false);
    expect(parseExpiresAt("garbage").ok).toBe(false);
    expect(parseExpiresAt("2026-02-31T25:00Z").ok).toBe(false);
  });

  it("rejects a local value the browser did not convert", () => {
    expect(parseExpiresAt("", "2026-10-27T09:00").ok).toBe(false);
  });
});
