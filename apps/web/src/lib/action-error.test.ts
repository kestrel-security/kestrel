// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { redirect } from "next/navigation";
import { describe, expect, it } from "vitest";

import { formatActionError, validationDetailMessage } from "@/lib/action-error";
import { ApiError } from "@/lib/api";

function redirectError(): unknown {
  try {
    redirect("/login");
  } catch (err) {
    return err;
  }
  throw new Error("redirect() did not throw");
}

describe("formatActionError", () => {
  it("rethrows Next's redirect so the action still navigates", () => {
    const err = redirectError();
    expect(() => formatActionError(err)).toThrow(err as Error);
  });

  it("returns a string detail", () => {
    expect(formatActionError(new ApiError(400, '{"detail":"Bad cron"}'))).toBe("Bad cron");
  });

  it("joins FastAPI validation messages", () => {
    const body = JSON.stringify({
      detail: [
        { loc: ["body", "name"], msg: "Field required", type: "missing" },
        { loc: ["body", "url"], msg: "Input should be a valid URL", type: "url_parsing" },
      ],
    });
    expect(formatActionError(new ApiError(422, body))).toBe(
      "Field required; Input should be a valid URL",
    );
  });

  it("reads a structured detail message", () => {
    const body = JSON.stringify({ detail: { code: "x", message: "Nope" } });
    expect(formatActionError(new ApiError(403, body))).toBe("Nope");
  });

  it("never returns a raw JSON body", () => {
    expect(formatActionError(new ApiError(500, '{"error":"boom"}'))).toBe("Request failed");
    expect(formatActionError(new ApiError(422, '{"detail":[]}'))).toBe("Request failed");
  });

  it("passes plain-text bodies through", () => {
    expect(formatActionError(new ApiError(502, "Bad Gateway"))).toBe("Bad Gateway");
  });

  it("maps rate limits and unknown errors", () => {
    expect(formatActionError(new ApiError(429, "{}"))).toMatch(/Rate limit/);
    expect(formatActionError(new Error("x"))).toBe("Request failed");
  });
});

describe("validationDetailMessage", () => {
  it("is null for non-list details", () => {
    expect(validationDetailMessage("x")).toBeNull();
    expect(validationDetailMessage([{ nope: 1 }])).toBeNull();
  });
});
