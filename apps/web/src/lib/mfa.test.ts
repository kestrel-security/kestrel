// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  apiErrorCode,
  formatSecret,
  normalizeMfaCode,
  recoveryCodesText,
  routeAfterEnrolment,
  routeAfterLogin,
  withNext,
} from "./mfa";

describe("normalizeMfaCode", () => {
  it("accepts a 6-digit code, ignoring spaces and dashes", () => {
    expect(normalizeMfaCode("123456")).toEqual({ code: "123456", kind: "totp" });
    expect(normalizeMfaCode(" 123 456 ")).toEqual({ code: "123456", kind: "totp" });
    expect(normalizeMfaCode("123-456")).toEqual({ code: "123456", kind: "totp" });
  });

  it("accepts a recovery code with or without its dash, in any case", () => {
    expect(normalizeMfaCode("abcd-ef23")).toEqual({ code: "abcdef23", kind: "recovery" });
    expect(normalizeMfaCode("ABCD EF23")).toEqual({ code: "abcdef23", kind: "recovery" });
    expect(normalizeMfaCode("abcdef23")).toEqual({ code: "abcdef23", kind: "recovery" });
    // An all-digit recovery code is still 8 long, so it can't pass for a TOTP.
    expect(normalizeMfaCode("2345-6789")).toEqual({ code: "23456789", kind: "recovery" });
  });

  it.each(["", "   ", "12345", "1234567", "abcdef", "abcd-ef2!", "12345a"])(
    "rejects %j",
    (raw) => {
      expect(normalizeMfaCode(raw)).toBeNull();
    },
  );
});

describe("formatSecret", () => {
  it("groups a base32 secret in fours", () => {
    expect(formatSecret("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")).toBe(
      "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP",
    );
  });

  it("leaves a short last group and normalises case and whitespace", () => {
    expect(formatSecret("abcdefghij")).toBe("ABCD EFGH IJ");
    expect(formatSecret(" ABCD EFGH ")).toBe("ABCD EFGH");
    expect(formatSecret("")).toBe("");
  });
});

describe("recoveryCodesText", () => {
  it("lists every code on its own line under a short header", () => {
    const text = recoveryCodesText(["aaaa-bbbb", "cccc-dddd"], {
      account: "admin@kestrel.local",
      generatedAt: new Date("2026-10-06T12:00:00Z"),
    });
    expect(text).toBe(
      [
        "Kestrel recovery codes",
        "Account: admin@kestrel.local",
        "Generated: 2026-10-06T12:00:00.000Z",
        "",
        "Each code signs you in once if you lose your authenticator.",
        "Generating new codes invalidates these.",
        "",
        "aaaa-bbbb",
        "cccc-dddd",
        "",
      ].join("\n"),
    );
  });

  it("omits the optional lines", () => {
    const text = recoveryCodesText(["aaaa-bbbb"]);
    expect(text.startsWith("Kestrel recovery codes\n\n")).toBe(true);
    expect(text).not.toContain("Account:");
    expect(text.endsWith("aaaa-bbbb\n")).toBe(true);
  });
});

describe("routeAfterLogin", () => {
  it("sends a pending second factor to /login/mfa, keeping next", () => {
    expect(routeAfterLogin({ token: "t", mfa_required: true }, null)).toBe("/login/mfa");
    expect(routeAfterLogin({ token: "t", mfa_required: true }, "/findings?status=open")).toBe(
      "/login/mfa?next=%2Ffindings%3Fstatus%3Dopen",
    );
  });

  it("sends a required enrolment to /mfa/setup, keeping next", () => {
    expect(routeAfterLogin({ token: "t", mfa_enrollment_required: true }, null)).toBe("/mfa/setup");
    expect(routeAfterLogin({ token: "t", mfa_enrollment_required: true }, "/policies")).toBe(
      "/mfa/setup?next=%2Fpolicies",
    );
  });

  it("otherwise goes to next or the dashboard", () => {
    expect(routeAfterLogin({ token: "t" }, null)).toBe("/dashboard");
    expect(routeAfterLogin({ token: "t", mfa_required: false }, "/findings")).toBe("/findings");
  });

  it("prefers the challenge when both flags are set", () => {
    expect(
      routeAfterLogin({ token: "t", mfa_required: true, mfa_enrollment_required: true }, null),
    ).toBe("/login/mfa");
  });
});

describe("routeAfterEnrolment", () => {
  it("continues to next, but never back into setup", () => {
    expect(routeAfterEnrolment(null)).toBe("/dashboard");
    expect(routeAfterEnrolment("/findings")).toBe("/findings");
    expect(routeAfterEnrolment("/mfa/setup")).toBe("/dashboard");
    expect(routeAfterEnrolment("/mfa")).toBe("/dashboard");
    expect(routeAfterEnrolment("/mfa-docs")).toBe("/mfa-docs");
  });
});

describe("withNext", () => {
  it("drops a next that is just the default", () => {
    expect(withNext("/login/mfa", "/dashboard")).toBe("/login/mfa");
  });
});

describe("apiErrorCode", () => {
  it("reads the code of a structured detail", () => {
    expect(
      apiErrorCode(JSON.stringify({ detail: { code: "mfa_enrollment_required", message: "m" } })),
    ).toBe("mfa_enrollment_required");
  });

  it.each(['{"detail":"Not allowed"}', "not json", "", '{"detail":{"code":3}}', "null"])(
    "is null for %j",
    (body) => {
      expect(apiErrorCode(body)).toBeNull();
    },
  );
});
