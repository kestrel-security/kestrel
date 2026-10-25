// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { changePasswordProblem, generateTemporaryPassword, newPasswordProblem } from "./password-policy";

const ok = { current: "old-password-1", next: "correct horse battery", confirm: "correct horse battery" };

describe("changePasswordProblem", () => {
  it("accepts a valid change", () => {
    expect(changePasswordProblem(ok)).toBeNull();
  });

  it("requires the current password", () => {
    expect(changePasswordProblem({ ...ok, current: "" })).toMatch(/current password/);
  });

  it("enforces 12 to 128 characters", () => {
    expect(changePasswordProblem({ ...ok, next: "a".repeat(11), confirm: "a".repeat(11) })).toMatch(
      /at least 12/,
    );
    expect(changePasswordProblem({ ...ok, next: "a".repeat(12), confirm: "a".repeat(12) })).toBeNull();
    expect(changePasswordProblem({ ...ok, next: "a".repeat(128), confirm: "a".repeat(128) })).toBeNull();
    expect(changePasswordProblem({ ...ok, next: "a".repeat(129), confirm: "a".repeat(129) })).toMatch(
      /at most 128/,
    );
  });

  it("counts characters the way the server does, not UTF-16 units", () => {
    const emoji = "🔒".repeat(12); // 24 UTF-16 units, 12 code points
    expect(changePasswordProblem({ ...ok, next: emoji, confirm: emoji })).toBeNull();
    const long = "🔒".repeat(100); // 200 units but 100 code points
    expect(changePasswordProblem({ ...ok, next: long, confirm: long })).toBeNull();
  });

  it("requires the confirmation to match", () => {
    expect(changePasswordProblem({ ...ok, confirm: "correct horse battery!" })).toMatch(/don't match/);
  });

  it("rejects reusing the current password", () => {
    expect(
      changePasswordProblem({ current: ok.next, next: ok.next, confirm: ok.next }),
    ).toMatch(/differ/);
  });
});

describe("generateTemporaryPassword", () => {
  it("meets the server's policy at the default length", () => {
    const password = generateTemporaryPassword();
    expect(password).toHaveLength(20);
    expect(newPasswordProblem(password)).toBeNull();
  });

  it("avoids characters that are easy to misread", () => {
    expect(generateTemporaryPassword(200)).not.toMatch(/[0O1lI]/);
  });

  it("differs between calls", () => {
    expect(generateTemporaryPassword()).not.toBe(generateTemporaryPassword());
  });
});

describe("newPasswordProblem", () => {
  it("rejects a short password and accepts a 12-character one", () => {
    expect(newPasswordProblem("short")).toMatch(/at least 12/);
    expect(newPasswordProblem("a".repeat(12))).toBeNull();
  });
});
