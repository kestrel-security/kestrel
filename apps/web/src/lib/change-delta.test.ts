// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  changeDelta,
  formatChangeValue,
  formatCompactChangeValue,
  isEmptyChangeValue,
} from "./change-delta";

// Thin adapters so the assertions read the same as the rest of the file.
const assert = {
  equal: (actual: unknown, expected: unknown) => expect(actual).toBe(expected),
  deepEqual: (actual: unknown, expected: unknown) => expect(actual).toEqual(expected),
  ok: (value: unknown) => expect(value).toBeTruthy(),
};

describe("changeDelta", () => {
  it("renders a grant as an addition rather than a transition from nothing", () => {
    assert.deepEqual(changeDelta({ change_type: "created", before: null, after: "Admin" }), {
      kind: "added",
      value: "Admin",
    });
  });

  it("renders a revoke as a removal", () => {
    assert.deepEqual(
      changeDelta({
        change_type: "deleted",
        before: "Application Administrator",
        after: null,
      }),
      { kind: "removed", value: "Application Administrator" },
    );
  });

  it("prefers direction over synthesized prose on the missing side", () => {
    assert.deepEqual(
      changeDelta({
        change_type: "created",
        before: "Not a member",
        after: "Member of Engineering",
      }),
      { kind: "added", value: "Member of Engineering" },
    );
    assert.deepEqual(
      changeDelta({ change_type: "deleted", before: "grace@acme.example", after: "Removed" }),
      { kind: "removed", value: "grace@acme.example" },
    );
  });

  it("keeps the arrow for real transitions", () => {
    assert.deepEqual(changeDelta({ change_type: "updated", before: false, after: true }), {
      kind: "modified",
      before: "false",
      after: "true",
    });
  });

  it("falls back to a direction when an update only has one side", () => {
    assert.deepEqual(changeDelta({ change_type: "updated", before: null, after: "admin" }), {
      kind: "added",
      value: "admin",
    });
    assert.deepEqual(changeDelta({ change_type: "updated", before: "admin", after: null }), {
      kind: "removed",
      value: "admin",
    });
  });

  it("never produces a bare dash when neither side was recorded", () => {
    assert.deepEqual(changeDelta({ change_type: "updated", before: null, after: "—" }), {
      kind: "unrecorded",
    });
  });
});

describe("formatCompactChangeValue", () => {
  it("returns null for absent values instead of a dash", () => {
    assert.equal(formatCompactChangeValue(null), null);
    assert.equal(formatCompactChangeValue(undefined), null);
    assert.equal(formatCompactChangeValue("—"), null);
  });

  it("collapses scope lists to a count past two entries", () => {
    assert.equal(formatCompactChangeValue(["read", "write"]), "read, write");
    assert.equal(formatCompactChangeValue(["a", "b", "c"]), "3 scopes");
    assert.equal(formatCompactChangeValue([]), "none");
    assert.equal(formatCompactChangeValue([{ a: 1 }, { b: 2 }]), "2 items");
    assert.equal(formatCompactChangeValue([{ a: 1 }]), "1 item");
  });

  it("keeps booleans readable", () => {
    assert.equal(formatCompactChangeValue(false), "false");
    assert.equal(formatCompactChangeValue(true), "true");
  });
});

describe("formatChangeValue", () => {
  it("keeps full lists for the evidence panel", () => {
    assert.equal(formatChangeValue(["a", "b", "c"]), "a, b, c");
    assert.equal(formatChangeValue({ mfa: false }), '{"mfa":false}');
    assert.equal(formatChangeValue(null), null);
  });
});

describe("isEmptyChangeValue", () => {
  it("treats null and a stringified em dash as absent", () => {
    assert.equal(isEmptyChangeValue(null), true);
    assert.equal(isEmptyChangeValue("—"), true);
    assert.equal(isEmptyChangeValue(false), false);
    assert.equal(isEmptyChangeValue(""), false);
  });
});
