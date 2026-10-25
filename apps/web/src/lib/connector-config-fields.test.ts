// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { firstMissingConfigField, isOptionalConfigField } from "./connector-config-fields";

describe("firstMissingConfigField", () => {
  it("does not demand an optional field such as Slack's enterprise_id", () => {
    expect(firstMissingConfigField(["team_id", "enterprise_id"], ["enterprise_id"], { team_id: "T1" })).toBeNull();
  });

  it("still reports a blank required field", () => {
    expect(firstMissingConfigField(["team_id", "enterprise_id"], ["enterprise_id"], { team_id: "  " })).toBe(
      "team_id",
    );
  });

  it("treats every field as required when the manifest marks none optional", () => {
    expect(firstMissingConfigField(["org_login"], undefined, {})).toBe("org_login");
  });
});

describe("isOptionalConfigField", () => {
  it("matches only listed fields", () => {
    expect(isOptionalConfigField("enterprise_id", ["enterprise_id"])).toBe(true);
    expect(isOptionalConfigField("team_id", ["enterprise_id"])).toBe(false);
    expect(isOptionalConfigField("team_id", null)).toBe(false);
  });
});
