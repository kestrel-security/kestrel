// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { changedEndpointFields, isEndpointConfigKey } from "./connector-endpoints";

describe("isEndpointConfigKey", () => {
  it("matches URL / host / domain shaped names", () => {
    expect(isEndpointConfigKey("org_url")).toBe(true);
    expect(isEndpointConfigKey("base_url")).toBe(true);
    expect(isEndpointConfigKey("token_uri")).toBe(true);
    expect(isEndpointConfigKey("api-host")).toBe(true);
    expect(isEndpointConfigKey("domain")).toBe(true);
  });

  it("ignores ordinary config names", () => {
    expect(isEndpointConfigKey("org_login")).toBe(false);
    expect(isEndpointConfigKey("team_id")).toBe(false);
  });
});

describe("changedEndpointFields", () => {
  it("flags a changed org URL", () => {
    expect(
      changedEndpointFields({ org_url: "https://acme.okta.com" }, { org_url: "https://attacker.example" }),
    ).toEqual(["org_url"]);
  });

  it("treats whitespace, host case and a trailing slash as no change", () => {
    expect(
      changedEndpointFields({ org_url: "https://acme.okta.com" }, { org_url: " https://ACME.okta.com/ " }),
    ).toEqual([]);
  });

  it("flags URL-valued keys whatever their name", () => {
    expect(changedEndpointFields({ target: "https://a.example" }, { target: "https://b.example" })).toEqual([
      "target",
    ]);
  });

  it("ignores non-endpoint fields", () => {
    expect(changedEndpointFields({ org_login: "acme" }, { org_login: "other" })).toEqual([]);
  });
});
