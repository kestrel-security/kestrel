// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { describeIntentAnalysis, describeScope, scopeForRequest, summarizeAssessability } from "./policy-generate";
import type { PolicyGenerateIntentAnalysis } from "./types";

const ANALYSIS: PolicyGenerateIntentAnalysis = {
  scope: "cross_app",
  scope_source: "intent_wording",
  scope_reason: "intent says 'any app'",
  focus_connector: "okta",
  resource_type: null,
  subject: { identity_type: "user", worker_type: "contractor" },
  conditions: ["stale_activity"],
  days: 30,
  per: "account",
  fields_needed: ["identity.last_active_at"],
  requires: ["identity:last_sign_in", "identity:worker_type"],
  notes: [],
};

describe("policy-generate", () => {
  it("keeps the selected app as the focus of a cross-app request", () => {
    expect(scopeForRequest("cross_app", "okta")).toEqual({ scope: "cross_app", connector_hint: "okta" });
    expect(scopeForRequest("cross_app", undefined)).toEqual({ scope: "cross_app", connector_hint: "cross_app" });
    expect(scopeForRequest("single_app", "slack")).toEqual({ scope: "single_app", connector_hint: "slack" });
  });

  it("describes the analysis as short lines", () => {
    expect(describeScope(ANALYSIS)).toBe("every connected app (focus: okta) — intent says 'any app'");
    expect(describeIntentAnalysis(ANALYSIS)).toEqual([
      "Subject: identity_type=user, worker_type=contractor",
      "Conditions: stale_activity",
      "Threshold: 30 days",
      "Finding per account",
      "REQUIRES: identity:last_sign_in, identity:worker_type",
    ]);
    expect(describeIntentAnalysis(null)).toEqual([]);
  });

  it("summarizes which connected apps cannot assess the draft", () => {
    expect(summarizeAssessability(null)).toBe("");
    expect(
      summarizeAssessability([
        { application_type: "okta", name: "Okta", assessable: true, missing: [] },
        { application_type: "github", name: "GitHub (acme)", assessable: false, missing: ["identity:worker_type"] },
      ]),
    ).toBe("Not assessable in GitHub (acme): identity:worker_type");
    expect(
      summarizeAssessability([{ application_type: "okta", name: "Okta", assessable: true, missing: [] }]),
    ).toBe("Assessable in all 1 connected app.");
  });
});
