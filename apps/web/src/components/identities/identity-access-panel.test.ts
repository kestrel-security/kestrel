// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { groupAccessByApplication } from "./identity-access-panel";

describe("groupAccessByApplication", () => {
  it("puts OAuth consents in the same section as the application's roles", () => {
    const groups = groupAccessByApplication(
      [
        { role_name: "Super Admin", application_type: "google_workspace", application_instance_display_name: "Acme Google Workspace" },
        { role_name: "Admin", application_type: "slack", application_instance_display_name: "Acme Slack" },
      ],
      [{ oauth_application_name: "Slack", application_type: "google_workspace", application_instance_display_name: "Acme Google Workspace" }],
    );

    expect(groups.map((g) => g.label)).toEqual(["Acme Google Workspace", "Acme Slack"]);
    expect(groups[0].oauth.map((o) => o.oauth_application_name)).toEqual(["Slack"]);
  });

  it("falls back to the application type, then Other", () => {
    const groups = groupAccessByApplication([{ role_name: "Owner" }], [{ oauth_application_name: "Zoom", application_type: "okta" }]);

    expect(groups.map((g) => g.label)).toEqual(["Other", "okta"]);
  });
});
