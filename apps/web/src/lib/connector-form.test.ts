// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  connectorConfigValues,
  connectorFormDefaults,
  followDefault,
  resolveAuthMethod,
} from "./connector-form";
import type { ConnectorCatalogEntry } from "./types";

const GITHUB: ConnectorCatalogEntry = {
  name: "github",
  display_name: "GitHub",
  version: "1",
  description: "",
  auth_methods: [
    { id: "pat", label: "Personal access token", config_fields: ["org_login"], secret_fields: ["token"] },
    {
      id: "github_app",
      label: "GitHub App",
      config_fields: ["org_login", "app_id"],
      secret_fields: ["private_key"],
    },
  ],
  example_config: { org_login: "acme", app_id: null },
};

const SLACK: ConnectorCatalogEntry = {
  name: "slack",
  display_name: "Slack",
  version: "1",
  description: "",
  auth_methods: [
    { id: "user_token", label: "User OAuth token", config_fields: ["workspace_id"], secret_fields: ["token"] },
  ],
  example_config: { workspace_id: "T0123" },
};

describe("resolveAuthMethod", () => {
  it("returns the named method", () => {
    expect(resolveAuthMethod(GITHUB, "github_app")?.id).toBe("github_app");
  });

  it("falls back to the first method for a stale or empty id", () => {
    expect(resolveAuthMethod(SLACK, "pat")?.id).toBe("user_token");
    expect(resolveAuthMethod(SLACK, "")?.id).toBe("user_token");
    expect(resolveAuthMethod(null, "pat")).toBeNull();
  });
});

describe("connectorFormDefaults", () => {
  it("picks the new connector's first auth method and its config fields", () => {
    expect(connectorFormDefaults(SLACK)).toEqual({
      authMethod: "user_token",
      configValues: { workspace_id: "T0123" },
      displayName: "Slack",
      externalTenantRef: "T0123",
    });
  });

  it("drops the previous connector's config fields", () => {
    const github = connectorFormDefaults(GITHUB);
    expect(github.configValues).toEqual({ org_login: "acme" });
    expect(Object.keys(connectorFormDefaults(SLACK).configValues)).not.toContain("org_login");
  });
});

describe("connectorConfigValues", () => {
  it("keeps typed values when only the auth method changes", () => {
    const app = resolveAuthMethod(GITHUB, "github_app");
    expect(connectorConfigValues(GITHUB, app, { org_login: "initech" })).toEqual({
      org_login: "initech",
      app_id: "",
    });
  });
});

describe("followDefault", () => {
  it("replaces an empty or untouched default", () => {
    expect(followDefault("", "GitHub", "Slack")).toBe("Slack");
    expect(followDefault("GitHub", "GitHub", "Slack")).toBe("Slack");
  });

  it("keeps what the operator typed", () => {
    expect(followDefault("Acme prod", "GitHub", "Slack")).toBe("Acme prod");
  });
});
