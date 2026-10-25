// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import { compactEdgeLabel, edgeHoverText, edgeTypeLabel, nodeChipLabel } from "./graph-edge-label";

describe("compactEdgeLabel", () => {
  it("prefers permission_level over the relationship verb", () => {
    expect(compactEdgeLabel("can_access", { permission_level: "admin" })).toBe("admin");
  });

  it("uses membership_role on member_of", () => {
    expect(compactEdgeLabel("member_of", { membership_role: "OWNER" })).toBe("OWNER");
  });

  it("ignores membership_role on edge types other than member_of", () => {
    expect(compactEdgeLabel("assigned_role", { membership_role: "OWNER" })).toBe("assigned");
  });

  it("prefers a sensitive OAuth scope, else first scope, else OAuth", () => {
    expect(
      compactEdgeLabel("possesses_scope", {
        scopes: [
          { name: "openid", is_sensitive: false },
          { name: "okta.users.manage", is_sensitive: true },
        ],
      }),
    ).toBe("okta.users.manage");
    expect(
      compactEdgeLabel("possesses_scope", {
        scopes: [{ name: "openid", is_sensitive: false }],
      }),
    ).toBe("openid");
    expect(compactEdgeLabel("possesses_scope", {})).toBe("OAuth");
  });

  it("falls back to edge-type verbs", () => {
    expect(compactEdgeLabel("assigned_role", {})).toBe("assigned");
    expect(compactEdgeLabel("member_of", {})).toBe("member of");
  });

  it("defaults to an empty properties object", () => {
    expect(compactEdgeLabel("assigned_role")).toBe("assigned");
  });

  it("ignores malformed scope entries", () => {
    expect(
      compactEdgeLabel("possesses_scope", {
        scopes: ["not-an-object", { name: 123 }, null, { is_sensitive: true }],
      }),
    ).toBe("OAuth");
  });
});

describe("edgeHoverText", () => {
  it("prefers a full explanation when present", () => {
    expect(
      edgeHoverText({
        edgeType: "can_access",
        accessPath: "direct",
        explanation: 'The identity “alice” can access the resource “repo” with admin permission.',
      }),
    ).toBe('The identity “alice” can access the resource “repo” with admin permission.');
  });

  it("builds a compact fallback", () => {
    expect(
      edgeHoverText({
        edgeType: "assigned_role",
        accessPath: "direct",
      }),
    ).toBe("assigned · direct");
  });

  it("ignores a blank explanation and falls through to the compact form", () => {
    expect(
      edgeHoverText({
        edgeType: "assigned_role",
        accessPath: "direct",
        explanation: "   ",
      }),
    ).toBe("assigned · direct");
  });

  it("appends permission, membership, and scope details", () => {
    expect(
      edgeHoverText({
        edgeType: "can_access",
        accessPath: null,
        properties: {
          permission_level: "admin",
          membership_role: "OWNER",
          scopes: [
            { name: "openid", is_sensitive: false },
            { name: "okta.users.manage", is_sensitive: true },
          ],
        },
      }),
    ).toBe("can access · admin · OWNER · openid, okta.users.manage*");
  });
});

describe("edgeTypeLabel / nodeChipLabel", () => {
  it("maps known edge types", () => {
    expect(edgeTypeLabel("possesses_scope")).toBe("OAuth");
  });

  it("humanizes an unknown edge type by replacing underscores", () => {
    expect(edgeTypeLabel("some_new_edge_type")).toBe("some new edge type");
  });

  it("marks privileged roles", () => {
    expect(nodeChipLabel("role", { is_privileged: true })).toBe("Privileged");
    expect(nodeChipLabel("role", { is_privileged: false })).toBeNull();
  });

  it("checks the privileged-role chip before falling back to an incoming permission", () => {
    // is_privileged on a role wins even when an incoming permission is also given.
    expect(nodeChipLabel("role", { is_privileged: true }, "admin")).toBe("Privileged");
    // Non-role nodes have no privileged check, so incomingPermission applies.
    expect(nodeChipLabel("group", {}, "admin")).toBe("admin");
  });

  it("chips a sensitive scope on an oauth_application node", () => {
    expect(
      nodeChipLabel("oauth_application", {
        scopes: [
          { name: "openid", is_sensitive: false },
          { name: "okta.users.manage", is_sensitive: true },
        ],
      }),
    ).toBe("okta.users.manage");
  });

  it("returns null when nothing applies", () => {
    expect(nodeChipLabel("resource", {})).toBeNull();
  });
});
