// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  ACCESS_PATH_META,
  KNOWN_NODE_TYPES,
  NODE_TYPE_META,
  accessPathMeta,
  nodeTypeMeta,
  nodeTypeShape,
  type NodeShape,
} from "./graph-style";

describe("nodeTypeShape", () => {
  it("maps every known node type to a unique shape", () => {
    const shapes = KNOWN_NODE_TYPES.map((t) => nodeTypeShape(t));
    expect(shapes.length).toBe(8);
    expect(new Set(shapes).size).toBe(shapes.length);
  });

  it("uses the planned silhouette for each type", () => {
    const expected: Record<(typeof KNOWN_NODE_TYPES)[number], NodeShape> = {
      identity: "circle",
      group: "hexagon",
      role: "shield",
      application: "rounded_square",
      oauth_application: "cloud",
      resource: "cylinder",
      permission: "diamond",
      setting: "octagon",
    };
    for (const [type, shape] of Object.entries(expected)) {
      expect(nodeTypeShape(type)).toBe(shape);
      expect(NODE_TYPE_META[type].shape).toBe(shape);
      expect(NODE_TYPE_META[type].icon).toBeTruthy();
    }
  });

  it("falls back to setting for unknown types", () => {
    expect(nodeTypeShape("not_a_real_type")).toBe(NODE_TYPE_META.setting.shape);
    expect(nodeTypeMeta("not_a_real_type")).toBe(NODE_TYPE_META.setting);
  });
});

describe("accessPathMeta", () => {
  it("distinguishes inherited_role from inherited_group strokes", () => {
    expect(accessPathMeta("inherited_role").stroke).not.toBe(
      accessPathMeta("inherited_group").stroke,
    );
    expect(ACCESS_PATH_META.inherited_role.stroke).toBe("#7c3aed");
  });

  it("falls back to the default relationship meta for null, undefined, and unknown paths", () => {
    const fallback = { label: "Relationship", stroke: "#94a3b8", width: 1.5 };
    expect(accessPathMeta(null)).toEqual(fallback);
    expect(accessPathMeta(undefined)).toEqual(fallback);
    expect(accessPathMeta("not_a_real_path")).toEqual(fallback);
  });

  it("marks oauth_derived as dashed and every known path as solid otherwise", () => {
    expect(accessPathMeta("oauth_derived").dash).toBe("6 4");
    expect(accessPathMeta("direct").dash).toBeUndefined();
  });
});
