// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";

import {
  EXPLORE_NODE_WIDTH,
  defaultExploreDirection,
  layoutExploreGraph,
  ranksFromFocus,
} from "./graph-layout";

function node(id: string, label = id): Node {
  return { id, type: "explore", position: { x: 0, y: 0 }, data: { label } };
}

function edge(id: string, source: string, target: string): Edge {
  return { id, source, target };
}

describe("defaultExploreDirection", () => {
  it("sandwiches a group with direction=both", () => {
    expect(defaultExploreDirection("group")).toBe("both");
  });

  it("pulls resources, oauth apps, permissions, and settings inbound", () => {
    for (const type of ["resource", "oauth_application", "permission", "setting"]) {
      expect(defaultExploreDirection(type)).toBe("in");
    }
  });

  it("defaults everything else outbound", () => {
    expect(defaultExploreDirection("identity")).toBe("out");
    expect(defaultExploreDirection("role")).toBe("out");
    expect(defaultExploreDirection("application")).toBe("out");
    expect(defaultExploreDirection("not_a_real_type")).toBe("out");
  });
});

describe("ranksFromFocus", () => {
  it("layers inbound paths away from the focus", () => {
    const nodes = new Set(["wiki", "group", "alan"]);
    const edges = [
      edge("e1", "group", "wiki"),
      edge("e2", "alan", "group"),
    ];
    const ranks = ranksFromFocus(nodes, edges, "wiki", "in");
    expect(ranks.get("wiki")).toBe(0);
    expect(ranks.get("group")).toBe(1);
    expect(ranks.get("alan")).toBe(2);
  });

  it("layers outbound paths from the focus", () => {
    const nodes = new Set(["alan", "group", "wiki"]);
    const edges = [
      edge("e1", "alan", "group"),
      edge("e2", "group", "wiki"),
    ];
    const ranks = ranksFromFocus(nodes, edges, "alan", "out");
    expect(ranks.get("alan")).toBe(0);
    expect(ranks.get("group")).toBe(1);
    expect(ranks.get("wiki")).toBe(2);
  });

  it("sandwiches inbound left of focus and outbound right for both", () => {
    const nodes = new Set(["member", "group", "app"]);
    const edges = [
      edge("e1", "member", "group"),
      edge("e2", "group", "app"),
    ];
    const ranks = ranksFromFocus(nodes, edges, "group", "both");
    expect((ranks.get("member") ?? -1) < (ranks.get("group") ?? -1)).toBe(true);
    expect((ranks.get("group") ?? -1) < (ranks.get("app") ?? -1)).toBe(true);
  });

  it("assigns a column to nodes only reachable undirected", () => {
    // A→B→focus with edges oriented so directed inbound from focus misses A
    // if we only had focus←B, but undirected from a spur:
    // focus←B, and C—B where C→B; wait — simpler: isolated-looking node
    // connected via an edge that directed BFS from focus in "out" misses.
    const nodes = new Set(["focus", "a", "b"]);
    const edges = [
      edge("e1", "a", "focus"), // inbound to focus
      edge("e2", "a", "b"), // spur only reachable via a, not from focus outbound
    ];
    const ranks = ranksFromFocus(nodes, edges, "focus", "out");
    // Outbound from focus finds nobody; undirected fallback still places a and b.
    expect(ranks.has("a")).toBe(true);
    expect(ranks.has("b")).toBe(true);
    expect(ranks.get("a")).not.toBe(ranks.get("focus"));
  });

  it("gives the focus node rank 0 even in an empty graph", () => {
    const ranks = ranksFromFocus(new Set(["focus"]), [], "focus", "out");
    expect(ranks.get("focus")).toBe(0);
    expect(ranks.size).toBe(1);
  });
});

describe("layoutExploreGraph", () => {
  it("places inbound nodes in hop order along the arrow direction", () => {
    const nodes = [node("wiki"), node("group"), node("alan")];
    const edges = [
      edge("e1", "group", "wiki"),
      edge("e2", "alan", "group"),
    ];
    const { nodes: laidOut } = layoutExploreGraph(nodes, edges, {
      focusNodeId: "wiki",
      direction: "in",
      mode: "hierarchical",
    });
    const byId = Object.fromEntries(laidOut.map((n) => [n.id, n.position.x]));
    // Arrows alan→group→wiki read left to right; focus (wiki) is downstream on the right.
    expect(byId.alan < byId.group).toBe(true);
    expect(byId.group < byId.wiki).toBe(true);
  });

  it("places outbound nodes in hop order left to right", () => {
    const nodes = [node("alan"), node("group"), node("wiki")];
    const edges = [
      edge("e1", "alan", "group"),
      edge("e2", "group", "wiki"),
    ];
    const { nodes: laidOut } = layoutExploreGraph(nodes, edges, {
      focusNodeId: "alan",
      direction: "out",
      mode: "hierarchical",
    });
    const byId = Object.fromEntries(laidOut.map((n) => [n.id, n.position.x]));
    expect(byId.alan < byId.group).toBe(true);
    expect(byId.group < byId.wiki).toBe(true);
  });

  it("spreads a both-direction group sandwich horizontally", () => {
    const nodes = [node("member"), node("group"), node("app")];
    const edges = [
      edge("e1", "member", "group"),
      edge("e2", "group", "app"),
    ];
    const { nodes: laidOut } = layoutExploreGraph(nodes, edges, {
      focusNodeId: "group",
      direction: "both",
      mode: "hierarchical",
    });
    const byId = Object.fromEntries(laidOut.map((n) => [n.id, n.position.x]));
    expect(byId.member < byId.group).toBe(true);
    expect(byId.group < byId.app).toBe(true);
  });

  it("wraps dense same-hop layers into multiple subcolumns", () => {
    const members = Array.from({ length: 10 }, (_, i) => node(`m${i}`, `Member ${i}`));
    const nodes = [node("group", "Engineering"), ...members];
    const edges = members.map((m, i) => edge(`e${i}`, m.id, "group"));
    const { nodes: laidOut } = layoutExploreGraph(nodes, edges, {
      focusNodeId: "group",
      direction: "both",
      mode: "hierarchical",
    });
    const memberXs = new Set(
      laidOut.filter((n) => n.id.startsWith("m")).map((n) => n.position.x),
    );
    expect(memberXs.size >= 2).toBe(true);
    const ys = laidOut.filter((n) => n.id.startsWith("m")).map((n) => n.position.y);
    const span = Math.max(...ys) - Math.min(...ys);
    // 10 nodes in one column would span ~9*(100+72)=1548; wrapped into 2 cols of 5 → ~4*172=688
    expect(span < 1200).toBe(true);
  });

  it("keeps a wrapped hop column clear of the next one", () => {
    // 25 outbound neighbours wrap into 5 subcolumns, which is wider than a
    // fixed NODE_WIDTH + RANKSEP pitch. Before the rank origins were measured,
    // the block bled into the next hop and captions ran together.
    const mid = Array.from({ length: 25 }, (_, i) => node(`g${i}`, `Group ${i}`));
    const nodes = [node("alan", "Alan"), ...mid, node("repo", "Repo")];
    const edges = [
      ...mid.map((m, i) => edge(`a${i}`, "alan", m.id)),
      edge("z", mid[0]!.id, "repo"),
    ];
    const { nodes: laidOut } = layoutExploreGraph(nodes, edges, {
      focusNodeId: "alan",
      direction: "out",
      mode: "hierarchical",
    });
    const byId = Object.fromEntries(laidOut.map((n) => [n.id, n.position.x]));
    const midXs = mid.map((m) => byId[m.id]!);
    // The wrapped rank really does use several subcolumns...
    expect(new Set(midXs).size).toBeGreaterThan(2);
    // ...and the next hop starts clear of the widest one, with room for a
    // 120px caption rather than overlapping it.
    expect(byId.repo! - Math.max(...midXs)).toBeGreaterThanOrEqual(EXPLORE_NODE_WIDTH);
    // The focus column stays clear of the rank it feeds, too.
    expect(Math.min(...midXs) - byId.alan!).toBeGreaterThanOrEqual(EXPLORE_NODE_WIDTH);
  });

  it("returns every input node exactly once, even in free mode", () => {
    const nodes = [node("a"), node("b"), node("c")];
    const edges = [edge("e1", "a", "b"), edge("e2", "b", "c")];
    const { nodes: laidOut } = layoutExploreGraph(nodes, edges, {
      focusNodeId: "a",
      direction: "out",
      mode: "free",
    });
    expect(laidOut.map((n) => n.id).sort()).toEqual(["a", "b", "c"]);
  });
});
