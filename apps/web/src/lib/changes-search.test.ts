// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  changesActiveChips,
  changesFiltersFromParams,
  changesFiltersToParams,
  changesHref,
  formatChangesQuery,
  parseChangesQuery,
  removeChangesChip,
} from "./changes-search";

describe("parseChangesQuery", () => {
  it("parses free text and tokens", () => {
    const filters = parseChangesQuery("grace class:admin_granted significance:high app:Okta");
    expect(filters.search).toBe("grace");
    expect(filters.change_class).toBe("admin_granted");
    expect(filters.min_significance).toBe("high");
    expect(filters.app).toBe("Okta");
  });

  it("parses person and quoted phrases", () => {
    const filters = parseChangesQuery('person:"Grace Hopper" class:admin_granted');
    expect(filters.person).toBe("Grace Hopper");
    expect(filters.change_class).toBe("admin_granted");
    expect(filters.search).toBeUndefined();
  });

  it("ignores an unrecognized significance value and keeps it as free text", () => {
    const filters = parseChangesQuery("significance:extreme");
    expect(filters.min_significance).toBeUndefined();
    expect(filters.search).toBe("significance:extreme");
  });

  it("accepts identity: and user: as aliases for person:", () => {
    expect(parseChangesQuery("identity:bob").person).toBe("bob");
    expect(parseChangesQuery("user:bob").person).toBe("bob");
  });

  it("treats a bare colon-less token as free text", () => {
    const filters = parseChangesQuery("just some text");
    expect(filters.search).toBe("just some text");
  });
});

describe("formatChangesQuery", () => {
  it("omits default medium significance", () => {
    expect(
      formatChangesQuery({
        search: "bob",
        min_significance: "medium",
        change_class: "admin_granted",
      }),
    ).toBe("class:admin_granted bob");
  });

  it("quotes person and app values that contain spaces", () => {
    expect(formatChangesQuery({ person: "Grace Hopper" })).toBe('person:"Grace Hopper"');
    expect(formatChangesQuery({ app: "Google Workspace" })).toBe('app:"Google Workspace"');
    expect(formatChangesQuery({ person: "bob" })).toBe("person:bob");
  });

  it("round-trips through parseChangesQuery", () => {
    const filters = {
      change_class: "role_assigned",
      min_significance: "high" as const,
      person: "Grace Hopper",
      search: "wiki",
    };
    const query = formatChangesQuery(filters);
    expect(parseChangesQuery(query)).toEqual(filters);
  });
});

describe("changesHref / params", () => {
  it("builds a shareable URL", () => {
    expect(
      changesHref({
        search: "bob",
        change_class: "admin_granted",
        window_hours: "168",
        min_significance: "high",
      }),
    ).toBe("/changes?window_hours=168&change_class=admin_granted&min_significance=high&search=bob");
  });

  it("returns the bare path when there are no filters", () => {
    expect(changesHref({})).toBe("/changes");
  });

  it("puts person into the search param for the API", () => {
    const params = changesFiltersToParams({ person: "grace", min_significance: "medium" });
    expect(params.get("search")).toBe("person:grace");
    expect(params.get("min_significance")).toBeNull();
  });
});

describe("changesActiveChips", () => {
  it("builds one chip per active filter, replacing underscores in the class label", () => {
    const chips = changesActiveChips({
      search: "bob",
      person: "grace",
      app: "Okta",
      change_class: "admin_granted",
      min_significance: "high",
      connector_instance_id: "12345678-abcd-ef00-0000-000000000000",
    });
    expect(chips.map((c) => c.key)).toEqual([
      "search",
      "person",
      "app",
      "change_class",
      "min_significance",
      "connector_instance_id",
    ]);
    expect(chips.find((c) => c.key === "change_class")?.label).toBe("class:admin granted");
    expect(chips.find((c) => c.key === "connector_instance_id")?.label).toBe("connector:12345678…");
  });

  it("omits the default medium significance and returns no chips for empty filters", () => {
    expect(changesActiveChips({ min_significance: "medium" })).toEqual([]);
    expect(changesActiveChips({})).toEqual([]);
  });
});

describe("removeChangesChip", () => {
  it("drops a single key", () => {
    expect(removeChangesChip({ search: "a", change_class: "other" }, "change_class")).toEqual({
      search: "a",
    });
  });
});

describe("changesFiltersFromParams", () => {
  it("prefers explicit params over embedded search tokens", () => {
    const filters = changesFiltersFromParams({
      search: "class:role_assigned bob",
      change_class: "admin_granted",
    });
    expect(filters.change_class).toBe("admin_granted");
    expect(filters.search).toBe("bob");
  });

  it("defaults min_significance to medium when nothing supplies it", () => {
    const filters = changesFiltersFromParams({ search: "bob" });
    expect(filters.min_significance).toBe("medium");
  });

  it("pulls person/app/significance out of the embedded search string", () => {
    const filters = changesFiltersFromParams({ search: 'person:"Grace Hopper" significance:high' });
    expect(filters.person).toBe("Grace Hopper");
    expect(filters.min_significance).toBe("high");
    expect(filters.search).toBeUndefined();
  });
});
