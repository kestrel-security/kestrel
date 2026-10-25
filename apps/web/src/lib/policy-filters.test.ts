// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  DEFAULT_PER_PAGE,
  DEFAULT_POLICY_SORT,
  applicationsPresent,
  applyPolicyFilters,
  facetCounts,
  hasActiveFilters,
  pageHref,
  paginate,
  parsePolicyFilters,
  perPageHref,
  policyFiltersToParams,
  sortPolicies,
  type PackFrameworks,
} from "./policy-filters.ts";
import type { PolicySummary } from "./types.ts";

function policy(over: Partial<PolicySummary> & { slug: string }): PolicySummary {
  return {
    id: over.slug,
    title: over.slug,
    source: "pack",
    pack_name: "okta-posture",
    application: "okta",
    current_version_id: "v",
    version: 1,
    severity: "medium",
    is_enabled: true,
    resource_type: "identity",
    open_finding_count: 0,
    last_evaluation_status: "success",
    last_evaluated_at: null,
    ...over,
  } as PolicySummary;
}

const PACKS: PackFrameworks = new Map([
  ["okta-posture", new Set(["cis", "soc2"])],
  ["github-posture", new Set(["cis"])],
]);

const CORPUS: PolicySummary[] = [
  policy({ slug: "okta-admin-no-mfa", open_finding_count: 5, severity: "critical" }),
  policy({ slug: "okta-dormant-admin", open_finding_count: 0, severity: "low" }),
  policy({ slug: "gh-2fa", pack_name: "github-posture", application: "github", open_finding_count: 2 }),
  policy({
    slug: "my-custom",
    source: "custom",
    pack_name: null,
    application: null,
    is_enabled: false,
    open_finding_count: 1,
    severity: "high",
  }),
];

describe("parsePolicyFilters", () => {
  it("keeps valid values and drops garbage", () => {
    const f = parsePolicyFilters({
      enabled: "true",
      source: "custom",
      resource_type: "identity",
      has_open: "true",
      framework: "cis",
      q: "  MFA  ",
      sort: "title",
    });
    expect(f.enabled).toBe("true");
    expect(f.source).toBe("custom");
    expect(f.resource_type).toBe("identity");
    expect(f.framework).toBe("cis");
    expect(f.q).toBe("mfa", "lowercased and trimmed for case-insensitive matching");
    expect(f.sort).toBe("title");

    const junk = parsePolicyFilters({
      enabled: "yes",
      source: "nope",
      resource_type: "wat",
      framework: "hipaa",
      sort: "sideways",
    });
    expect(junk.enabled).toBe(undefined);
    expect(junk.source).toBe(undefined);
    expect(junk.resource_type).toBe(undefined);
    expect(junk.framework).toBe(undefined);
    expect(junk.sort).toBe(DEFAULT_POLICY_SORT);
  });

  it("round-trips through params, omitting the default sort", () => {
    const f = parsePolicyFilters({ source: "pack", sort: "open_desc" });
    expect(policyFiltersToParams(f).toString()).toBe("source=pack");
    const withSort = parsePolicyFilters({ source: "pack", sort: "title" });
    expect(policyFiltersToParams(withSort).toString()).toBe("source=pack&sort=title");
  });

  it("parses page and per, falling back on garbage", () => {
    const f = parsePolicyFilters({ page: "3", per: "100" });
    expect(f.page).toBe(3);
    expect(f.per).toBe(100);
    const junk = parsePolicyFilters({ page: "0", per: "33" });
    expect(junk.page).toBe(1);
    expect(junk.per).toBe(DEFAULT_PER_PAGE);
    const weird = parsePolicyFilters({ page: "-2", per: "abc" });
    expect(weird.page).toBe(1);
    expect(weird.per).toBe(DEFAULT_PER_PAGE);
    const none = parsePolicyFilters({});
    expect(none.page).toBe(1);
    expect(none.per).toBe(DEFAULT_PER_PAGE);
  });

  it("serializes per but never page, so filter and sort links return to page 1", () => {
    const f = parsePolicyFilters({ source: "pack", page: "4", per: "50" });
    expect(policyFiltersToParams(f).toString()).toBe("source=pack&per=50");
    expect(policyFiltersToParams(parsePolicyFilters({ page: "4" })).toString()).toBe("");
    expect(hasActiveFilters(parsePolicyFilters({ page: "4", per: "100" }))).toBe(false);
  });
});

describe("pagination", () => {
  const rows = Array.from({ length: 179 }, (_, i) => i + 1);

  it("slices with 1-based inclusive bounds", () => {
    const p = paginate(rows, 2, 25);
    expect(p.rows[0]).toBe(26);
    expect(p.rows.at(-1)).toBe(50);
    expect(p).toMatchObject({ page: 2, pageCount: 8, start: 26, end: 50, total: 179 });
    const last = paginate(rows, 8, 25);
    expect(last.rows.length).toBe(4);
    expect(last).toMatchObject({ start: 176, end: 179 });
  });

  it("clamps a stale page past the end to the last page, never an empty one", () => {
    const p = paginate(rows, 40, 100);
    expect(p.page).toBe(2);
    expect(p.rows.length).toBe(79);
  });

  it("reports an empty set without dividing by zero", () => {
    expect(paginate([], 3, 25)).toMatchObject({ rows: [], page: 1, pageCount: 1, start: 0, end: 0, total: 0 });
  });

  it("builds page links on top of the current filters", () => {
    const f = parsePolicyFilters({ source: "pack", per: "50", page: "3" });
    expect(pageHref("/policies", f, 1)).toBe("/policies?source=pack&per=50");
    expect(pageHref("/policies", f, 2)).toBe("/policies?source=pack&per=50&page=2");
    expect(perPageHref("/policies", f, 25)).toBe("/policies?source=pack");
    expect(perPageHref("/policies", f, 100)).toBe("/policies?source=pack&per=100");
  });
});

describe("hasActiveFilters", () => {
  it("ignores sort", () => {
    expect(hasActiveFilters(parsePolicyFilters({ sort: "title" }))).toBe(false);
    expect(hasActiveFilters(parsePolicyFilters({ q: "mfa" }))).toBe(true);
  });
});

describe("applyPolicyFilters", () => {
  it("matches query against both slug and title, case-insensitively", () => {
    const withTitle = [policy({ slug: "abc", title: "Admin without MFA" })];
    const f = parsePolicyFilters({ q: "mfa" });
    expect(applyPolicyFilters(withTitle, f, PACKS).length).toBe(1);
  });

  it("matches every token of a query in any order, across pack, slug parts, severity and type", () => {
    const slugs = (q: string) =>
      applyPolicyFilters(CORPUS, parsePolicyFilters({ q }), PACKS)
        .map((p) => p.slug)
        .sort();
    expect(slugs("admin okta")).toEqual(["okta-admin-no-mfa", "okta-dormant-admin"]);
    expect(slugs("github-posture")).toEqual(["gh-2fa"]);
    expect(slugs("posture critical")).toEqual(["okta-admin-no-mfa"]);
    expect(slugs("identity high")).toEqual(["my-custom"]);
    expect(slugs("dormant github")).toEqual([]);
  });

  it("excludes custom policies from framework filters", () => {
    const f = parsePolicyFilters({ framework: "cis" });
    const out = applyPolicyFilters(CORPUS, f, PACKS);
    expect(out.some((p) => p.slug === "my-custom")).toBe(false);
    expect(out.length).toBe(3);
  });

  it("treats has_open as a boundary on the count", () => {
    const open = applyPolicyFilters(CORPUS, parsePolicyFilters({ has_open: "true" }), PACKS);
    expect(open.map((p) => p.slug).sort()).toEqual(["gh-2fa", "my-custom", "okta-admin-no-mfa"]);
    const clean = applyPolicyFilters(CORPUS, parsePolicyFilters({ has_open: "false" }), PACKS);
    expect(clean.map((p) => p.slug)).toEqual(["okta-dormant-admin"]);
  });

  it("ignores the excepted facet but honours the others", () => {
    const f = parsePolicyFilters({ source: "custom", has_open: "true" });
    const all = applyPolicyFilters(CORPUS, f, PACKS);
    expect(all.map((p) => p.slug)).toEqual(["my-custom"]);

    const exceptSource = applyPolicyFilters(CORPUS, f, PACKS, { except: "source" });
    expect(exceptSource.map((p) => p.slug).sort()).toEqual(["gh-2fa", "my-custom", "okta-admin-no-mfa"],
      "has_open still applies",);
  });
});

describe("facetCounts", () => {
  it("counts each chip against the other active facets, not the whole corpus", () => {
    const f = parsePolicyFilters({ has_open: "true" });
    const counts = facetCounts(CORPUS, f, PACKS, "source", ["pack", "custom"]);
    expect(counts).toEqual([
      { value: "pack", count: 2 },
      { value: "custom", count: 1 },
    ]);
  });

  it("is unaffected by the facet's own current selection", () => {
    const withSelection = parsePolicyFilters({ source: "custom" });
    const without = parsePolicyFilters({});
    expect(facetCounts(CORPUS, withSelection, PACKS, "source", ["pack", "custom"])).toEqual(facetCounts(CORPUS, without, PACKS, "source", ["pack", "custom"]),);
  });
});

describe("sortPolicies", () => {
  it("puts the noisiest first by default and zero-open last", () => {
    const out = sortPolicies(CORPUS, "open_desc").map((p) => p.slug);
    expect(out).toEqual(["okta-admin-no-mfa", "gh-2fa", "my-custom", "okta-dormant-admin"]);
  });

  it("ranks severity critical → low", () => {
    const out = sortPolicies(CORPUS, "severity").map((p) => p.severity);
    expect(out).toEqual(["critical", "high", "medium", "low"]);
  });

  it("sorts never-run policies last rather than treating them as oldest", () => {
    const items = [
      policy({ slug: "never", last_evaluated_at: null }),
      policy({ slug: "old", last_evaluated_at: "2026-01-01T00:00:00Z" }),
      policy({ slug: "recent", last_evaluated_at: "2026-08-01T00:00:00Z" }),
    ];
    expect(sortPolicies(items, "last_run").map((p) => p.slug)).toEqual(["recent", "old", "never"]);
  });

  it("does not mutate the input array", () => {
    const before = CORPUS.map((p) => p.slug);
    sortPolicies(CORPUS, "title");
    expect(CORPUS.map((p) => p.slug)).toEqual(before);
  });
});

describe("applicationsPresent", () => {
  it("returns sorted distinct apps and skips nulls", () => {
    expect(applicationsPresent(CORPUS)).toEqual(["github", "okta"]);
  });
});

describe("pack filter", () => {
  it("narrows to policies installed from the named pack", () => {
    const f = parsePolicyFilters({ pack: "okta-posture" });
    expect(f.pack).toBe("okta-posture");
    expect(hasActiveFilters(f)).toBe(true);
    expect(policyFiltersToParams(f).toString()).toBe("pack=okta-posture");
    expect(applyPolicyFilters(CORPUS, f, PACKS).map((p) => p.slug)).toEqual([
      "okta-admin-no-mfa",
      "okta-dormant-admin",
    ]);
  });

  it("matches nothing for a pack with no installed policies", () => {
    const f = parsePolicyFilters({ pack: "slack-posture" });
    expect(applyPolicyFilters(CORPUS, f, PACKS)).toEqual([]);
  });

  it("narrows other facets' chip counts", () => {
    const f = parsePolicyFilters({ pack: "github-posture" });
    expect(facetCounts(CORPUS, f, PACKS, "has_open", ["true", "false"])).toEqual([
      { value: "true", count: 1 },
      { value: "false", count: 0 },
    ]);
  });
});
