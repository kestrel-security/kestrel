// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";

import {
  activeFindingsQueue,
  findingsActiveChips,
  findingsFiltersToParams,
  findingsHref,
  findingsQueueFilters,
  formatFindingsQuery,
  parseFindingsQuery,
  removeFindingsChip,
} from "./findings-search";

describe("parseFindingsQuery", () => {
  it("parses severity, status, policy, age, and free text", () => {
    const f = parseFindingsQuery(
      'severity:high status:open policy:github-org-2fa-not-required age:>=7 "2fa org"',
    );
    expect(f.severity).toBe("high");
    expect(f.status).toBe("open");
    expect(f.policy_slug).toBe("github-org-2fa-not-required");
    expect(f.open_older_than_days).toBe("7");
    expect(f.search).toBe("2fa org");
  });

  it("maps assignee:me and assignee:unassigned", () => {
    const me = parseFindingsQuery("assignee:me", { meOperatorId: "op-1" });
    expect(me.assigned_to_operator_id).toBe("op-1");
    expect(me.unassigned).toBeUndefined();

    const u = parseFindingsQuery("assignee:unassigned");
    expect(u.unassigned).toBe("true");
    expect(u.assigned_to_operator_id).toBeUndefined();
  });

  it("sets status=open for age when status omitted", () => {
    const f = parseFindingsQuery("age:30");
    expect(f.open_older_than_days).toBe("30");
    expect(f.status).toBe("open");
  });

  it("keeps an explicit earlier status when age also implies open", () => {
    const f = parseFindingsQuery("status:resolved age:30");
    expect(f.status).toBe("resolved");
    expect(f.open_older_than_days).toBe("30");
  });

  it("treats assignee:<uuid> as a direct operator id", () => {
    const f = parseFindingsQuery("assignee:op-42");
    expect(f.assigned_to_operator_id).toBe("op-42");
    expect(f.unassigned).toBeUndefined();
  });

  it("falls back to assignee:me literal text when no meOperatorId is given", () => {
    const f = parseFindingsQuery("assignee:me");
    // No meOperatorId supplied, so "me" is treated as a literal operator id.
    expect(f.assigned_to_operator_id).toBe("me");
  });

  it("rejects an unrecognized severity or status as a keyword", () => {
    const f = parseFindingsQuery("severity:extreme status:pending");
    expect(f.severity).toBeUndefined();
    expect(f.status).toBeUndefined();
    expect(f.search).toBe("severity:extreme status:pending");
  });

  it("parses subject_type, subject_id, and app tokens", () => {
    const f = parseFindingsQuery("subject_type:IDENTITY subject_id:abc123 app:app-1");
    expect(f.subject_type).toBe("identity");
    expect(f.subject_id).toBe("abc123");
    expect(f.application_instance_id).toBe("app-1");
  });
});

describe("formatFindingsQuery + chips", () => {
  it("round-trips structured filters", () => {
    const filters = {
      severity: "critical",
      status: "open",
      assigned_to_operator_id: "op-1",
    };
    const q = formatFindingsQuery(filters, { meOperatorId: "op-1" });
    expect(q).toBe("severity:critical status:open assignee:me");
    const again = parseFindingsQuery(q, { meOperatorId: "op-1" });
    expect(again.severity).toBe("critical");
    expect(again.assigned_to_operator_id).toBe("op-1");
  });

  it("builds href and removes chips", () => {
    expect(findingsHref({ status: "open", severity: "high" })).toBe(
      "/findings?status=open&severity=high",
    );
    const next = removeFindingsChip({ status: "open", severity: "high" }, "severity");
    expect(next.severity).toBeUndefined();
    expect(next.status).toBe("open");
    const chips = findingsActiveChips({ unassigned: "true" });
    expect(chips.length).toBe(1);
    expect(chips[0].key).toBe("unassigned");
  });

  it("quotes a free-text search containing spaces", () => {
    expect(formatFindingsQuery({ search: "2fa org" })).toBe('"2fa org"');
    expect(formatFindingsQuery({ search: "solo" })).toBe("solo");
  });
});

describe("findingsFiltersToParams", () => {
  it("drops undefined, null, and empty-string values", () => {
    const params = findingsFiltersToParams({
      severity: "high",
      status: "",
      subject_id: undefined,
    });
    expect(params.get("severity")).toBe("high");
    expect(params.has("status")).toBe(false);
    expect(params.has("subject_id")).toBe(false);
  });
});

describe("findingsActiveChips", () => {
  it("labels the assignee chip with a resolved operator name", () => {
    const chips = findingsActiveChips(
      { assigned_to_operator_id: "op-9" },
      { operatorLabel: (id) => `Operator ${id}` },
    );
    expect(chips[0]).toEqual({
      key: "assigned_to_operator_id",
      label: "assignee:Operator op-9",
      value: "op-9",
    });
  });

  it("falls back to a truncated id when no operatorLabel is given", () => {
    const chips = findingsActiveChips({ assigned_to_operator_id: "0123456789abcdef" });
    expect(chips[0].label).toBe("assignee:01234567");
  });

  it("truncates subject_id and application_instance_id chip values", () => {
    const chips = findingsActiveChips({
      subject_id: "0123456789abcdef",
      application_instance_id: "fedcba9876543210",
    });
    expect(chips.find((c) => c.key === "subject_id")?.label).toBe("subject_id:01234567…");
    expect(chips.find((c) => c.key === "application_instance_id")?.label).toBe(
      "app:fedcba98…",
    );
  });
});

describe("removeFindingsChip", () => {
  it("clears assigned_to_operator_id when removing the unassigned chip and vice versa", () => {
    expect(
      removeFindingsChip({ unassigned: "true", severity: "high" }, "unassigned"),
    ).toEqual({ severity: "high" });
    expect(
      removeFindingsChip({ assigned_to_operator_id: "op-1", severity: "high" }, "assigned_to_operator_id"),
    ).toEqual({ severity: "high" });
  });
});

describe("findings queues", () => {
  const ME = "op-me";

  it("links every queue chip to open findings only, like its count", () => {
    expect(findingsHref(findingsQueueFilters("open", ME))).toBe("/findings?status=open");
    expect(findingsHref(findingsQueueFilters("unassigned", ME))).toBe(
      "/findings?status=open&unassigned=true",
    );
    expect(findingsHref(findingsQueueFilters("mine", ME))).toBe(
      "/findings?status=open&assigned_to_operator_id=op-me",
    );
  });

  it("recognises the queue the filters show exactly", () => {
    expect(activeFindingsQueue({ status: "open" }, ME)).toBe("open");
    expect(activeFindingsQueue({ unassigned: "1", status: "open" }, ME)).toBe("unassigned");
    expect(activeFindingsQueue({ assigned_to_operator_id: ME, status: "open" }, ME)).toBe("mine");
  });

  it("treats any narrower or different view as no queue", () => {
    expect(activeFindingsQueue({}, ME)).toBeNull();
    expect(activeFindingsQueue({ assigned_to_operator_id: ME }, ME)).toBeNull();
    expect(activeFindingsQueue({ status: "open", severity: "high" }, ME)).toBeNull();
    expect(activeFindingsQueue({ status: "open", assigned_to_operator_id: "other" }, ME)).toBeNull();
    expect(activeFindingsQueue({ status: "open", assigned_to_operator_id: ME }, null)).toBeNull();
  });
});
