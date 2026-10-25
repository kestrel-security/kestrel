// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Findings advanced search: parse/serialize query tokens ↔ URL params. */

export type FindingsSearchFilters = {
  search?: string;
  severity?: string;
  status?: string;
  policy_slug?: string;
  assigned_to_operator_id?: string;
  unassigned?: string;
  open_older_than_days?: string;
  subject_id?: string;
  subject_type?: string;
  application_instance_id?: string;
};

const SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const STATUSES = new Set(["open", "resolved", "exception", "suppressed", "muted"]);

/** Split on spaces but keep quoted phrases intact. */
function tokenize(input: string): string[] {
  const tokens: string[] = [];
  const re = /"([^"]*)"|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(input)) !== null) {
    tokens.push(match[1] !== undefined ? match[1] : match[2]);
  }
  return tokens;
}

/**
 * Parse a command-bar query into findings list filters.
 * Tokens: severity:, status:, policy: / policy_slug:, assignee:me|unassigned|<uuid>,
 * age:>N | age:>=N | age:N. Remaining text becomes `search`.
 */
export function parseFindingsQuery(
  raw: string,
  opts?: { meOperatorId?: string | null },
): FindingsSearchFilters {
  const filters: FindingsSearchFilters = {};
  const free: string[] = [];
  const meId = opts?.meOperatorId ?? null;

  for (const token of tokenize(raw.trim())) {
    const colon = token.indexOf(":");
    if (colon <= 0) {
      free.push(token);
      continue;
    }
    const key = token.slice(0, colon).toLowerCase();
    const value = token.slice(colon + 1).trim();
    if (!value) {
      free.push(token);
      continue;
    }

    if (key === "severity" && SEVERITIES.has(value.toLowerCase())) {
      filters.severity = value.toLowerCase();
      continue;
    }
    if (key === "status" && STATUSES.has(value.toLowerCase())) {
      filters.status = value.toLowerCase();
      continue;
    }
    if (key === "policy" || key === "policy_slug") {
      filters.policy_slug = value;
      continue;
    }
    if (key === "assignee") {
      const v = value.toLowerCase();
      if (v === "unassigned" || v === "none") {
        filters.unassigned = "true";
        delete filters.assigned_to_operator_id;
      } else if (v === "me" && meId) {
        filters.assigned_to_operator_id = meId;
        delete filters.unassigned;
      } else {
        filters.assigned_to_operator_id = value;
        delete filters.unassigned;
      }
      continue;
    }
    if (key === "unassigned" && ["true", "1", "yes"].includes(value.toLowerCase())) {
      filters.unassigned = "true";
      delete filters.assigned_to_operator_id;
      continue;
    }
    if (key === "age") {
      const m = value.match(/^>=?(\d+)$/) || value.match(/^>(\d+)$/) || value.match(/^(\d+)$/);
      if (m) {
        filters.open_older_than_days = m[1];
        // Aging queues imply open triage unless status was set earlier in this parse —
        // prefer explicit status if already present.
        if (!filters.status) filters.status = "open";
      }
      continue;
    }
    if (key === "subject_type") {
      filters.subject_type = value.toLowerCase();
      continue;
    }
    if (key === "subject_id") {
      filters.subject_id = value;
      continue;
    }
    if (key === "app" || key === "application_instance_id") {
      filters.application_instance_id = value;
      continue;
    }

    free.push(token);
  }

  const search = free.join(" ").trim();
  if (search) filters.search = search;
  return filters;
}

/** Build a command-bar string from structured filters (for display / edit). */
export function formatFindingsQuery(
  filters: FindingsSearchFilters,
  opts?: { meOperatorId?: string | null },
): string {
  const parts: string[] = [];
  if (filters.severity) parts.push(`severity:${filters.severity}`);
  if (filters.status) parts.push(`status:${filters.status}`);
  if (filters.policy_slug) parts.push(`policy:${filters.policy_slug}`);
  if (filters.unassigned === "true" || filters.unassigned === "1") {
    parts.push("assignee:unassigned");
  } else if (filters.assigned_to_operator_id) {
    if (opts?.meOperatorId && filters.assigned_to_operator_id === opts.meOperatorId) {
      parts.push("assignee:me");
    } else {
      parts.push(`assignee:${filters.assigned_to_operator_id}`);
    }
  }
  if (filters.open_older_than_days) parts.push(`age:>=${filters.open_older_than_days}`);
  if (filters.subject_type) parts.push(`subject_type:${filters.subject_type}`);
  if (filters.subject_id) parts.push(`subject_id:${filters.subject_id}`);
  if (filters.application_instance_id) {
    parts.push(`app:${filters.application_instance_id}`);
  }
  if (filters.search) {
    parts.push(filters.search.includes(" ") ? `"${filters.search}"` : filters.search);
  }
  return parts.join(" ");
}

export function findingsFiltersToParams(filters: FindingsSearchFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  return params;
}

export function findingsHref(filters: FindingsSearchFilters): string {
  const qs = findingsFiltersToParams(filters).toString();
  return qs ? `/findings?${qs}` : "/findings";
}

export type FindingsChip = {
  key: keyof FindingsSearchFilters;
  label: string;
  /** Param value for toggle-off */
  value: string;
};

export function findingsActiveChips(
  filters: FindingsSearchFilters,
  opts?: {
    meOperatorId?: string | null;
    operatorLabel?: (id: string) => string;
  },
): FindingsChip[] {
  const chips: FindingsChip[] = [];
  if (filters.search) chips.push({ key: "search", label: `“${filters.search}”`, value: filters.search });
  if (filters.severity) {
    chips.push({ key: "severity", label: `severity:${filters.severity}`, value: filters.severity });
  }
  if (filters.status) {
    chips.push({ key: "status", label: `status:${filters.status}`, value: filters.status });
  }
  if (filters.policy_slug) {
    chips.push({
      key: "policy_slug",
      label: `policy:${filters.policy_slug}`,
      value: filters.policy_slug,
    });
  }
  if (filters.unassigned === "true" || filters.unassigned === "1") {
    chips.push({ key: "unassigned", label: "assignee:unassigned", value: "true" });
  } else if (filters.assigned_to_operator_id) {
    const id = filters.assigned_to_operator_id;
    const label =
      opts?.meOperatorId && id === opts.meOperatorId
        ? "assignee:me"
        : `assignee:${opts?.operatorLabel?.(id) ?? id.slice(0, 8)}`;
    chips.push({ key: "assigned_to_operator_id", label, value: id });
  }
  if (filters.open_older_than_days) {
    chips.push({
      key: "open_older_than_days",
      label: `age:≥${filters.open_older_than_days}d`,
      value: filters.open_older_than_days,
    });
  }
  if (filters.subject_type) {
    chips.push({
      key: "subject_type",
      label: `subject:${filters.subject_type}`,
      value: filters.subject_type,
    });
  }
  if (filters.subject_id) {
    chips.push({
      key: "subject_id",
      label: `subject_id:${filters.subject_id.slice(0, 8)}…`,
      value: filters.subject_id,
    });
  }
  if (filters.application_instance_id) {
    chips.push({
      key: "application_instance_id",
      label: `app:${filters.application_instance_id.slice(0, 8)}…`,
      value: filters.application_instance_id,
    });
  }
  return chips;
}

export function removeFindingsChip(
  filters: FindingsSearchFilters,
  key: keyof FindingsSearchFilters,
): FindingsSearchFilters {
  const next = { ...filters };
  delete next[key];
  if (key === "unassigned") delete next.assigned_to_operator_id;
  if (key === "assigned_to_operator_id") delete next.unassigned;
  return next;
}

export type FindingsQueue = "open" | "unassigned" | "mine";

/**
 * The list filters behind an ownership-queue chip. `GET /findings/queues`
 * counts open findings across the whole org, so each chip links to exactly
 * that set -- status:open and nothing else from the current view -- and the
 * number on the chip matches the list it opens.
 */
export function findingsQueueFilters(
  queue: FindingsQueue,
  meOperatorId: string | null,
): FindingsSearchFilters {
  switch (queue) {
    case "open":
      return { status: "open" };
    case "unassigned":
      return { status: "open", unassigned: "true" };
    case "mine":
      return meOperatorId
        ? { status: "open", assigned_to_operator_id: meOperatorId }
        : { status: "open" };
  }
}

/** The queue the current filters show exactly, or null when they show anything else. */
export function activeFindingsQueue(
  filters: FindingsSearchFilters,
  meOperatorId: string | null,
): FindingsQueue | null {
  const current = findingsFiltersToParams({
    ...filters,
    unassigned: filters.unassigned === "1" ? "true" : filters.unassigned,
  });
  current.sort();
  const queues: FindingsQueue[] = meOperatorId ? ["open", "unassigned", "mine"] : ["open", "unassigned"];
  for (const queue of queues) {
    const params = findingsFiltersToParams(findingsQueueFilters(queue, meOperatorId));
    params.sort();
    if (params.toString() === current.toString()) return queue;
  }
  return null;
}
