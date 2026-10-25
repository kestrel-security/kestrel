// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/** Changes investigation search: parse/serialize query tokens ↔ URL params. */

export type ChangesSearchFilters = {
  search?: string;
  change_class?: string;
  min_significance?: string;
  connector_instance_id?: string;
  window_hours?: string;
  person?: string;
  app?: string;
};

const SIGNIFICANCES = new Set(["high", "medium", "low"]);

/** Split on spaces but keep `key:"quoted value"` and quoted phrases intact. */
function tokenize(input: string): string[] {
  const tokens: string[] = [];
  const re = /\w+:"[^"]*"|\w+:\S+|"[^"]*"|\S+/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(input)) !== null) {
    tokens.push(match[0]);
  }
  return tokens;
}

/**
 * Parse a command-bar query into Changes list filters.
 * Tokens: class:, significance:, app:, person:. Remaining text becomes `search`.
 */
export function parseChangesQuery(raw: string): ChangesSearchFilters {
  const filters: ChangesSearchFilters = {};
  const free: string[] = [];

  for (const token of tokenize(raw.trim())) {
    const colon = token.indexOf(":");
    if (colon <= 0) {
      free.push(token.startsWith('"') && token.endsWith('"') ? token.slice(1, -1) : token);
      continue;
    }
    const key = token.slice(0, colon).toLowerCase();
    let value = token.slice(colon + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      value = value.slice(1, -1);
    }
    if (!value) {
      free.push(token);
      continue;
    }

    if (key === "class" || key === "change_class") {
      filters.change_class = value;
      continue;
    }
    if (
      (key === "significance" || key === "min_significance") &&
      SIGNIFICANCES.has(value.toLowerCase())
    ) {
      filters.min_significance = value.toLowerCase();
      continue;
    }
    if (key === "person" || key === "identity" || key === "user") {
      filters.person = value;
      continue;
    }
    if (key === "app" || key === "application") {
      filters.app = value;
      continue;
    }

    free.push(token);
  }

  const search = free.join(" ").trim();
  if (search) filters.search = search;
  return filters;
}

/** Build a command-bar string from structured filters (for display / edit). */
export function formatChangesQuery(filters: ChangesSearchFilters): string {
  const parts: string[] = [];
  if (filters.change_class) parts.push(`class:${filters.change_class}`);
  if (filters.min_significance && filters.min_significance !== "medium") {
    parts.push(`significance:${filters.min_significance}`);
  }
  if (filters.person) {
    parts.push(filters.person.includes(" ") ? `person:"${filters.person}"` : `person:${filters.person}`);
  }
  if (filters.app) {
    parts.push(filters.app.includes(" ") ? `app:"${filters.app}"` : `app:${filters.app}`);
  }
  if (filters.search) {
    parts.push(filters.search.includes(" ") ? `"${filters.search}"` : filters.search);
  }
  return parts.join(" ");
}

/** Merge token-derived fields into a single `search` string for the API. */
export function changesFiltersToSearchParam(filters: ChangesSearchFilters): string {
  return formatChangesQuery({
    search: filters.search,
    change_class: undefined,
    min_significance: undefined,
    person: filters.person,
    app: filters.app,
  });
}

export function changesFiltersToParams(filters: ChangesSearchFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.window_hours) params.set("window_hours", filters.window_hours);
  if (filters.change_class) params.set("change_class", filters.change_class);
  if (filters.min_significance && filters.min_significance !== "medium") {
    params.set("min_significance", filters.min_significance);
  }
  if (filters.connector_instance_id) {
    params.set("connector_instance_id", filters.connector_instance_id);
  }
  const search = changesFiltersToSearchParam(filters);
  if (search) params.set("search", search);
  return params;
}

export function changesHref(filters: ChangesSearchFilters): string {
  const qs = changesFiltersToParams(filters).toString();
  return qs ? `/changes?${qs}` : "/changes";
}

export type ChangesChip = {
  key: keyof ChangesSearchFilters;
  label: string;
  value: string;
};

export function changesActiveChips(filters: ChangesSearchFilters): ChangesChip[] {
  const chips: ChangesChip[] = [];
  if (filters.search) {
    chips.push({ key: "search", label: `“${filters.search}”`, value: filters.search });
  }
  if (filters.person) {
    chips.push({ key: "person", label: `person:${filters.person}`, value: filters.person });
  }
  if (filters.app) {
    chips.push({ key: "app", label: `app:${filters.app}`, value: filters.app });
  }
  if (filters.change_class) {
    chips.push({
      key: "change_class",
      label: `class:${filters.change_class.replace(/_/g, " ")}`,
      value: filters.change_class,
    });
  }
  if (filters.min_significance && filters.min_significance !== "medium") {
    chips.push({
      key: "min_significance",
      label: `significance:${filters.min_significance}`,
      value: filters.min_significance,
    });
  }
  if (filters.connector_instance_id) {
    chips.push({
      key: "connector_instance_id",
      label: `connector:${filters.connector_instance_id.slice(0, 8)}…`,
      value: filters.connector_instance_id,
    });
  }
  return chips;
}

export function removeChangesChip(
  filters: ChangesSearchFilters,
  key: keyof ChangesSearchFilters,
): ChangesSearchFilters {
  const next = { ...filters };
  delete next[key];
  return next;
}

/** Reconstruct filters from URL search params (and optional embedded tokens). */
export function changesFiltersFromParams(params: {
  search?: string;
  change_class?: string;
  min_significance?: string;
  connector_instance_id?: string;
  window_hours?: string;
}): ChangesSearchFilters {
  const fromTokens = parseChangesQuery(params.search ?? "");
  return {
    window_hours: params.window_hours,
    change_class: params.change_class || fromTokens.change_class,
    min_significance: params.min_significance || fromTokens.min_significance || "medium",
    connector_instance_id: params.connector_instance_id,
    search: fromTokens.search,
    person: fromTokens.person,
    app: fromTokens.app,
  };
}
