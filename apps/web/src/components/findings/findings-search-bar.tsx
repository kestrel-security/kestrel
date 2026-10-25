// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useMemo, useState, useTransition } from "react";

import {
  deleteFindingPreset,
  saveFindingPreset,
  setFindingPresetFavorite,
  touchFindingPreset,
} from "@/lib/actions/findings";
import { FilterChip } from "@/components/ui/filter-chip";
import {
  activeFindingsQueue,
  findingsActiveChips,
  findingsHref,
  findingsQueueFilters,
  formatFindingsQuery,
  parseFindingsQuery,
  removeFindingsChip,
  type FindingsQueue,
  type FindingsSearchFilters,
} from "@/lib/findings-search";
import type { FindingFilterPreset, Operator, PolicySummary } from "@/lib/types";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const STATUSES = ["open", "resolved", "exception", "suppressed", "muted"] as const;
const AGE_OPTIONS = [
  { days: "7", label: "≥ 7 days" },
  { days: "30", label: "≥ 30 days" },
  { days: "90", label: "≥ 90 days" },
] as const;

type QueueCounts = {
  open_total: number;
  open_unassigned: number;
  open_assigned_to_me: number;
};

function filtersHref(filters: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === null || value === "") continue;
    if (key === "unassigned") {
      if (value === true || value === "true" || value === "1") params.set("unassigned", "true");
      continue;
    }
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `/findings?${qs}` : "/findings";
}

function mergeFilter(
  current: FindingsSearchFilters,
  patch: Partial<FindingsSearchFilters>,
): FindingsSearchFilters {
  const next = { ...current, ...patch };
  if (patch.unassigned === "true") delete next.assigned_to_operator_id;
  if (patch.assigned_to_operator_id) delete next.unassigned;
  if (patch.open_older_than_days && !next.status) next.status = "open";
  return next;
}

export function FindingsSearchBar({
  filters,
  meOperatorId,
  operators,
  policies,
  queues,
  favorites,
  recent,
}: {
  filters: FindingsSearchFilters;
  meOperatorId: string | null;
  operators: Operator[];
  policies: PolicySummary[];
  queues: QueueCounts | null;
  favorites: FindingFilterPreset[];
  recent: FindingFilterPreset[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const addFilterId = useId();
  const viewsId = useId();

  const filterKey = [
    filters.search,
    filters.severity,
    filters.status,
    filters.policy_slug,
    filters.assigned_to_operator_id,
    filters.unassigned,
    filters.open_older_than_days,
    filters.subject_id,
    filters.subject_type,
    filters.application_instance_id,
    meOperatorId,
  ].join("|");

  const initialQuery = useMemo(
    () => formatFindingsQuery(filters, { meOperatorId }),
    // filterKey encodes URL filter fields + me; filters object identity changes each render from RSC.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- intentional sync key
    [filterKey],
  );

  const [query, setQuery] = useState(initialQuery);
  const [addOpen, setAddOpen] = useState(false);
  const [viewsOpen, setViewsOpen] = useState(false);
  const [presetName, setPresetName] = useState("");
  const [presetError, setPresetError] = useState<string | null>(null);

  useEffect(() => {
    setQuery(initialQuery);
  }, [initialQuery]);

  const chips = findingsActiveChips(filters, {
    meOperatorId,
    operatorLabel: (id) => {
      const op = operators.find((o) => o.id === id);
      return op?.display_name ?? op?.email ?? id.slice(0, 8);
    },
  });
  const hasFilters = chips.length > 0;

  const navigate = (next: FindingsSearchFilters) => {
    router.push(findingsHref(next));
  };

  const submitQuery = (raw: string) => {
    const parsed = parseFindingsQuery(raw, { meOperatorId });
    // Preserve deep-link scope params unless the user cleared everything.
    if (!raw.trim()) {
      navigate({});
      return;
    }
    const next: FindingsSearchFilters = { ...parsed };
    if (!("subject_id" in parsed) && filters.subject_id) next.subject_id = filters.subject_id;
    if (!("subject_type" in parsed) && filters.subject_type) next.subject_type = filters.subject_type;
    if (!("application_instance_id" in parsed) && filters.application_instance_id) {
      next.application_instance_id = filters.application_instance_id;
    }
    navigate(next);
  };

  const activeQueue = activeFindingsQueue(filters, meOperatorId);
  const queueClass = (queue: FindingsQueue) =>
    activeQueue === queue
      ? "font-medium text-foreground underline-offset-2 hover:underline"
      : "hover:text-foreground hover:underline";

  const refresh = () => router.refresh();

  return (
    <div className="mb-6 space-y-3">
      {/* The search <form> holds only the input and Search: the Views popover has
          a form of its own, and nesting forms is invalid HTML (and a hydration
          error). */}
      <div className="flex flex-wrap items-stretch gap-2">
        <form
          role="search"
          className="flex w-full min-w-0 items-stretch gap-2 sm:w-auto sm:min-w-[16rem] sm:flex-1"
          onSubmit={(e) => {
            e.preventDefault();
            submitQuery(query);
          }}
        >
          <label className="sr-only" htmlFor="findings-search-q">
            Search findings
          </label>
          <input
            id="findings-search-q"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='Search or try severity:high status:open assignee:me policy:… age:>=7'
            autoComplete="off"
            spellCheck={false}
            className="min-h-11 min-w-0 flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-base outline-none ring-offset-background placeholder:text-muted-foreground/80 focus:border-foreground/40 focus:ring-2 focus:ring-foreground/10"
          />
          <button
            type="submit"
            className="rounded-lg border border-transparent bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            Search
          </button>
        </form>

        <div className="relative">
          <button
            type="button"
            aria-expanded={addOpen}
            aria-controls={addFilterId}
            onClick={() => {
              setAddOpen((o) => !o);
              setViewsOpen(false);
            }}
            className="h-full min-h-11 rounded-lg border border-border px-3 text-sm hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            Add filter
          </button>
          {addOpen ? (
            <div
              id={addFilterId}
              className="absolute right-0 z-20 mt-1 w-[min(100vw-2rem,22rem)] rounded-lg border border-border bg-popover p-3 text-popover-foreground shadow-md"
            >
              <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Add filter
              </p>
              <div className="space-y-3 text-sm">
                <label className="flex flex-col gap-1">
                  <span className="text-muted-foreground">Severity</span>
                  <select
                    className="rounded-md border border-border bg-background px-2 py-1.5"
                    defaultValue=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (!v) return;
                      navigate(mergeFilter(filters, { severity: v }));
                      setAddOpen(false);
                    }}
                  >
                    <option value="">Select…</option>
                    {SEVERITIES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-muted-foreground">Status</span>
                  <select
                    className="rounded-md border border-border bg-background px-2 py-1.5"
                    defaultValue=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (!v) return;
                      navigate(mergeFilter(filters, { status: v }));
                      setAddOpen(false);
                    }}
                  >
                    <option value="">Select…</option>
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-muted-foreground">Open age</span>
                  <select
                    className="rounded-md border border-border bg-background px-2 py-1.5"
                    defaultValue=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (!v) return;
                      navigate(mergeFilter(filters, { open_older_than_days: v, status: "open" }));
                      setAddOpen(false);
                    }}
                  >
                    <option value="">Select…</option>
                    {AGE_OPTIONS.map((a) => (
                      <option key={a.days} value={a.days}>
                        {a.label}
                      </option>
                    ))}
                  </select>
                </label>
                {policies.length > 0 ? (
                  <label className="flex flex-col gap-1">
                    <span className="text-muted-foreground">Policy</span>
                    <select
                      className="rounded-md border border-border bg-background px-2 py-1.5"
                      defaultValue=""
                      onChange={(e) => {
                        const v = e.target.value;
                        if (!v) return;
                        navigate(mergeFilter(filters, { policy_slug: v }));
                        setAddOpen(false);
                      }}
                    >
                      <option value="">Select…</option>
                      {policies.slice(0, 40).map((p) => (
                        <option key={p.id} value={p.slug}>
                          {p.slug}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
                <label className="flex flex-col gap-1">
                  <span className="text-muted-foreground">Assignee</span>
                  <select
                    className="rounded-md border border-border bg-background px-2 py-1.5"
                    defaultValue=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (!v) return;
                      if (v === "unassigned") {
                        navigate(mergeFilter(filters, { unassigned: "true" }));
                      } else {
                        navigate(mergeFilter(filters, { assigned_to_operator_id: v }));
                      }
                      setAddOpen(false);
                    }}
                  >
                    <option value="">Select…</option>
                    <option value="unassigned">Unassigned</option>
                    {meOperatorId ? <option value={meOperatorId}>Me</option> : null}
                    {operators
                      .filter((o) => o.id !== meOperatorId)
                      .map((op) => (
                        <option key={op.id} value={op.id}>
                          {op.display_name ?? op.email}
                        </option>
                      ))}
                  </select>
                </label>
              </div>
              <button
                type="button"
                className="mt-3 text-xs text-muted-foreground hover:underline"
                onClick={() => setAddOpen(false)}
              >
                Close
              </button>
            </div>
          ) : null}
        </div>

        <div className="relative">
          <button
            type="button"
            aria-expanded={viewsOpen}
            aria-controls={viewsId}
            onClick={() => {
              setViewsOpen((o) => !o);
              setAddOpen(false);
            }}
            className="h-full min-h-11 rounded-lg border border-border px-3 text-sm hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            Views
          </button>
          {viewsOpen ? (
            <div
              id={viewsId}
              className="absolute right-0 z-20 mt-1 w-[min(100vw-2rem,24rem)] rounded-lg border border-border bg-popover p-3 text-popover-foreground shadow-md"
            >
              {hasFilters ? (
                <form
                  className="mb-3 flex flex-wrap gap-2 border-b border-border pb-3"
                  onSubmit={(e) => {
                    e.preventDefault();
                    const label = presetName.trim();
                    if (!label) return;
                    startTransition(async () => {
                      setPresetError(null);
                      const sparse: Record<string, unknown> = {};
                      for (const [key, value] of Object.entries(filters)) {
                        if (value === undefined || value === "") continue;
                        if (key === "unassigned") {
                          sparse.unassigned = true;
                          continue;
                        }
                        if (key === "open_older_than_days") {
                          const days = Number.parseInt(String(value), 10);
                          if (!Number.isNaN(days)) sparse.open_older_than_days = days;
                          continue;
                        }
                        sparse[key] = value;
                      }
                      const result = await saveFindingPreset(label, sparse);
                      if (!result.ok) {
                        setPresetError(result.error);
                        return;
                      }
                      setPresetName("");
                      refresh();
                    });
                  }}
                >
                  <input
                    value={presetName}
                    onChange={(e) => setPresetName(e.target.value)}
                    maxLength={120}
                    aria-label="Saved view name"
                    placeholder="Save view as…"
                    className="min-w-0 flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-sm"
                  />
                  <button
                    type="submit"
                    disabled={pending || !presetName.trim()}
                    className="rounded-md border border-border px-2 py-1.5 text-sm hover:bg-muted disabled:opacity-50"
                  >
                    Save
                  </button>
                  {presetError ? (
                    <p role="alert" className="w-full text-sm text-destructive">
                      {presetError}
                    </p>
                  ) : null}
                </form>
              ) : (
                <p className="mb-3 text-sm text-muted-foreground">
                  Apply filters, then save a named view.
                </p>
              )}

              {favorites.length === 0 && recent.length === 0 ? (
                <p className="text-sm text-muted-foreground">No saved views yet.</p>
              ) : (
                <ul className="max-h-64 space-y-1 overflow-y-auto text-sm">
                  {[...favorites, ...recent.filter((r) => !favorites.some((f) => f.id === r.id))].map(
                    (preset) => (
                      <li
                        key={preset.id}
                        className="flex items-center justify-between gap-2 rounded-md px-1 py-1 hover:bg-muted/60"
                      >
                        <button
                          type="button"
                          disabled={pending}
                          className="min-w-0 flex-1 truncate text-left hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
                          onClick={() => {
                            // Only the "recent" ordering depends on this; never
                            // hold up (or fail) opening the view on it.
                            void touchFindingPreset(preset.id).catch(() => undefined);
                            setPresetError(null);
                            setViewsOpen(false);
                            router.push(filtersHref(preset.filters));
                          }}
                        >
                          {preset.is_favorite ? "★ " : ""}
                          {preset.name}
                        </button>
                        <button
                          type="button"
                          disabled={pending}
                          title={preset.is_favorite ? "Unfavorite" : "Favorite"}
                          aria-label={
                            preset.is_favorite
                              ? `Unfavorite view “${preset.name}”`
                              : `Favorite view “${preset.name}”`
                          }
                          className="shrink-0 px-1 text-xs text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
                          onClick={() =>
                            startTransition(async () => {
                              setPresetError(null);
                              const result = await setFindingPresetFavorite(preset.id, !preset.is_favorite);
                              if (!result.ok) {
                                setPresetError(result.error);
                                return;
                              }
                              refresh();
                            })
                          }
                        >
                          {preset.is_favorite ? "★" : "☆"}
                        </button>
                        <button
                          type="button"
                          disabled={pending}
                          title="Remove"
                          aria-label={`Remove view “${preset.name}”`}
                          className="shrink-0 px-1 text-xs text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
                          onClick={() =>
                            startTransition(async () => {
                              setPresetError(null);
                              const result = await deleteFindingPreset(preset.id);
                              if (!result.ok) {
                                setPresetError(result.error);
                                return;
                              }
                              refresh();
                            })
                          }
                        >
                          ✕
                        </button>
                      </li>
                    ),
                  )}
                </ul>
              )}
              {presetError && !hasFilters ? (
                <p role="alert" className="mt-2 text-sm text-destructive">
                  {presetError}
                </p>
              ) : null}
              <button
                type="button"
                className="mt-3 text-xs text-muted-foreground hover:underline"
                onClick={() => setViewsOpen(false)}
              >
                Close
              </button>
            </div>
          ) : null}
        </div>
      </div>

      {chips.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          {chips.map((chip) => (
            <FilterChip
              key={`${chip.key}:${chip.value}`}
              label={chip.label}
              active
              onRemove={() => navigate(removeFindingsChip(filters, chip.key))}
            />
          ))}
          <Link href="/findings" className="text-sm text-muted-foreground hover:underline">
            Clear all
          </Link>
        </div>
      ) : null}

      {queues ? (
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
          <span className="sr-only">Queues</span>
          {/* Counts are org-wide open findings, so each chip opens exactly that
              set rather than adding to the current filters. */}
          <Link
            href={findingsHref(findingsQueueFilters("open", meOperatorId))}
            aria-current={activeQueue === "open" ? "page" : undefined}
            className={queueClass("open")}
          >
            Open <span className="tabular-nums">{queues.open_total}</span>
          </Link>
          <span aria-hidden>·</span>
          <Link
            href={findingsHref(findingsQueueFilters("unassigned", meOperatorId))}
            aria-current={activeQueue === "unassigned" ? "page" : undefined}
            className={queueClass("unassigned")}
          >
            Open, unassigned <span className="tabular-nums">{queues.open_unassigned}</span>
          </Link>
          {meOperatorId ? (
            <>
              <span aria-hidden>·</span>
              <Link
                href={findingsHref(findingsQueueFilters("mine", meOperatorId))}
                aria-current={activeQueue === "mine" ? "page" : undefined}
                className={queueClass("mine")}
              >
                Open, mine <span className="tabular-nums">{queues.open_assigned_to_me}</span>
              </Link>
            </>
          ) : null}
        </p>
      ) : null}

      <p className="text-xs text-muted-foreground">
        Tokens:{" "}
        <code className="rounded bg-muted px-1 py-0.5">severity:</code>{" "}
        <code className="rounded bg-muted px-1 py-0.5">status:</code>{" "}
        <code className="rounded bg-muted px-1 py-0.5">policy:</code>{" "}
        <code className="rounded bg-muted px-1 py-0.5">assignee:me</code>{" "}
        <code className="rounded bg-muted px-1 py-0.5">age:&gt;=7</code>
      </p>
    </div>
  );
}
