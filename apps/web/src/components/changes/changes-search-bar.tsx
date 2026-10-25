// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Search } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState, useTransition, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { FilterChip } from "@/components/ui/filter-chip";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  changesActiveChips,
  changesHref,
  formatChangesQuery,
  parseChangesQuery,
  removeChangesChip,
  type ChangesSearchFilters,
} from "@/lib/changes-search";
import type { ConnectorInstanceSummary } from "@/lib/types";

const WINDOWS = [
  { id: "24", label: "24 hours" },
  { id: "168", label: "7 days" },
  { id: "720", label: "30 days" },
] as const;

const SIGNIFICANCES = [
  { id: "high", label: "High only" },
  { id: "medium", label: "Medium and up" },
  { id: "low", label: "All including low" },
] as const;

function mergeFilter(
  current: ChangesSearchFilters,
  patch: Partial<ChangesSearchFilters>,
): ChangesSearchFilters {
  return { ...current, ...patch };
}

export function ChangesSearchBar({
  filters,
  connectors,
  classes,
}: {
  filters: ChangesSearchFilters;
  connectors: ConnectorInstanceSummary[];
  classes: string[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  const filterKey = [
    filters.search,
    filters.person,
    filters.app,
    filters.change_class,
    filters.min_significance,
    filters.connector_instance_id,
    filters.window_hours,
  ].join("|");

  const initialQuery = useMemo(
    () => formatChangesQuery(filters),
    // filterKey encodes URL filter fields; filters object identity changes each RSC render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [filterKey],
  );
  const [query, setQuery] = useState(initialQuery);
  useEffect(() => {
    setQuery(initialQuery);
  }, [initialQuery]);

  const chips = changesActiveChips(filters);
  const windowHours = filters.window_hours || "168";
  const significance = filters.min_significance || "medium";

  function navigate(next: ChangesSearchFilters) {
    startTransition(() => {
      router.push(changesHref(next));
    });
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    const parsed = parseChangesQuery(query);
    navigate(
      mergeFilter(filters, {
        search: parsed.search,
        person: parsed.person,
        app: parsed.app,
        change_class: parsed.change_class ?? filters.change_class,
        min_significance: parsed.min_significance ?? filters.min_significance,
      }),
    );
  }

  function onAddFilter(value: string) {
    if (!value) return;
    if (value.startsWith("class:")) {
      navigate(mergeFilter(filters, { change_class: value.slice(6) }));
    } else if (value.startsWith("connector:")) {
      navigate(mergeFilter(filters, { connector_instance_id: value.slice(10) }));
    } else if (value === "significance:high") {
      navigate(mergeFilter(filters, { min_significance: "high" }));
    } else if (value === "significance:low") {
      navigate(mergeFilter(filters, { min_significance: "low" }));
    }
  }

  return (
    <div className="mb-4 space-y-2.5">
      <form onSubmit={onSubmit} className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[20rem] flex-1">
          <Search
            aria-hidden
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
          />
          <Input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='Search people, apps…  class:admin_granted  person:grace@acme.example'
            aria-label="Search changes"
            className="pl-8"
          />
        </div>
        <Button type="submit" variant="outline" size="default" disabled={pending}>
          Search
        </Button>
        {chips.length > 0 ? (
          <Button asChild variant="ghost" size="sm">
            <Link href="/changes">Reset</Link>
          </Button>
        ) : null}
      </form>

      {chips.length > 0 ? (
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Active filters">
          {chips.map((chip) => (
            <FilterChip
              key={`${chip.key}:${chip.value}`}
              label={chip.label}
              active
              onRemove={() => navigate(removeChangesChip(filters, chip.key))}
            />
          ))}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Time window">
          {WINDOWS.map((option) => (
            <FilterChip
              key={option.id}
              label={option.label}
              active={windowHours === option.id}
              onClick={() => navigate(mergeFilter(filters, { window_hours: option.id }))}
            />
          ))}
        </div>
        <div
          className="flex flex-wrap items-center gap-1 border-l border-border pl-3"
          role="group"
          aria-label="Minimum significance"
        >
          {SIGNIFICANCES.map((option) => (
            <FilterChip
              key={option.id}
              label={option.label}
              active={significance === option.id}
              onClick={() =>
                navigate(
                  mergeFilter(filters, {
                    min_significance: option.id === "medium" ? undefined : option.id,
                  }),
                )
              }
            />
          ))}
        </div>
        <Select value="" onValueChange={onAddFilter}>
          <SelectTrigger
            aria-label="Add filter"
            className="h-7 w-auto gap-1.5 border-none bg-transparent px-2 text-xs text-muted-foreground shadow-none hover:bg-accent hover:text-foreground"
          >
            <SelectValue placeholder="Add filter…" />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectLabel>Significance</SelectLabel>
              <SelectItem value="significance:high">High only</SelectItem>
              <SelectItem value="significance:low">All including low</SelectItem>
            </SelectGroup>
            {classes.length > 0 ? (
              <SelectGroup>
                <SelectLabel>Class</SelectLabel>
                {classes.map((id) => (
                  <SelectItem key={id} value={`class:${id}`}>
                    {id.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectGroup>
            ) : null}
            {connectors.length > 0 ? (
              <SelectGroup>
                <SelectLabel>Integration</SelectLabel>
                {connectors.map((instance) => {
                  const label =
                    instance.application_display_name ||
                    instance.connector_display_name ||
                    instance.connector_name ||
                    "Integration";
                  return (
                    <SelectItem key={instance.id} value={`connector:${instance.id}`}>
                      {label}
                    </SelectItem>
                  );
                })}
              </SelectGroup>
            ) : null}
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
