// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState, useTransition } from "react";

import { AppMarkStack } from "@/components/brand/app-mark";
import { Badge } from "@/components/ui/badge";
import { searchGraphNodes } from "@/lib/actions/explore";
import { defaultExploreDirection } from "@/lib/graph-layout";
import type { GraphSearchItem } from "@/lib/types";

const NODE_TYPE_TONES: Record<string, string> = {
  identity: "bg-sky-100 text-sky-900 dark:bg-sky-950 dark:text-sky-200",
  group: "bg-violet-100 text-violet-900 dark:bg-violet-950 dark:text-violet-200",
  role: "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200",
  resource: "bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200",
  oauth_application: "bg-fuchsia-100 text-fuchsia-900 dark:bg-fuchsia-950 dark:text-fuchsia-200",
  permission: "bg-slate-100 text-slate-800 dark:bg-slate-800 dark:text-slate-200",
  application: "bg-indigo-100 text-indigo-900 dark:bg-indigo-950 dark:text-indigo-200",
  setting: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300",
};

export function ExploreSearch({
  depth,
  nodeTypes,
}: {
  depth: number;
  nodeTypes?: string;
}) {
  const router = useRouter();
  const listId = useId();
  const inputId = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<GraphSearchItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    const trimmed = query.trim();
    if (trimmed.length < 1) {
      setItems([]);
      setError(null);
      setOpen(false);
      setActiveIndex(-1);
      return;
    }
    const handle = window.setTimeout(() => {
      startTransition(async () => {
        const result = await searchGraphNodes(trimmed, nodeTypes);
        if (!result.ok) {
          setError(result.error);
          setItems([]);
          setOpen(true);
          setActiveIndex(-1);
          return;
        }
        setError(null);
        setItems(result.items);
        setOpen(true);
        setActiveIndex(result.items.length > 0 ? 0 : -1);
      });
    }, 200);
    return () => window.clearTimeout(handle);
  }, [query, nodeTypes]);

  // Close on outside click — keyboard users still get Escape below.
  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: PointerEvent) {
      if (!containerRef.current?.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  function select(item: GraphSearchItem) {
    const params = new URLSearchParams();
    params.set("focus", item.object_id);
    params.set("focus_type", item.node_type);
    params.set("direction", defaultExploreDirection(item.node_type));
    params.set("depth", String(depth));
    params.set("layout", "hierarchical");
    router.push(`/explore?${params.toString()}`);
    setQuery("");
    setItems([]);
    setOpen(false);
    setActiveIndex(-1);
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (!open || items.length === 0) {
      if (event.key === "Escape") setQuery("");
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((i) => (i + 1) % items.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((i) => (i - 1 + items.length) % items.length);
    } else if (event.key === "Enter") {
      if (activeIndex >= 0 && activeIndex < items.length) {
        event.preventDefault();
        select(items[activeIndex]!);
      }
    } else if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      setActiveIndex(-1);
    }
  }

  const activeOptionId =
    activeIndex >= 0 && items[activeIndex] ? `${listId}-option-${items[activeIndex].id}` : undefined;

  return (
    <div className="relative" ref={containerRef}>
      <label htmlFor={inputId} className="sr-only">
        Search the identity graph
      </label>
      <input
        id={inputId}
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        onKeyDown={onKeyDown}
        onFocus={() => {
          if (items.length > 0) setOpen(true);
        }}
        placeholder="Search identities, groups, apps, roles…"
        className="w-full rounded-md border border-border bg-background px-3 py-2.5 text-sm outline-none ring-offset-background placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-foreground/20"
        autoComplete="off"
        role="combobox"
        aria-expanded={open && items.length > 0}
        aria-controls={listId}
        aria-activedescendant={activeOptionId}
        aria-autocomplete="list"
      />
      {pending && (
        <p className="mt-1.5 text-xs text-muted-foreground" role="status">
          Searching…
        </p>
      )}
      {error && (
        <p className="mt-1.5 text-xs text-red-700 dark:text-red-300" role="alert">
          {error}
        </p>
      )}
      {open && items.length > 0 && (
        <ul
          id={listId}
          role="listbox"
          aria-label="Search results"
          className="absolute z-20 mt-1 max-h-72 w-full overflow-auto rounded-md border border-border bg-elevated text-elevated-foreground shadow-lg"
        >
          {items.map((item, index) => {
            const apps = item.application_types ?? [];
            const active = index === activeIndex;
            return (
              <li key={item.id} id={`${listId}-option-${item.id}`} role="option" aria-selected={active}>
                <button
                  type="button"
                  onClick={() => select(item)}
                  onMouseEnter={() => setActiveIndex(index)}
                  className={`flex w-full flex-col gap-1 px-3 py-2.5 text-left text-sm ${
                    active ? "bg-muted" : "hover:bg-muted"
                  }`}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <Badge className={NODE_TYPE_TONES[item.node_type] ?? NODE_TYPE_TONES.setting}>
                      {item.node_type.replace(/_/g, " ")}
                    </Badge>
                    <span className="truncate font-medium">{item.label}</span>
                    {item.account_count != null && item.account_count > 1 && (
                      <span className="shrink-0 text-[10px] text-muted-foreground">
                        {item.account_count} apps
                      </span>
                    )}
                  </span>
                  {apps.length > 0 && (
                    <span className="flex items-center gap-1.5 pl-0.5">
                      <AppMarkStack applicationTypes={apps} size={14} limit={5} />
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
