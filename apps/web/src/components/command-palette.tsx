// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  useTransition,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { orgSearch } from "@/lib/actions/search";
import type { OrgSearchGroup, OrgSearchResponse } from "@/lib/types";

const GROUP_LABELS: Record<string, string> = {
  finding: "Findings",
  policy: "Policies",
};

const STATIC_NAV: { label: string; href: string; subtitle: string }[] = [
  { label: "Dashboard", href: "/dashboard", subtitle: "Findings & posture overview" },
  { label: "Integrations", href: "/connectors", subtitle: "Connected SaaS apps" },
  { label: "Identities", href: "/identities", subtitle: "People and accounts across applications" },
  { label: "Explore", href: "/explore", subtitle: "Identity and access graph" },
  { label: "Changes", href: "/changes", subtitle: "Classified sync diffs" },
  { label: "Policies", href: "/policies", subtitle: "Built-in and custom policies" },
  { label: "Findings", href: "/findings", subtitle: "Failed policy checks" },
  { label: "Settings", href: "/settings", subtitle: "Operators, webhooks, ticketing" },
];

function flattenHits(groups: OrgSearchGroup[]): { groupType: string; index: number }[] {
  const out: { groupType: string; index: number }[] = [];
  for (const group of groups) {
    group.items.forEach((_, index) => {
      out.push({ groupType: group.type, index });
    });
  }
  return out;
}

export function CommandPalette() {
  const router = useRouter();
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<OrgSearchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState(0);
  const [pending, startTransition] = useTransition();
  // Bumped by every search and by closing: a response that is not the latest
  // search of the current opening is dropped, so a slow "ad" cannot replace
  // the results for "admin", and nothing lands after the palette closed.
  const requestSeqRef = useRef(0);

  // Escape, outside clicks, the focus trap and returning focus to whatever
  // opened the palette are the Radix Dialog's; only the ⌘K chord is ours.
  const setPaletteOpen = useCallback((next: boolean) => {
    if (!next) {
      requestSeqRef.current += 1;
      setQuery("");
      setResult(null);
      setError(null);
      setActive(0);
    }
    setOpen(next);
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const isPaletteChord =
        (event.key === "k" || event.key === "K") && (event.metaKey || event.ctrlKey);
      if (isPaletteChord) {
        event.preventDefault();
        setPaletteOpen(!open);
      }
    }
    function onOpenRequest() {
      setOpen(true);
    }
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("kestrel:open-command-palette", onOpenRequest);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("kestrel:open-command-palette", onOpenRequest);
    };
  }, [open, setPaletteOpen]);

  useEffect(() => {
    if (!open) return;
    const q = query.trim();
    if (!q) {
      requestSeqRef.current += 1;
      setResult(null);
      setError(null);
      setActive(0);
      return;
    }
    const handle = window.setTimeout(() => {
      const seq = ++requestSeqRef.current;
      startTransition(async () => {
        const res = await orgSearch(q);
        if (seq !== requestSeqRef.current) return;
        if (!res.ok) {
          setError(res.error);
          setResult(null);
          return;
        }
        setError(null);
        setResult(res.data);
        setActive(0);
      });
    }, 150);
    return () => window.clearTimeout(handle);
  }, [open, query]);

  const hitRefs = result ? flattenHits(result.groups) : [];
  const staticMode = !query.trim();
  const total = staticMode ? STATIC_NAV.length : hitRefs.length;

  function navigateTo(href: string) {
    setPaletteOpen(false);
    router.push(href);
  }

  function onInputKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (total === 0) return;
      setActive((i) => (i + 1) % total);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      if (total === 0) return;
      setActive((i) => (i - 1 + total) % total);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      if (staticMode) {
        const item = STATIC_NAV[active];
        if (item) navigateTo(item.href);
        return;
      }
      const ref = hitRefs[active];
      if (!ref || !result) return;
      const group = result.groups.find((g) => g.type === ref.groupType);
      const item = group?.items[ref.index];
      if (item) navigateTo(item.href);
    }
  }

  let flatIndex = 0;

  return (
    <Dialog open={open} onOpenChange={setPaletteOpen}>
      <DialogContent
        aria-describedby={undefined}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          inputRef.current?.focus();
        }}
        className="top-[12vh] w-[calc(100%-2rem)] max-w-xl translate-y-0 gap-0 overflow-hidden rounded-lg bg-popover p-0 text-popover-foreground shadow-lg"
      >
        <DialogTitle className="sr-only">Search Kestrel</DialogTitle>
        <div className="border-b border-border py-2 pl-3 pr-10">
          <label htmlFor={inputId} className="sr-only">
            Search
          </label>
          <input
            ref={inputRef}
            id={inputId}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKeyDown}
            placeholder="Search findings, policies, and destinations…"
            className="w-full bg-transparent px-1 py-2 text-sm outline-none placeholder:text-muted-foreground"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="max-h-[min(24rem,50vh)] overflow-auto p-2">
          {error ? <p className="px-2 py-2 text-sm text-destructive">{error}</p> : null}
          {staticMode ? (
            <ul className="space-y-0.5">
              <li className="text-eyebrow px-2 py-1">Go to</li>
              {STATIC_NAV.map((item, index) => (
                <li key={item.href}>
                  <button
                    type="button"
                    className={`flex w-full flex-col rounded-md px-2 py-1.5 text-left text-sm transition-colors ${
                      index === active ? "bg-accent text-accent-foreground" : "hover:bg-muted/70"
                    }`}
                    onMouseEnter={() => setActive(index)}
                    onClick={() => navigateTo(item.href)}
                  >
                    <span className="font-medium">{item.label}</span>
                    <span className="text-xs text-muted-foreground">{item.subtitle}</span>
                  </button>
                </li>
              ))}
            </ul>
          ) : null}
          {!staticMode && pending && !result ? (
            <p className="px-2 py-2 text-sm text-muted-foreground">Searching…</p>
          ) : null}
          {!staticMode && result
            ? result.groups.map((group) => {
                if (group.items.length === 0) return null;
                return (
                  <div key={group.type} className="mb-2 last:mb-0">
                    <p className="text-eyebrow px-2 py-1">{GROUP_LABELS[group.type] ?? group.type}</p>
                    <ul className="space-y-0.5">
                      {group.items.map((item) => {
                        const thisIndex = flatIndex;
                        flatIndex += 1;
                        return (
                          <li key={`${group.type}-${item.id}`}>
                            <button
                              type="button"
                              className={`flex w-full flex-col rounded-md px-2 py-1.5 text-left text-sm ${
                                thisIndex === active ? "bg-muted" : "hover:bg-muted/70"
                              }`}
                              onMouseEnter={() => setActive(thisIndex)}
                              onClick={() => navigateTo(item.href)}
                            >
                              <span className="font-medium">{item.label}</span>
                              {item.subtitle ? (
                                <span className="text-xs text-muted-foreground">{item.subtitle}</span>
                              ) : null}
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                );
              })
            : null}
          {!staticMode && result && hitRefs.length === 0 && !pending ? (
            <p className="px-2 py-2 text-sm text-muted-foreground">No matches for “{result.query}”.</p>
          ) : null}
        </div>
        <div className="border-t border-border px-3 py-1.5 text-xs text-muted-foreground">
          ↑↓ navigate · Enter open · Esc close · ⌘K / Ctrl+K
        </div>
      </DialogContent>
    </Dialog>
  );
}
