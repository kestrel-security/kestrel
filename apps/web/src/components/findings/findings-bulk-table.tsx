// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState, useTransition } from "react";
import { ArrowDown } from "lucide-react";

import { LoadMoreButton } from "@/components/load-more";
import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { LocalTime } from "@/components/ui/local-time";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { bulkUpdateFindings, fetchFindingsPage } from "@/lib/actions/findings";
import { blocksActionShortcut, blocksNavigationShortcut } from "@/lib/keyboard-targets";
import { cn } from "@/lib/utils";
import type { FindingSummary, Operator } from "@/lib/types";
import { plural } from "@/lib/plural";

export function FindingsBulkTable({
  initialFindings,
  initialCursor,
  filters,
  pageSize,
  operators,
}: {
  initialFindings: FindingSummary[];
  initialCursor: string | null;
  filters: {
    severity?: string;
    status?: string;
    search?: string;
    policy_slug?: string;
    assigned_to_operator_id?: string;
    unassigned?: string;
    open_older_than_days?: string;
    subject_id?: string;
    subject_type?: string;
    application_instance_id?: string;
  };
  pageSize: number;
  operators: Operator[];
}) {
  const router = useRouter();
  const [findings, setFindings] = useState(initialFindings);
  const [cursor, setCursor] = useState(initialCursor);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const [assigneeId, setAssigneeId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [loadingMore, startLoadMore] = useTransition();

  const allIds = useMemo(() => findings.map((f) => f.id), [findings]);
  const allSelected = allIds.length > 0 && allIds.every((id) => selected.has(id));
  const someSelected = selected.size > 0 && !allSelected;

  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(allIds));
  }

  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function runBulk(patch: { status?: string; assigned_to_operator_id?: string | null }) {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    setError(null);
    startTransition(async () => {
      const result = await bulkUpdateFindings(ids, patch);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      const idSet = new Set(ids);
      const assignee =
        patch.assigned_to_operator_id === undefined
          ? undefined
          : patch.assigned_to_operator_id === null
            ? null
            : (operators.find((o) => o.id === patch.assigned_to_operator_id) ?? null);
      setFindings((prev) =>
        prev.map((f) => {
          if (!idSet.has(f.id)) return f;
          return {
            ...f,
            ...(patch.status !== undefined ? { status: patch.status } : {}),
            ...(assignee !== undefined
              ? {
                  assigned_to: assignee
                    ? { id: assignee.id, email: assignee.email, display_name: assignee.display_name }
                    : null,
                }
              : {}),
          };
        }),
      );
      setSelected(new Set());
      router.refresh();
    });
  }

  function loadMore() {
    if (!cursor || loadingMore) return;
    setLoadError(null);
    startLoadMore(async () => {
      const result = await fetchFindingsPage(filters, cursor, pageSize);
      if (!result.ok) {
        setLoadError(result.error);
        return;
      }
      setFindings((prev) => {
        const seen = new Set(prev.map((f) => f.id));
        return [...prev, ...result.items.filter((f) => !seen.has(f.id))];
      });
      setCursor(result.next_cursor);
    });
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }
      if (findings.length === 0) return;
      // Arrow keys and j/k belong to menus, listboxes and text fields when
      // focus is in one; everything else belongs to any focused control.
      if (blocksNavigationShortcut(event.target)) return;

      if (event.key === "j" || event.key === "ArrowDown") {
        event.preventDefault();
        setFocusedIndex((i) => {
          if (i < 0) return 0;
          return Math.min(findings.length - 1, i + 1);
        });
        return;
      }
      if (event.key === "k" || event.key === "ArrowUp") {
        event.preventDefault();
        setFocusedIndex((i) => {
          if (i < 0) return findings.length - 1;
          return Math.max(0, i - 1);
        });
        return;
      }
      if (blocksActionShortcut(event.target)) return;

      if (event.key === "Escape") {
        setSelected(new Set());
        setFocusedIndex(-1);
        return;
      }

      // Row actions need a row the operator moved to with j/k; nothing is
      // implied when no row is focused.
      const focused = focusedIndex >= 0 ? findings[focusedIndex] : undefined;

      if (event.key === "Enter" && focused) {
        event.preventDefault();
        router.push(`/findings/${focused.id}`);
        return;
      }
      if (event.key === "x" && focused) {
        event.preventDefault();
        toggleOne(focused.id);
        return;
      }
      if (event.key === "o" && !pending) {
        const ids = selected.size > 0 ? Array.from(selected) : focused ? [focused.id] : [];
        if (ids.length === 0) return;
        event.preventDefault();
        setError(null);
        startTransition(async () => {
          const result = await bulkUpdateFindings(ids, { status: "resolved" });
          if (!result.ok) {
            setError(result.error);
            return;
          }
          const idSet = new Set(ids);
          setFindings((prev) =>
            prev.map((f) => (idSet.has(f.id) ? { ...f, status: "resolved" } : f)),
          );
          setSelected(new Set());
          router.refresh();
        });
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  });

  return (
    <TooltipProvider delayDuration={150}>
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Showing {findings.length}
          {cursor ? "+" : ""} {plural(cursor ? 2 : findings.length, "result")}
        </p>
        <p className="hidden text-xs text-muted-foreground md:block">
          Keys: <kbd className="rounded border border-border px-1">j</kbd>/
          <kbd className="rounded border border-border px-1">k</kbd> move ·{" "}
          <kbd className="rounded border border-border px-1">Enter</kbd> open ·{" "}
          <kbd className="rounded border border-border px-1">x</kbd> select ·{" "}
          <kbd className="rounded border border-border px-1">o</kbd> resolve ·{" "}
          <kbd className="rounded border border-border px-1">Esc</kbd> clear
        </p>
      </div>

      {selected.size > 0 ? (
        <div
          role="toolbar"
          aria-label="Bulk actions"
          className="flex flex-wrap items-center gap-2 rounded-lg border border-primary/30 bg-elevated px-3 py-2 text-sm text-elevated-foreground shadow-sm"
        >
          <span className="font-medium tabular-nums">
            {selected.size} of {findings.length} selected
          </span>
          <Button type="button" size="sm" variant="secondary" disabled={pending} onClick={() => runBulk({ status: "resolved" })}>
            Resolve
          </Button>
          <Button type="button" size="sm" variant="secondary" disabled={pending} onClick={() => runBulk({ status: "suppressed" })}>
            Suppress
          </Button>
          <Button type="button" size="sm" variant="secondary" disabled={pending} onClick={() => runBulk({ status: "open" })}>
            Reopen
          </Button>
          <span className="mx-1 text-muted-foreground" aria-hidden>
            |
          </span>
          <label className="flex items-center gap-2">
            <span className="text-muted-foreground">Assign</span>
            <select
              value={assigneeId}
              onChange={(e) => setAssigneeId(e.target.value)}
              aria-label="Assign selected findings to"
              className="h-8 rounded-md border border-input bg-background px-2 text-sm text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
              disabled={pending}
            >
              <option value="">Select operator…</option>
              {operators.map((op) => (
                <option key={op.id} value={op.id}>
                  {op.display_name ?? op.email}
                </option>
              ))}
            </select>
          </label>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            disabled={pending || !assigneeId}
            onClick={() => runBulk({ assigned_to_operator_id: assigneeId })}
          >
            Assign
          </Button>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            disabled={pending}
            onClick={() => runBulk({ assigned_to_operator_id: null })}
          >
            Unassign
          </Button>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={pending}
            className="ml-auto"
            onClick={() => setSelected(new Set())}
          >
            Clear
          </Button>
        </div>
      ) : null}

      {error ? <p className="text-sm text-destructive">{error}</p> : null}

      <div className="overflow-hidden rounded-lg border border-border bg-card">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-card">
            <TableRow>
              <TableHead scope="col" className="w-10">
                <Checkbox
                  checked={allSelected ? true : someSelected ? "indeterminate" : false}
                  onCheckedChange={() => toggleAll()}
                  aria-label="Select all findings"
                  disabled={findings.length === 0}
                />
              </TableHead>
              <TableHead scope="col">Title</TableHead>
              <TableHead scope="col" className="hidden sm:table-cell">
                Subject
              </TableHead>
              <TableHead scope="col" className="hidden lg:table-cell">
                Policy
              </TableHead>
              <TableHead scope="col">
                <span
                  className="inline-flex items-center gap-1"
                  title="Sorted worst first, most recently detected within a severity"
                >
                  Severity
                  <ArrowDown className="size-3 text-muted-foreground/70" aria-hidden />
                </span>
              </TableHead>
              <TableHead scope="col">Status</TableHead>
              <TableHead scope="col" className="hidden md:table-cell">
                Age
              </TableHead>
              <TableHead scope="col" className="hidden lg:table-cell">
                Assigned To
              </TableHead>
              <TableHead scope="col" className="hidden xl:table-cell">
                Last Seen
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {findings.map((f, index) => (
              <TableRow
                key={f.id}
                onClick={() => setFocusedIndex(index)}
                aria-selected={selected.has(f.id)}
                data-state={focusedIndex === index ? "selected" : undefined}
                className={cn(focusedIndex === index && "bg-primary/5 ring-1 ring-inset ring-primary/30")}
              >
                <TableCell>
                  <Checkbox
                    checked={selected.has(f.id)}
                    onCheckedChange={() => toggleOne(f.id)}
                    aria-label={`Select ${f.title}`}
                    onClick={(e) => e.stopPropagation()}
                  />
                </TableCell>
                <TableCell className="max-w-[24rem]">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Link
                        href={`/findings/${f.id}`}
                        className="block truncate font-medium hover:underline"
                      >
                        {f.title}
                      </Link>
                    </TooltipTrigger>
                    <TooltipContent side="top" className="max-w-sm break-words">
                      {f.title}
                    </TooltipContent>
                  </Tooltip>
                  {/* Subject shown inline once the dedicated column hides on narrow screens. */}
                  <p className="mt-0.5 truncate text-xs text-muted-foreground sm:hidden">
                    {f.subject_label ?? f.subject_type}
                  </p>
                </TableCell>
                <TableCell className="hidden max-w-[16rem] sm:table-cell">
                  <p className="truncate font-medium" title={f.subject_label ?? undefined}>
                    {f.subject_label ?? (
                      <span className="text-muted-foreground">{f.subject_type}</span>
                    )}
                  </p>
                  {f.subject_secondary ? (
                    <p className="truncate text-xs text-muted-foreground" title={f.subject_secondary}>
                      {f.subject_secondary}
                    </p>
                  ) : f.subject_label ? (
                    <p className="truncate text-xs text-muted-foreground">{f.subject_type}</p>
                  ) : null}
                </TableCell>
                <TableCell
                  className="hidden max-w-[12rem] truncate font-mono text-xs text-muted-foreground lg:table-cell"
                  title={f.policy_slug ?? undefined}
                >
                  {f.policy_slug ?? "—"}
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={f.severity} />
                </TableCell>
                <TableCell>
                  <StatusBadge status={f.status} />
                  {f.status === "muted" && f.muted_until ? (
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      until <LocalTime value={f.muted_until} />
                      {new Date(f.muted_until).getTime() <= Date.now() ? " · expired" : ""}
                    </p>
                  ) : null}
                </TableCell>
                <TableCell className="hidden tabular-nums text-muted-foreground md:table-cell">
                  {f.age_days}d
                </TableCell>
                <TableCell className="hidden truncate lg:table-cell">
                  {f.assigned_to?.display_name ?? f.assigned_to?.email ?? "—"}
                </TableCell>
                <TableCell className="hidden text-muted-foreground xl:table-cell">
                  <LocalTime value={f.last_seen_at} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {cursor ? <LoadMoreButton pending={loadingMore} error={loadError} onClick={loadMore} /> : null}
    </div>
    </TooltipProvider>
  );
}
