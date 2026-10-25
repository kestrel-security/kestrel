// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition } from "react";

import { LoadMoreButton } from "@/components/load-more";
import { LocalTime } from "@/components/ui/local-time";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchAuditLogPage } from "@/lib/actions/settings";
import type { AuditLogEntry } from "@/lib/types";

export function AuditLogTable({
  initialItems,
  initialCursor,
  actionFilter,
  pageSize,
}: {
  initialItems: AuditLogEntry[];
  initialCursor: string | null;
  actionFilter?: string;
  pageSize: number;
}) {
  const [items, setItems] = useState(initialItems);
  const [cursor, setCursor] = useState(initialCursor);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function loadMore() {
    if (!cursor) return;
    startTransition(async () => {
      const result = await fetchAuditLogPage({ action: actionFilter }, cursor, pageSize);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setError(null);
      setItems((prev) => [...prev, ...result.items]);
      setCursor(result.next_cursor);
    });
  }

  return (
    <div className="space-y-3">
      <div className="max-h-[32rem] overflow-auto rounded-md border border-border">
        <Table>
          <TableHeader>
            <TableRow className="sticky top-0 z-10 bg-card hover:bg-card">
              <TableHead>When</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Target</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((row) => (
              <TableRow key={row.id}>
                <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                  <LocalTime value={row.created_at} />
                </TableCell>
                <TableCell>
                  {row.actor ? (
                    <>
                      <span>{row.actor.display_name ?? row.actor.email}</span>
                      {row.actor.display_name ? (
                        <span className="ml-1.5 font-mono text-xs text-muted-foreground">
                          {row.actor.email}
                        </span>
                      ) : null}
                    </>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs">{row.action}</TableCell>
                <TableCell className="text-muted-foreground">
                  {row.target_type}
                  {row.target_id ? (
                    <span className="ml-1 font-mono text-xs">
                      {String(row.target_id).slice(0, 8)}…
                    </span>
                  ) : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <p className="text-xs text-muted-foreground">
        Showing {items.length}
        {cursor ? "+" : ""} events
      </p>
      {cursor ? <LoadMoreButton pending={pending} error={error} onClick={loadMore} /> : null}
    </div>
  );
}
