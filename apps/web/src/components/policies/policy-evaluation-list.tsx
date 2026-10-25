// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import Link from "next/link";
import { CheckCircle2, XCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { policyTabHref } from "@/lib/policy-tabs";
import type { PolicyEvaluationSummary } from "@/lib/types";
import { countOf } from "@/lib/plural";

const LIST_PREVIEW = 5;

export function PolicyEvaluationList({
  items,
  policyId,
  preview = false,
  emptyHint = "No evaluations yet. Use Evaluate now, or run an integration sync.",
}: {
  items: PolicyEvaluationSummary[];
  policyId: string;
  preview?: boolean;
  emptyHint?: ReactNode;
}) {
  if (items.length === 0) {
    return <p className="text-sm text-muted-foreground">{emptyHint}</p>;
  }

  const visible = preview ? items.slice(0, LIST_PREVIEW) : items;
  const showViewAll = preview && items.length >= LIST_PREVIEW;

  return (
    <div>
      <div
        className={
          preview ? undefined : "max-h-[28rem] overflow-auto rounded-md border border-border"
        }
      >
        <Table>
          <TableHeader>
            <TableRow
              className={
                preview ? "hover:bg-transparent" : "sticky top-0 z-10 bg-card hover:bg-card"
              }
            >
              <TableHead>Status</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Started</TableHead>
              <TableHead>Matches</TableHead>
              <TableHead>Integration</TableHead>
              <TableHead>Findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.map((ev) => (
              <TableRow key={ev.id}>
                <TableCell className="align-top">
                  <div className="space-y-1">
                    {ev.status === "success" ? (
                      <Badge className="border-green-500/30 bg-green-500/10 text-green-800 dark:text-green-300">
                        <CheckCircle2 className="size-3" aria-hidden />
                        success
                      </Badge>
                    ) : (
                      <Badge className="border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300">
                        <XCircle className="size-3" aria-hidden />
                        error
                      </Badge>
                    )}
                    {ev.error_message ? (
                      <p className="max-w-xs whitespace-pre-wrap font-mono text-xs text-red-700 dark:text-red-300">
                        {ev.error_message}
                      </p>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell className="align-top tabular-nums text-muted-foreground">
                  v{ev.policy_version}
                </TableCell>
                <TableCell className="whitespace-nowrap align-top tabular-nums text-muted-foreground">
                  <LocalTime value={ev.started_at} fallback="—" />
                </TableCell>
                <TableCell className="align-top tabular-nums text-muted-foreground">
                  {ev.status === "success"
                    ? countOf(ev.matched_object_count, "match", "matches")
                    : "—"}
                </TableCell>
                <TableCell className="align-top text-xs">
                  {ev.connector_run_path ? (
                    <Link href={ev.connector_run_path} className="text-primary underline">
                      Sync run →
                    </Link>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell className="align-top text-xs">
                  {ev.findings_list_path && ev.matched_object_count > 0 ? (
                    <Link href={ev.findings_list_path} className="text-primary underline">
                      Findings →
                    </Link>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {showViewAll ? (
        <p className="mt-2 text-xs text-muted-foreground">
          Showing the latest {LIST_PREVIEW} evaluations.{" "}
          <Link
            href={policyTabHref(policyId, "evaluations")}
            className="underline hover:text-foreground"
          >
            View all evaluations →
          </Link>
        </p>
      ) : null}
    </div>
  );
}
