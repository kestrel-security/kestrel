// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { StatusBadge } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { ConnectorRun } from "@/lib/types";

const LIST_PREVIEW = 5;

function objectsLabel(run: ConnectorRun): string {
  const counts = Object.entries(run.object_counts ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join(", ");
  if (counts) {
    return counts;
  }
  if (run.error_summary) {
    const text = run.error_summary.replace(/\s+/g, " ").trim();
    return text.length > 140 ? `${text.slice(0, 137)}…` : text;
  }
  return "—";
}

export function ConnectorRunHistory({
  runs,
  instanceId,
  preview = false,
}: {
  runs: ConnectorRun[];
  instanceId: string;
  preview?: boolean;
}) {
  if (runs.length === 0) {
    return <p className="mt-3 text-sm text-muted-foreground">No runs yet.</p>;
  }

  const visible = preview ? runs.slice(0, LIST_PREVIEW) : runs;
  const hidden = preview && runs.length > LIST_PREVIEW;

  return (
    <div className="mt-3">
      <div className={preview ? undefined : "max-h-[28rem] overflow-auto rounded-md border border-border"}>
        <Table>
          <TableHeader>
            <TableRow
              className={preview ? "hover:bg-transparent" : "sticky top-0 z-10 bg-card hover:bg-card"}
            >
              <TableHead>Status</TableHead>
              <TableHead>Started</TableHead>
              <TableHead>Objects</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.map((r) => (
              <TableRow key={r.id}>
                <TableCell className="align-top">
                  <Link href={`/connectors/runs/${r.id}`} className="hover:underline">
                    <StatusBadge status={r.status} />
                  </Link>
                </TableCell>
                <TableCell className="whitespace-nowrap align-top tabular-nums">
                  <Link href={`/connectors/runs/${r.id}`} className="hover:underline">
                    <LocalTime value={r.started_at} fallback="—" />
                  </Link>
                </TableCell>
                <TableCell className="align-top text-muted-foreground">{objectsLabel(r)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {hidden && (
        <p className="mt-2 text-xs text-muted-foreground">
          Showing the latest {LIST_PREVIEW} runs.{" "}
          <Link href={`/connectors/${instanceId}#runs`} className="underline hover:text-foreground">
            View all
          </Link>
        </p>
      )}
    </div>
  );
}
