// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { notFound } from "next/navigation";

import { SeverityBadge, StatusBadge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty-state";
import { LocalTime } from "@/components/ui/local-time";
import { PageHeader } from "@/components/ui/page-header";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { apiStatePage } from "@/components/api-state";
import { ApiError, api, segment } from "@/lib/api";
import type { ConnectorRunChanges, ConnectorRunDetail } from "@/lib/types";
import { countOf } from "@/lib/plural";

export default async function ConnectorRunDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ change_type?: string; entity_type?: string }>;
}) {
  const { id } = await params;
  const filters = await searchParams;
  let run: ConnectorRunDetail;
  let drift: ConnectorRunChanges | null = null;
  try {
    run = await api.get<ConnectorRunDetail>(`/connector-runs/${segment(id)}`);
    const qs = new URLSearchParams();
    if (filters.change_type) qs.set("change_type", filters.change_type);
    if (filters.entity_type) qs.set("entity_type", filters.entity_type);
    qs.set("limit", "50");
    drift = await api.get<ConnectorRunChanges>(
      `/connector-runs/${segment(id)}/changes${qs.toString() ? `?${qs}` : ""}`,
    );
  } catch (error) {
    const statePage = apiStatePage(error);
    if (statePage) return statePage;
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }

  const title =
    run.application.display_name ||
    run.connector_instance.connector_display_name ||
    run.connector_instance.connector_name ||
    "Sync run";

  const summary = run.change_summary ?? drift?.change_summary;
  const prev = run.previous_successful_run ?? drift?.previous_successful_run;

  const skipped = run.coverage?.skipped ?? [];
  const collected =
    run.coverage?.collected ??
    Object.entries(run.object_counts).map(([object_type, count]) => ({ object_type, count }));

  return (
    <div className="space-y-6">
      <p className="text-sm text-muted-foreground">
        <Link href="/connectors" className="hover:underline">
          Integrations
        </Link>
        {" / "}
        <span>Run</span>
      </p>
      <PageHeader
        eyebrow="Integrations"
        title={title}
        status={<StatusBadge status={run.status} />}
        description={
          <>
            Triggered by {run.triggered_by}
            {run.started_at ? (
              <>
                {" · started "}
                <LocalTime value={run.started_at} />
              </>
            ) : null}
            {run.duration_seconds != null ? (
              ` · ${Math.round(run.duration_seconds)}s`
            ) : run.finished_at ? (
              <>
                {" · finished "}
                <LocalTime value={run.finished_at} />
              </>
            ) : null}
          </>
        }
        className="mb-0"
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-wrap items-baseline justify-between gap-2">
            <CardTitle>Coverage</CardTitle>
            <span className="text-xs text-muted-foreground">
              {run.coverage?.is_complete
                ? "Complete inventory"
                : skipped.length > 0
                  ? `${countOf(skipped.length, "family", "families")} not read`
                  : ""}
            </span>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Objects collected</span>
              <span className="tabular-nums font-medium">{run.objects_total.toLocaleString()}</span>
            </div>

            {skipped.length > 0 && (
              <div className="space-y-2 rounded-md border border-tone-warning/40 bg-tone-warning/5 p-3">
                <p className="font-medium">Reduced coverage</p>
                <p className="text-xs text-muted-foreground">
                  These families were not read on this run. Deletion detection and the change snapshot were skipped,
                  so nothing here is reported as removed.
                </p>
                <ul className="space-y-1.5">
                  {skipped.map((item) => (
                    <li key={item.object_type}>
                      <span className="font-mono text-xs">{item.object_type}</span>
                      <span className="ml-2 text-xs text-muted-foreground">{item.detail}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {collected.length === 0 ? (
              <p className="text-muted-foreground">No object counts recorded.</p>
            ) : (
              <ul className="divide-y divide-border">
                {collected.map((item) => (
                  <li key={item.object_type} className="flex justify-between gap-3 py-1.5">
                    <span className="text-muted-foreground">{item.object_type}</span>
                    <span className="tabular-nums">{item.count.toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}

            {run.error_summary && run.status === "failed" ? (
              <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {run.error_summary}
              </p>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Context</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Connector</span>
              <span>
                {run.connector_instance.connector_name ?? "—"}
                {" · "}
                {run.connector_instance.sync_mode} / {run.connector_instance.auth_method}
              </span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Application</span>
              {run.application.detail_path ? (
                <Link href={run.application.detail_path} className="text-primary underline">
                  {run.application.display_name ?? "Inventory →"}
                </Link>
              ) : (
                <span>—</span>
              )}
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Schedule</span>
              <span>
                {run.connector_instance.schedule_cron ? (
                  <code className="rounded bg-muted px-1 font-mono">
                    {run.connector_instance.schedule_cron}
                  </code>
                ) : (
                  "none"
                )}
              </span>
            </div>
            {prev ? (
              <div className="flex justify-between gap-3 border-t border-border pt-3">
                <span className="text-muted-foreground">Previous success</span>
                <Link href={prev.detail_path} className="text-primary underline">
                  {countOf(prev.change_summary.total, "change")} →
                </Link>
              </div>
            ) : null}
            <p className="border-t border-border pt-3">
              <Link href="/connectors" className="text-primary underline">
                Back to integrations →
              </Link>
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <div id="drift">
          <CardHeader>
            <CardTitle>Drift / changes ({summary?.total ?? 0})</CardTitle>
          </CardHeader>
        </div>
        <CardContent className="space-y-4">
          {summary ? (
            <div className="flex flex-wrap gap-4 text-sm">
              <span>
                Created: <strong className="tabular-nums">{summary.by_change_type.created}</strong>
              </span>
              <span>
                Updated: <strong className="tabular-nums">{summary.by_change_type.updated}</strong>
              </span>
              <span>
                Deleted: <strong className="tabular-nums">{summary.by_change_type.deleted}</strong>
              </span>
            </div>
          ) : null}
          {summary?.note ? <p className="text-xs text-muted-foreground">{summary.note}</p> : null}
          <div className="flex flex-wrap gap-2 text-xs">
            <Link
              href={`/connectors/runs/${id}`}
              className={`rounded border px-2 py-1 ${!filters.change_type ? "bg-muted" : "hover:bg-muted"}`}
            >
              All
            </Link>
            {(["created", "updated", "deleted"] as const).map((ct) => (
              <Link
                key={ct}
                href={`/connectors/runs/${id}?change_type=${ct}`}
                className={`rounded border px-2 py-1 ${
                  filters.change_type === ct ? "bg-muted" : "hover:bg-muted"
                }`}
              >
                {ct}
              </Link>
            ))}
          </div>
          {!drift || drift.changes.length === 0 ? (
            <EmptyState
              title="No entity drift for this run"
              hint="Create/update/delete events appear when sync detects inventory attribute changes."
            />
          ) : (
            <div className="max-h-[28rem] overflow-auto rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow className="sticky top-0 z-10 bg-card hover:bg-card">
                    <TableHead>Entity</TableHead>
                    <TableHead>Change</TableHead>
                    <TableHead>Fields</TableHead>
                    <TableHead>Detected</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {drift.changes.map((row) => (
                    <TableRow key={row.id}>
                      <TableCell className="align-top">
                        {row.detail_path ? (
                          <Link href={row.detail_path} className="font-medium hover:underline">
                            {row.label ?? row.entity_type}
                          </Link>
                        ) : (
                          <span className="font-medium">{row.label ?? row.entity_type}</span>
                        )}
                        <p className="text-xs text-muted-foreground">
                          <code className="font-mono">{row.entity_type}</code>
                        </p>
                      </TableCell>
                      <TableCell className="align-top">
                        <StatusBadge status={row.change_type} />
                      </TableCell>
                      <TableCell className="align-top font-mono text-xs text-muted-foreground">
                        {row.field_changes.length === 0
                          ? "—"
                          : row.field_changes
                              .slice(0, 4)
                              .map((fc) => {
                                const field = fc.field ?? "?";
                                return `${field}: ${JSON.stringify(fc.old)} → ${JSON.stringify(fc.new)}`;
                              })
                              .join("; ")}
                        {row.field_changes.length > 4 ? "…" : ""}
                      </TableCell>
                      <TableCell className="align-top text-xs text-muted-foreground">
                        <LocalTime value={row.detected_at} fallback="—" />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {drift?.truncated ? (
            <p className="text-xs text-muted-foreground">
              Showing {drift.changes.length} of {drift.total} changes.
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Policy evaluations ({run.policy_evaluation_count})</CardTitle>
          <CardDescription>Policy runs triggered by this sync.</CardDescription>
        </CardHeader>
        <CardContent>
          {run.policy_evaluations.length === 0 ? (
            <EmptyState
              title="No policy evaluations for this run"
              hint="Evaluations appear when a sync finishes and policies are enabled."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Policy</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Matched</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Links</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {run.policy_evaluations.map((ev) => (
                    <TableRow key={ev.id}>
                      <TableCell className="align-top">
                        <Link href={ev.policy_detail_path} className="font-medium hover:underline">
                          {ev.policy_title}
                        </Link>
                        <p className="text-xs text-muted-foreground">
                          <code className="font-mono">{ev.policy_slug}</code> · v{ev.policy_version}
                        </p>
                        {ev.error_message ? (
                          <p className="mt-1 text-xs text-destructive">{ev.error_message}</p>
                        ) : null}
                      </TableCell>
                      <TableCell className="align-top">
                        <StatusBadge status={ev.status} />
                      </TableCell>
                      <TableCell className="align-top tabular-nums">{ev.matched_object_count}</TableCell>
                      <TableCell className="align-top">
                        <SeverityBadge severity={ev.severity} />
                      </TableCell>
                      <TableCell className="align-top">
                        <div className="flex flex-col gap-1 text-xs">
                          <Link href={ev.findings_list_path} className="text-primary underline">
                            Findings →
                          </Link>
                          <Link href={ev.policy_detail_path} className="text-primary underline">
                            Policy →
                          </Link>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
