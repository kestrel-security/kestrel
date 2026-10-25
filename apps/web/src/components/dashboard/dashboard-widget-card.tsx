// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { ExternalLink, GripVertical, MoreVertical, Trash2, X } from "lucide-react";

import { PresetWidgetBody } from "@/components/dashboard/widget-bodies";
import { KpiTile } from "@/components/dashboard/kpi-tile";
import {
  DashboardAreaChart,
  DashboardBarChart,
  DashboardLineChart,
  DashboardPieChart,
} from "@/components/dashboard/widget-charts-lazy";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import type {
  DashboardOverview,
  DashboardQueryResult,
  DashboardWidget,
} from "@/lib/types";
import { cn } from "@/lib/utils";
import { widgetWindowLabel } from "@/lib/widget-query";

type Props = {
  widget: DashboardWidget;
  overview: DashboardOverview;
  query?: DashboardQueryResult;
  /** Header range, which posture-trend widgets follow. */
  timeRange: string;
  loading?: boolean;
  editing: boolean;
  /** Whether drag/resize is actually available right now (false on stacked mobile/tablet layouts). */
  draggable?: boolean;
  onRemove: () => void;
  onEditQuery?: () => void;
  /** First-run checklist only: hide it for this operator. Absent for every other widget. */
  onDismiss?: () => void;
};

/** Keys from kestrel/src/kestrel/dashboard/presets.py's PRESETS dict — kept in sync manually. */
const KNOWN_PRESET_KEYS = new Set([
  "first_run",
  "summary_metrics",
  "open_by_severity",
  "by_status",
  "top_failing_policies",
  "recent_open_findings",
  "connector_health",
  "my_open_findings",
  "unassigned_open",
  "aging_open_findings",
]);

/**
 * `widget_key` is the reliable preset identifier: the catalog drawer sets it
 * to the preset's id when adding a built-in widget (matching presets.py's
 * dict key, e.g. "connector_health") and to `custom_<ts>` for a fresh query
 * widget. Checking `KNOWN_PRESET_KEYS` (rather than gating on
 * `viz_type === "preset"`) correctly matches non-"preset" viz_types too, like
 * the "donut" connector-health widget, which carries a `widget_key` but no
 * `query_spec.preset` — while still returning `null` for custom widgets so
 * callers can tell "real preset" apart from "ad hoc query".
 */
function presetKeyOf(widget: DashboardWidget): string | null {
  return KNOWN_PRESET_KEYS.has(widget.widget_key) ? widget.widget_key : null;
}

/** Charts and the KPI strip fill the grid cell; scrolling lists keep natural height. */
function widgetFillsHeight(widget: DashboardWidget): boolean {
  const preset = presetKeyOf(widget);
  if (
    preset === "summary_metrics" ||
    preset === "open_by_severity" ||
    preset === "by_status" ||
    preset === "connector_health"
  ) {
    return true;
  }
  return ["bar", "pie", "donut", "line", "area"].includes(widget.viz_type);
}

function findingsHref(drilldown: Record<string, unknown> | undefined) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(drilldown || {})) {
    if (v == null || v === "") continue;
    params.set(k, String(v));
  }
  const q = params.toString();
  return q ? `/findings?${q}` : "/findings";
}

/** Where clicking a query widget goes: the list its numbers came from. */
function drillHref(widget: DashboardWidget, drilldown: Record<string, unknown> | undefined) {
  const entity = widget.query_spec?.entity;
  if (entity === "connector") {
    const health = drilldown?.health;
    return typeof health === "string" ? `/connectors/health?health=${encodeURIComponent(health)}` : "/connectors/health";
  }
  return findingsHref(drilldown);
}

function subtitleFor(widget: DashboardWidget): string {
  const preset = widget.query_spec?.preset;
  if (typeof preset === "string") return `Preset · ${preset.replace(/_/g, " ")}`;
  const entity = widget.query_spec?.entity;
  if (typeof entity === "string") return `Query · ${entity}`;
  return widget.viz_type;
}

/** Where this widget should lead when clicked through — never a decorative dead end. */
function widgetDestination(
  widget: DashboardWidget,
  overview: DashboardOverview,
  query?: DashboardQueryResult,
): { href: string; label: string } | null {
  if (widget.viz_type === "markdown") return null;
  const preset = presetKeyOf(widget);

  if (preset === "first_run") return null;
  if (preset === "connector_health") return { href: "/connectors/health", label: "Open integration health" };
  if (preset === "top_failing_policies") return { href: "/policies", label: "Open policies" };
  if (preset === "my_open_findings") {
    const meId = overview.findings.viewer_operator_id;
    const href = meId
      ? `/findings?status=open&assigned_to_operator_id=${encodeURIComponent(meId)}`
      : "/findings?status=open";
    return { href, label: "Open my findings" };
  }
  if (preset === "unassigned_open") {
    return { href: "/findings?status=open&unassigned=true", label: "Open unassigned findings" };
  }
  if (preset === "aging_open_findings") return { href: "/findings?status=open", label: "Open aging queue" };
  if (preset === "summary_metrics") return { href: "/findings?status=open", label: "Open findings" };
  if (preset === "open_by_severity" || preset === "by_status" || preset === "recent_open_findings") {
    return { href: "/findings", label: "Open in Findings" };
  }
  if (widget.query_spec?.entity === "connector") return { href: drillHref(widget, undefined), label: "Open integration health" };
  return { href: findingsHref(query?.drilldown), label: "Open in Findings" };
}

export function DashboardWidgetCard({
  widget,
  overview,
  query,
  timeRange,
  loading,
  editing,
  draggable = true,
  onRemove,
  onEditQuery,
  onDismiss,
}: Props) {
  const preset = presetKeyOf(widget);
  const dismissable = preset === "first_run" && Boolean(onDismiss) && !editing;
  const destination = widgetDestination(widget, overview, query);
  const fillsHeight = widgetFillsHeight(widget);
  const timeWindow = widgetWindowLabel(widget.query_spec, timeRange);

  return (
    <Card
      className={cn(
        "flex h-full flex-col overflow-hidden",
        editing && "ring-1 ring-dashed ring-primary/40",
      )}
    >
      <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0 px-3 py-2.5">
        <div className="min-w-0 flex items-start gap-2">
          {editing && draggable ? (
            <span
              className="drag-handle mt-0.5 shrink-0 cursor-grab text-muted-foreground active:cursor-grabbing"
              aria-hidden
            >
              <GripVertical className="h-4 w-4" />
            </span>
          ) : null}
          <div className="min-w-0">
            <CardTitle className="truncate text-sm">{widget.title}</CardTitle>
            <CardDescription className="truncate">
              {subtitleFor(widget)}
              {timeWindow ? ` · ${timeWindow}` : ""}
            </CardDescription>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-0.5">
          {dismissable ? (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={onDismiss}
              aria-label="Dismiss checklist"
              title="Dismiss checklist"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          ) : null}
          {destination && !editing ? (
            <Button type="button" variant="ghost" size="icon" className="h-7 w-7" asChild>
              <Link href={destination.href} aria-label={destination.label} title={destination.label}>
                <ExternalLink className="h-3.5 w-3.5" />
              </Link>
            </Button>
          ) : null}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button type="button" variant="ghost" size="icon" className="h-7 w-7" aria-label="Widget menu">
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {destination ? (
                <DropdownMenuItem asChild>
                  <Link href={destination.href}>
                    <ExternalLink className="h-4 w-4" />
                    {destination.label}
                  </Link>
                </DropdownMenuItem>
              ) : null}
              {onEditQuery ? (
                <DropdownMenuItem onClick={onEditQuery}>Edit query</DropdownMenuItem>
              ) : null}
              {dismissable ? (
                <DropdownMenuItem onClick={onDismiss}>
                  <X className="h-4 w-4" />
                  Dismiss checklist
                </DropdownMenuItem>
              ) : null}
              {editing ? (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={onRemove} className="text-destructive focus:text-destructive">
                    <Trash2 className="h-4 w-4" />
                    Remove
                  </DropdownMenuItem>
                </>
              ) : null}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>
      <CardContent
        className={cn(
          "px-3 pb-3 pt-3",
          fillsHeight && "flex min-h-0 flex-1 flex-col",
        )}
      >
        {loading && !preset && widget.viz_type !== "markdown" ? (
          <div className="space-y-2 py-4">
            <Skeleton className="h-4 w-1/3" />
            <Skeleton className="h-32 w-full" />
          </div>
        ) : fillsHeight ? (
          <div className="flex min-h-0 flex-1 flex-col">
            <WidgetBody widget={widget} overview={overview} query={query} />
          </div>
        ) : (
          <WidgetBody widget={widget} overview={overview} query={query} />
        )}
      </CardContent>
    </Card>
  );
}

function WidgetBody({
  widget,
  overview,
  query,
}: {
  widget: DashboardWidget;
  overview: DashboardOverview;
  query?: DashboardQueryResult;
}) {
  const preset = presetKeyOf(widget);

  if (widget.viz_type === "markdown") {
    if (!widget.body_markdown?.trim()) {
      return <EmptyState title="No content" hint="This note widget has no text yet." showMark={false} />;
    }
    return (
      <pre className="whitespace-pre-wrap text-sm text-muted-foreground">{widget.body_markdown}</pre>
    );
  }

  if (preset) {
    return <PresetWidgetBody preset={preset} overview={overview} />;
  }

  const series = (query?.series ?? []).map((s) => ({ name: s.name, value: s.value }));
  const drill = query?.drilldown;

  if (widget.viz_type === "kpi") {
    const v = series[0]?.value ?? query?.total ?? 0;
    return (
      <KpiTile label={widget.title} value={v} href={drillHref(widget, drill)} />
    );
  }
  if (widget.viz_type === "bar") {
    return (
      <Link href={drillHref(widget, drill)} className="block h-full min-h-0 flex-1">
        <DashboardBarChart series={series} />
      </Link>
    );
  }
  if (widget.viz_type === "pie" || widget.viz_type === "donut") {
    return (
      <Link href={drillHref(widget, drill)} className="block h-full min-h-0 flex-1">
        <DashboardPieChart series={series} donut={widget.viz_type === "donut"} />
      </Link>
    );
  }
  if (widget.viz_type === "line") {
    const lineSeries = (query?.rows || series).map((r) => ({
      name: String((r as { date?: string; name?: string }).date || (r as { name?: string }).name || ""),
      value: Number(
        (r as { open_total?: number; value?: number }).open_total ??
          (r as { value?: number }).value ??
          0,
      ),
    }));
    return (
      <div className="h-full min-h-0 flex-1">
        <DashboardLineChart series={lineSeries} />
      </div>
    );
  }
  if (widget.viz_type === "area") {
    const lineSeries = (query?.rows || series).map((r) => ({
      name: String((r as { date?: string; name?: string }).date || (r as { name?: string }).name || ""),
      value: Number(
        (r as { open_total?: number; value?: number }).open_total ??
          (r as { value?: number }).value ??
          0,
      ),
    }));
    return (
      <div className="h-full min-h-0 flex-1">
        <DashboardAreaChart series={lineSeries} />
      </div>
    );
  }
  if (widget.viz_type === "table" || widget.viz_type === "list") {
    const rows = query?.rows ?? [];
    if (!rows.length) {
      return <EmptyState title="No data in this range" hint="Try a wider time range or a different filter." showMark={false} />;
    }
    return (
      <table className="w-full text-sm">
        <tbody>
          {rows.map((r, i) => (
            <tr key={String(r.label ?? i)} className="border-b border-border/50 last:border-0">
              <td className="py-2">
                <Link
                  href={drillHref(widget, {
                    ...drill,
                    ...(r.severity ? { severity: String(r.severity) } : {}),
                    ...(r.health ? { health: String(r.health) } : {}),
                  })}
                  className="hover:underline"
                >
                  {String(r.label)}
                </Link>
              </td>
              <td className="py-2 text-right tabular-nums text-muted-foreground">{String(r.value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  if (!series.length) {
    return <EmptyState title="No data in this range" hint="Try a wider time range or a different filter." showMark={false} />;
  }
  return (
    <ul className="space-y-1 text-sm">
      {series.map((s) => (
        <li key={s.name} className="flex justify-between gap-2">
          <span>{s.name}</span>
          <span className="tabular-nums">{s.value}</span>
        </li>
      ))}
    </ul>
  );
}
