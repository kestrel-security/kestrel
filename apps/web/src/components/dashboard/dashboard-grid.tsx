// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import dynamic from "next/dynamic";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Layout } from "react-grid-layout";

import { DashboardWidgetCard } from "@/components/dashboard/dashboard-widget-card";
import type {
  DashboardOverview,
  DashboardQueryResult,
  DashboardWidget,
} from "@/lib/types";

import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

const GridLayout = dynamic(() => import("react-grid-layout"), { ssr: false });

const ROW_HEIGHT = 36;
/** Below this width, stack every widget full-width single-column — dense multi-column
 * layouts squeeze charts/tables illegibly on tablet and mobile. */
const STACK_BREAKPOINT = 1024;

type Props = {
  widgets: DashboardWidget[];
  overview: DashboardOverview;
  queryResults: Record<string, DashboardQueryResult>;
  /** Header range, which posture-trend widgets follow. */
  timeRange: string;
  loadingIds: Set<string>;
  editing: boolean;
  onLayoutChange: (widgets: DashboardWidget[]) => void;
  onRemove: (id: string) => void;
  /** Dismisses the first-run checklist; only that widget receives it. */
  onDismissFirstRun?: () => void;
};

function isFirstRunWidget(w: DashboardWidget): boolean {
  return w.widget_key === "first_run" || w.query_spec?.preset === "first_run";
}

function toLayout(widgets: DashboardWidget[], cols: number): Layout[] {
  if (cols < 12) {
    // Stacked mobile/tablet layout: full width, natural reading order.
    let y = 0;
    return widgets.map((w) => {
      // The KPI strip wraps to two rows of tiles when stacked.
      const minH = w.widget_key === "summary_metrics" ? 7 : 6;
      const h = Math.max(minH, Number(w.layout?.h ?? 5));
      const item = { i: w.id, x: 0, y, w: cols, h, minW: cols, minH: 3 };
      y += h;
      return item;
    });
  }
  return widgets.map((w, i) => {
    const L = w.layout || {};
    return {
      i: w.id,
      x: Number(L.x ?? (i % 2) * 6),
      y: Number(L.y ?? Math.floor(i / 2) * 4),
      w: Math.min(12, Math.max(3, Number(L.w ?? 6))),
      h: Math.max(3, Number(L.h ?? 5)),
      minW: 3,
      minH: 5,
    };
  });
}

export function DashboardGrid({
  widgets,
  overview,
  queryResults,
  timeRange,
  loadingIds,
  editing,
  onLayoutChange,
  onRemove,
  onDismissFirstRun,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  const cols = width > 0 && width < STACK_BREAKPOINT ? 1 : 12;
  const stacked = cols < 12;
  const interactive = editing && !stacked;
  const layout = useMemo(() => toLayout(widgets, cols), [widgets, cols]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    let frame = 0;
    const sync = () => {
      const next = Math.max(0, Math.floor(el.getBoundingClientRect().width));
      setWidth((prev) => (prev === next ? prev : next));
    };
    sync();
    const ro = new ResizeObserver(() => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(sync);
    });
    ro.observe(el);
    return () => {
      cancelAnimationFrame(frame);
      ro.disconnect();
    };
  }, []);

  return (
    <div ref={containerRef} className="w-full">
      {editing && stacked ? (
        <p className="mb-2 text-xs text-muted-foreground">
          Widen your browser to reorder or resize widgets — layout edits need the full 12-column grid.
        </p>
      ) : null}
      {width > 0 ? (
        <GridLayout
          className="layout"
          layout={layout}
          width={width}
          cols={cols}
          rowHeight={ROW_HEIGHT}
          margin={[16, 16]}
          containerPadding={[0, 0]}
          isDraggable={interactive}
          isResizable={interactive}
          draggableHandle=".drag-handle"
          compactType="vertical"
          onLayoutChange={(next) => {
            if (!interactive) return;
            const byId = new Map(widgets.map((w) => [w.id, w]));
            const updated = next
              .map((item, sort_order) => {
                const w = byId.get(item.i);
                if (!w) return null;
                return {
                  ...w,
                  sort_order,
                  layout: { x: item.x, y: item.y, w: item.w, h: item.h },
                };
              })
              .filter(Boolean) as DashboardWidget[];
            onLayoutChange(updated);
          }}
        >
          {widgets.map((w) => (
            <div key={w.id} className="h-full">
              <DashboardWidgetCard
                widget={w}
                overview={overview}
                query={queryResults[w.id]}
                timeRange={timeRange}
                loading={loadingIds.has(w.id)}
                editing={editing}
                draggable={interactive}
                onRemove={() => onRemove(w.id)}
                onDismiss={isFirstRunWidget(w) ? onDismissFirstRun : undefined}
              />
            </div>
          ))}
        </GridLayout>
      ) : (
        <div className="h-48 animate-pulse rounded-lg border border-border bg-muted/20" />
      )}
    </div>
  );
}
