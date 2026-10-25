// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useCallback, useEffect, useMemo, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import { DashboardChrome } from "@/components/dashboard/dashboard-chrome";
import {
  DeleteBoardDialog,
  ExportDialog,
  NewBoardDialog,
  ScheduleDialog,
} from "@/components/dashboard/dashboard-dialogs";
import { DashboardGrid } from "@/components/dashboard/dashboard-grid";
import { WidgetCatalogDrawer } from "@/components/dashboard/widget-catalog-drawer";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import {
  deleteDashboardWidget,
  dismissFirstRun,
  duplicateDashboard,
  pinDashboardHome,
  previewDashboardQuery,
  restoreFirstRun,
  saveDashboardLayouts,
} from "@/lib/actions/dashboards";
import type {
  DashboardBoard,
  DashboardOverview,
  DashboardPresetCatalog,
  DashboardQueryResult,
  DashboardSchedule,
} from "@/lib/types";
import { boardQueryKey, boardQueryTargets } from "@/lib/widget-query";

type Props = {
  overview: DashboardOverview;
  boards: DashboardBoard[];
  active: DashboardBoard;
  presets: DashboardPresetCatalog;
  schedules: DashboardSchedule[];
  isAdmin: boolean;
  canWrite: boolean;
  operatorId: string;
};

export function DashboardBoardView({
  overview,
  boards,
  active,
  presets,
  schedules,
  isAdmin,
  canWrite,
  operatorId,
}: Props) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [widgets, setWidgets] = useState(active.widgets);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState("30d");
  const [refreshInterval, setRefreshInterval] = useState("off");
  const [queryResults, setQueryResults] = useState<Record<string, DashboardQueryResult>>({});
  const [loadingIds, setLoadingIds] = useState<Set<string>>(new Set());

  const [showNew, setShowNew] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [showSchedule, setShowSchedule] = useState(false);
  const [showCatalog, setShowCatalog] = useState(false);
  const [showDelete, setShowDelete] = useState(false);

  // Dismissal is optimistic: the card goes away on click and the refreshed
  // overview then carries `dismissed` itself.
  const [firstRunDismissedLocally, setFirstRunDismissedLocally] = useState(false);
  const firstRunUnfinished = Boolean(overview.first_run && !overview.first_run.complete);
  const firstRunDismissed = Boolean(overview.first_run?.dismissed) || firstRunDismissedLocally;
  const firstRunIncomplete = firstRunUnfinished && !firstRunDismissed;

  // Mirrors the API guard: Home is undeletable, and non-admins may only delete
  // boards they created.
  const canDelete =
    canWrite &&
    !active.is_default &&
    (isAdmin || active.created_by_operator_id === operatorId);
  // Mirrors the API guard on edits: admins edit any board; everyone else only
  // boards they created, never Home.
  const canEdit =
    canWrite && (isAdmin || (!active.is_default && active.created_by_operator_id === operatorId));

  const visibleWidgets = useMemo(() => {
    let list = [...widgets];
    if (active.is_default && firstRunIncomplete) {
      const has = list.some(
        (w) => w.widget_key === "first_run" || w.query_spec?.preset === "first_run",
      );
      if (!has) {
        list = [
          {
            id: "virtual-first-run",
            widget_key: "first_run",
            title: "Get started",
            viz_type: "preset",
            query_spec: { preset: "first_run" },
            layout: { x: 0, y: 0, w: 12, h: 4 },
            sort_order: -1,
            body_markdown: null,
            refresh_seconds: null,
          },
          ...list,
        ];
      }
    } else {
      list = list.filter(
        (w) => w.widget_key !== "first_run" && w.query_spec?.preset !== "first_run",
      );
    }
    return list.sort((a, b) => a.sort_order - b.sort_order);
  }, [widgets, active.is_default, firstRunIncomplete]);

  // Finding widgets run as stored (their own window, if any), the same as
  // exports and scheduled emails; trends follow the header range. The key
  // changes only when a widget is added/removed or its query or the range
  // changes -- not on every drag/resize, which rebuilds `widgets`.
  const queryKey = boardQueryKey(boardQueryTargets(widgets, timeRange));
  // Rebuilt from the key, so its identity is as stable as the key's.
  const queryTargets = useMemo(
    () => (JSON.parse(queryKey) as [string, Record<string, unknown>][]).map(([id, spec]) => ({ id, spec })),
    [queryKey],
  );
  // Each load bumps this; a response from an older load is dropped, so a slow
  // preview cannot overwrite the results of a newer range or widget set.
  const queryGenRef = useRef(0);

  const loadQueries = useCallback(() => {
    const targets = queryTargets;
    const gen = ++queryGenRef.current;
    if (!targets.length) {
      setQueryResults({});
      setLoadingIds(new Set());
      return;
    }
    setLoadingIds(new Set(targets.map((t) => t.id)));
    startTransition(async () => {
      const entries = await Promise.all(
        targets.map(async (t) => {
          const res = await previewDashboardQuery(t.spec);
          return [t.id, res.ok ? res.data : null] as const;
        }),
      );
      if (gen !== queryGenRef.current) return;
      const next: Record<string, DashboardQueryResult> = {};
      for (const [id, data] of entries) {
        if (data) next[id] = data;
      }
      setQueryResults(next);
      setLoadingIds(new Set());
    });
  }, [queryTargets]);

  useEffect(() => {
    setWidgets(active.widgets);
    setEditing(false);
  }, [active.id, active.widgets]);

  useEffect(() => {
    loadQueries();
  }, [loadQueries]);

  useEffect(() => {
    if (refreshInterval === "off") return;
    const ms = Number(refreshInterval) * 1000;
    if (!Number.isFinite(ms) || ms < 1000) return;
    const id = window.setInterval(() => loadQueries(), ms);
    return () => window.clearInterval(id);
  }, [refreshInterval, loadQueries]);

  function saveLayouts() {
    setError(null);
    const toSave = widgets.filter((w) => !w.id.startsWith("virtual-"));
    startTransition(async () => {
      const res = await saveDashboardLayouts(
        active.id,
        toSave.map((w, i) => ({
          id: w.id,
          layout: w.layout,
          sort_order: i,
        })),
      );
      if (!res.ok) {
        setError(res.error);
        return;
      }
      setWidgets(res.dashboard.widgets);
      setMessage("Layout saved");
      setEditing(false);
      router.refresh();
    });
  }

  return (
    <div className="space-y-4">
      <DashboardChrome
        boards={boards}
        active={active}
        editing={editing}
        pending={pending}
        timeRange={timeRange}
        refreshInterval={refreshInterval}
        isAdmin={isAdmin}
        canDelete={canDelete}
        canEdit={canEdit}
        onSelectBoard={(id) => router.push(`/dashboard?id=${id}`)}
        onTimeRange={setTimeRange}
        onRefreshInterval={setRefreshInterval}
        onRefresh={loadQueries}
        onEdit={() => {
          setMessage(null);
          setEditing(true);
        }}
        onNewBoard={() => setShowNew(true)}
        onDuplicate={() =>
          startTransition(async () => {
            const res = await duplicateDashboard(active.id);
            if (!res.ok) setError(res.error);
            else router.push(`/dashboard?id=${res.dashboard.id}`);
          })
        }
        onPinHome={() =>
          startTransition(async () => {
            const res = await pinDashboardHome(active.id);
            if (!res.ok) setError(res.error);
            else setMessage("Pinned as your home dashboard");
          })
        }
        onExport={() => setShowExport(true)}
        onSchedule={() => setShowSchedule(true)}
        onDelete={() => setShowDelete(true)}
        canRestoreFirstRun={firstRunUnfinished && firstRunDismissed}
        onRestoreFirstRun={() =>
          startTransition(async () => {
            const res = await restoreFirstRun();
            if (!res.ok) {
              setError(res.error);
              return;
            }
            setFirstRunDismissedLocally(false);
            setMessage("Getting-started checklist restored");
            router.refresh();
          })
        }
      />
      {!editing ? (
        <p className="text-xs text-muted-foreground">
          The time range applies to posture-trend charts. Finding widgets count every finding
          unless the widget sets its own window; each card says which.
        </p>
      ) : null}

      {editing ? (
        <div className="sticky top-0 z-20 flex flex-wrap items-center gap-2 rounded-lg border border-primary/30 bg-card/95 px-3 py-2 shadow-sm backdrop-blur">
          <span className="text-sm font-medium">Editing layout</span>
          <span className="text-xs text-muted-foreground">Drag handles · resize corners</span>
          <div className="ml-auto flex flex-wrap gap-2">
            <Button type="button" variant="secondary" size="sm" onClick={() => setShowCatalog(true)}>
              Add widget
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setEditing(false);
                setWidgets(active.widgets);
              }}
            >
              Discard
            </Button>
            <Button type="button" size="sm" disabled={pending} onClick={saveLayouts}>
              {pending ? "Saving…" : "Save"}
            </Button>
          </div>
        </div>
      ) : null}

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {message && !error ? <p className="text-sm text-muted-foreground">{message}</p> : null}

      {visibleWidgets.length ? (
        <DashboardGrid
          widgets={visibleWidgets}
          overview={overview}
          queryResults={queryResults}
          timeRange={timeRange}
          loadingIds={loadingIds}
          editing={editing}
          onLayoutChange={(next) => {
            // Preserve virtual first-run widget outside persisted layout edits.
            const virtual = widgets.filter((w) => w.id.startsWith("virtual-"));
            const real = next.filter((w) => !w.id.startsWith("virtual-"));
            setWidgets([...virtual, ...real]);
          }}
          onRemove={(id) => {
            if (id.startsWith("virtual-")) return;
            startTransition(async () => {
              const res = await deleteDashboardWidget(active.id, id);
              if (!res.ok) {
                setError(res.error);
                return;
              }
              setWidgets((prev) => prev.filter((w) => w.id !== id));
              router.refresh();
            });
          }}
          onDismissFirstRun={() => {
            setFirstRunDismissedLocally(true);
            startTransition(async () => {
              const res = await dismissFirstRun();
              if (!res.ok) {
                setFirstRunDismissedLocally(false);
                setError(res.error);
                return;
              }
              setMessage("Checklist dismissed. Bring it back any time from the dashboard menu.");
              router.refresh();
            });
          }}
        />
      ) : (
        <EmptyState
          title="No widgets on this board"
          hint="Enter edit mode and add presets or a custom metric."
          action={
            <Button type="button" size="sm" onClick={() => { setEditing(true); setShowCatalog(true); }}>
              Add widget
            </Button>
          }
        />
      )}

      <NewBoardDialog
        open={showNew}
        onOpenChange={setShowNew}
        templates={presets.templates}
        onCreated={(id) => router.push(`/dashboard?id=${id}`)}
        onError={setError}
      />
      <DeleteBoardDialog
        open={showDelete}
        onOpenChange={setShowDelete}
        board={active}
        onDeleted={() => {
          setMessage(`Deleted “${active.name}”`);
          router.push("/dashboard");
          router.refresh();
        }}
      />
      <ExportDialog open={showExport} onOpenChange={setShowExport} dashboardId={active.id} />
      {isAdmin ? (
        <ScheduleDialog
          open={showSchedule}
          onOpenChange={setShowSchedule}
          dashboardId={active.id}
          schedules={schedules}
          onError={setError}
          onSaved={() => router.refresh()}
        />
      ) : null}
      <WidgetCatalogDrawer
        open={showCatalog}
        onOpenChange={setShowCatalog}
        dashboardId={active.id}
        presets={presets.presets}
        timeRange={timeRange}
        onError={setError}
        onAdded={() => router.refresh()}
      />
    </div>
  );
}
