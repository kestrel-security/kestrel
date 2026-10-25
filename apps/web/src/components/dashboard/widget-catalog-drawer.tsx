// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition } from "react";

import {
  DashboardBarChart,
  DashboardLineChart,
  DashboardPieChart,
} from "@/components/dashboard/widget-charts-lazy";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { createDashboardWidget, previewDashboardQuery } from "@/lib/actions/dashboards";
import type { DashboardPresetCatalog, DashboardQueryResult } from "@/lib/types";
import { cn } from "@/lib/utils";
import {
  FINDING_WINDOW_OPTIONS,
  GROUP_BY_OPTIONS,
  VIZ_OPTIONS,
  WIDGET_ENTITIES,
  buildWidgetQuerySpec,
  type WidgetEntity,
} from "@/lib/widget-query";

type Props = {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  dashboardId: string;
  presets: DashboardPresetCatalog["presets"];
  timeRange: string;
  onAdded: () => void;
  onError: (msg: string) => void;
};

export function WidgetCatalogDrawer({
  open,
  onOpenChange,
  dashboardId,
  presets,
  timeRange,
  onAdded,
  onError,
}: Props) {
  const [pending, startTransition] = useTransition();
  const [title, setTitle] = useState("Custom metric");
  const [entity, setEntity] = useState<WidgetEntity>("finding");
  const [groupBy, setGroupBy] = useState("severity");
  const [status, setStatus] = useState("open");
  const [findingWindow, setFindingWindow] = useState("any");
  const [viz, setViz] = useState("bar");
  const [width, setWidth] = useState("6");
  const [preview, setPreview] = useState<DashboardQueryResult | null>(null);

  function buildQuerySpec(): Record<string, unknown> {
    return buildWidgetQuerySpec({ entity, groupBy, status, viz, findingWindow, trendRange: timeRange });
  }

  function changeEntity(next: string) {
    const nextEntity = next as WidgetEntity;
    setEntity(nextEntity);
    setGroupBy(GROUP_BY_OPTIONS[nextEntity][0]?.value ?? "");
    setViz(VIZ_OPTIONS[nextEntity][0].value);
    setPreview(null);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] max-w-2xl flex-col gap-0 overflow-hidden p-0">
        <DialogHeader className="border-b border-border px-6 py-4">
          <DialogTitle>Add widget</DialogTitle>
          <DialogDescription>
            Choose a preset or author a constrained metric query.
          </DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="presets" className="flex min-h-0 flex-1 flex-col">
          <div className="border-b border-border px-6 pt-3">
            <TabsList>
              <TabsTrigger value="presets">Presets</TabsTrigger>
              <TabsTrigger value="custom">Custom query</TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value="presets" className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
            <div className="grid gap-3 sm:grid-cols-2">
              {presets.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  disabled={pending}
                  className="rounded-lg border border-border p-3.5 text-left transition-colors hover:border-primary/40 hover:bg-elevated"
                  onClick={() =>
                    startTransition(async () => {
                      const res = await createDashboardWidget(dashboardId, {
                        widget_key: p.id,
                        title: p.title,
                        viz_type: p.viz_type,
                        query_spec: p.query_spec,
                        preset_id: p.id,
                        layout: (p.layout as { x: number; y: number; w: number; h: number }) || {
                          x: 0,
                          y: 0,
                          w: 6,
                          h: 5,
                        },
                      });
                      if (!res.ok) {
                        onError(res.error);
                        return;
                      }
                      onOpenChange(false);
                      onAdded();
                    })
                  }
                >
                  <p className="text-sm font-medium">{p.title}</p>
                  <p className="mt-1 text-xs text-muted-foreground">{p.description}</p>
                  <p className="text-eyebrow mt-2">
                    {p.viz_type}
                    {p.in_default ? " · default" : ""}
                  </p>
                </button>
              ))}
            </div>
          </TabsContent>
          <TabsContent value="custom" className="min-h-0 flex-1 overflow-y-auto px-6 py-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Title">
                <Input value={title} onChange={(e) => setTitle(e.target.value)} />
              </Field>
              <Field label="Entity">
                <Select value={entity} onValueChange={changeEntity}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {WIDGET_ENTITIES.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              {GROUP_BY_OPTIONS[entity].length > 0 ? (
                <Field label="Group by">
                  <Select value={groupBy} onValueChange={setGroupBy} disabled={viz === "kpi"}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {GROUP_BY_OPTIONS[entity].map((o) => (
                        <SelectItem key={o.value} value={o.value}>
                          {o.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
              ) : null}
              {entity === "finding" ? (
                <Field label="Status filter">
                  <Input value={status} onChange={(e) => setStatus(e.target.value)} placeholder="any status" />
                </Field>
              ) : null}
              {entity === "finding" ? (
                <Field label="First seen">
                  <Select
                    value={findingWindow}
                    onValueChange={(v) => {
                      setFindingWindow(v);
                      setPreview(null);
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {FINDING_WINDOW_OPTIONS.map((o) => (
                        <SelectItem key={o.value} value={o.value}>
                          {o.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
              ) : null}
              <Field label="Visualization">
                <Select value={viz} onValueChange={setViz}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {VIZ_OPTIONS[entity].map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <Field label="Width">
                <Select value={width} onValueChange={setWidth}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {[3, 4, 6, 8, 12].map((n) => (
                      <SelectItem key={n} value={String(n)}>
                        {n} / 12 columns
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            </div>
            {preview ? (
              <div className="mt-4 rounded-lg border border-border bg-elevated p-3">
                <p className="mb-2 text-xs text-muted-foreground">
                  Preview · total {preview.total ?? 0}
                </p>
                {entity === "posture_trend" ? (
                  <DashboardLineChart
                    series={(preview.rows ?? []).map((r) => ({
                      name: String((r as { date?: string }).date ?? ""),
                      value: Number((r as { open_total?: number }).open_total ?? 0),
                    }))}
                  />
                ) : viz === "pie" || viz === "donut" ? (
                  <DashboardPieChart
                    series={preview.series ?? []}
                    donut={viz === "donut"}
                    height={160}
                  />
                ) : (
                  <DashboardBarChart series={preview.series ?? []} height={160} />
                )}
              </div>
            ) : null}
            <div className="mt-4 flex gap-2">
              <Button
                type="button"
                variant="outline"
                disabled={pending}
                onClick={() =>
                  startTransition(async () => {
                    const res = await previewDashboardQuery(buildQuerySpec());
                    if (!res.ok) onError(res.error);
                    else setPreview(res.data);
                  })
                }
              >
                Preview
              </Button>
              <Button
                type="button"
                disabled={pending || !title.trim()}
                onClick={() =>
                  startTransition(async () => {
                    const res = await createDashboardWidget(dashboardId, {
                      widget_key: `custom_${Date.now()}`,
                      title: title.trim(),
                      viz_type: viz,
                      query_spec: buildQuerySpec(),
                      layout: { x: 0, y: 0, w: Number(width), h: 5 },
                    });
                    if (!res.ok) {
                      onError(res.error);
                      return;
                    }
                    onOpenChange(false);
                    onAdded();
                  })
                }
              >
                Add to board
              </Button>
            </div>
          </TabsContent>
        </Tabs>
        <DialogFooter className="border-t border-border px-6 py-3">
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className={cn("space-y-1.5")}>
      <Label>{label}</Label>
      {children}
    </div>
  );
}
