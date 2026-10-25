// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition } from "react";

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
import {
  createDashboard,
  createDashboardSchedule,
  deleteDashboard,
} from "@/lib/actions/dashboards";
import type { DashboardBoard, DashboardPresetCatalog, DashboardSchedule } from "@/lib/types";
import { cn } from "@/lib/utils";

export function NewBoardDialog({
  open,
  onOpenChange,
  templates,
  onCreated,
  onError,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  templates: DashboardPresetCatalog["templates"];
  onCreated: (id: string) => void;
  onError: (msg: string) => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [template, setTemplate] = useState("");
  const [visibility, setVisibility] = useState("org");
  const [pending, startTransition] = useTransition();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>New dashboard</DialogTitle>
          <DialogDescription>
            Create a named board from a blank canvas or an app template.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="nb-name">Name</Label>
            <Input
              id="nb-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Okta posture"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="nb-desc">Description</Label>
            <Input
              id="nb-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional"
            />
          </div>
          <div className="space-y-1.5">
            <Label>Template</Label>
            <div className="grid gap-2 sm:grid-cols-3">
              <TemplateCard
                title="Blank"
                description="Empty board"
                selected={template === ""}
                onClick={() => setTemplate("")}
              />
              {templates.map((t) => (
                <TemplateCard
                  key={t.slug}
                  title={t.name}
                  description={t.description}
                  selected={template === t.slug}
                  onClick={() => setTemplate(t.slug)}
                />
              ))}
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>Visibility</Label>
            <Select value={visibility} onValueChange={setVisibility}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="org">Organization</SelectItem>
                <SelectItem value="private">Private</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            type="button"
            disabled={pending || !name.trim()}
            onClick={() =>
              startTransition(async () => {
                const res = await createDashboard({
                  name: name.trim(),
                  description: description.trim() || null,
                  template: template || null,
                  visibility,
                });
                if (!res.ok) {
                  onError(res.error);
                  return;
                }
                setName("");
                setDescription("");
                setTemplate("");
                onOpenChange(false);
                onCreated(res.dashboard.id);
              })
            }
          >
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TemplateCard({
  title,
  description,
  selected,
  onClick,
}: {
  title: string;
  description: string;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-lg border p-3 text-left transition-colors",
        selected
          ? "border-primary bg-primary/5 ring-1 ring-primary"
          : "border-border hover:bg-muted/40",
      )}
    >
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">{description}</p>
    </button>
  );
}

export function DeleteBoardDialog({
  open,
  onOpenChange,
  board,
  onDeleted,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  board: DashboardBoard;
  onDeleted: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const widgetCount = board.widgets?.length ?? 0;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setError(null);
        onOpenChange(next);
      }}
    >
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Delete dashboard &ldquo;{board.name}&rdquo;?</DialogTitle>
          <DialogDescription>
            {widgetCount === 1 ? "Its 1 widget" : `Its ${widgetCount} widgets`} and any email
            schedules will be removed. This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            disabled={pending}
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={pending}
            onClick={() =>
              startTransition(async () => {
                setError(null);
                const res = await deleteDashboard(board.id);
                if (!res.ok) {
                  setError(res.error);
                  return;
                }
                onOpenChange(false);
                onDeleted();
              })
            }
          >
            {pending ? "Deleting…" : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ExportDialog({
  open,
  onOpenChange,
  dashboardId,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  dashboardId: string;
}) {
  const [format, setFormat] = useState("pdf");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Export dashboard</DialogTitle>
          <DialogDescription>Download a snapshot of this board.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          {[
            { id: "pdf", label: "PDF", hint: "Printable summary" },
            { id: "csv", label: "CSV", hint: "Widget values for sheets" },
            { id: "json", label: "JSON", hint: "Full snapshot payload" },
          ].map((f) => (
            <label
              key={f.id}
              className={cn(
                "flex cursor-pointer items-start gap-3 rounded-lg border p-3",
                format === f.id ? "border-primary bg-primary/5" : "border-border",
              )}
            >
              <input
                type="radio"
                name="export-format"
                className="mt-1"
                checked={format === f.id}
                onChange={() => setFormat(f.id)}
              />
              <span>
                <span className="block text-sm font-medium">{f.label}</span>
                <span className="text-xs text-muted-foreground">{f.hint}</span>
              </span>
            </label>
          ))}
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => {
              window.location.href = new URL(
                `/api/dashboards/${dashboardId}/export?format=${format}`,
                window.location.origin,
              ).href;
              onOpenChange(false);
            }}
          >
            Download
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

const CADENCE_PRESETS = [
  { id: "daily", label: "Daily at 09:00 UTC", cron: "0 9 * * *" },
  { id: "weekly", label: "Weekly Monday 09:00 UTC", cron: "0 9 * * 1" },
  { id: "custom", label: "Custom cron…", cron: "" },
];

export function ScheduleDialog({
  open,
  onOpenChange,
  dashboardId,
  schedules,
  onError,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  dashboardId: string;
  schedules: DashboardSchedule[];
  onError: (msg: string) => void;
  onSaved: () => void;
}) {
  const [cadence, setCadence] = useState("weekly");
  const [cron, setCron] = useState("0 9 * * 1");
  const [pending, startTransition] = useTransition();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Email schedule</DialogTitle>
          <DialogDescription>
            Send a PDF snapshot to yourself on a cadence. Requires email to be set up in Settings
            → Email.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3 py-2">
          {schedules.length ? (
            <ul className="space-y-2 rounded-lg border border-border bg-elevated p-3 text-sm">
              {schedules.map((s) => (
                <li key={s.id} className="flex justify-between gap-2">
                  <span>
                    {s.cron} · {s.format}
                  </span>
                  <span className="text-muted-foreground">{s.last_status || "never run"}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">No schedules yet.</p>
          )}
          <div className="space-y-1.5">
            <Label>Cadence</Label>
            <Select
              value={cadence}
              onValueChange={(v) => {
                setCadence(v);
                const p = CADENCE_PRESETS.find((c) => c.id === v);
                if (p?.cron) setCron(p.cron);
              }}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CADENCE_PRESETS.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {cadence === "custom" ? (
            <div className="space-y-1.5">
              <Label htmlFor="sched-cron">Cron (UTC)</Label>
              <Input id="sched-cron" value={cron} onChange={(e) => setCron(e.target.value)} />
            </div>
          ) : null}
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          <Button
            type="button"
            disabled={pending || !cron.trim()}
            onClick={() =>
              startTransition(async () => {
                const res = await createDashboardSchedule(dashboardId, {
                  cron: cron.trim(),
                  timezone: "UTC",
                  format: "pdf",
                  recipient_operator_ids: [],
                });
                if (!res.ok) {
                  onError(res.error);
                  return;
                }
                onSaved();
                onOpenChange(false);
              })
            }
          >
            Add schedule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
