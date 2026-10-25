// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import {
  CalendarClock,
  Copy,
  Download,
  Home,
  ListChecks,
  MoreHorizontal,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { PageHeader } from "@/components/ui/page-header";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { DashboardBoard } from "@/lib/types";
import { cn } from "@/lib/utils";

export const TIME_RANGES = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
] as const;

export const REFRESH_OPTIONS = [
  { value: "off", label: "Off" },
  { value: "60", label: "1 min" },
  { value: "300", label: "5 min" },
  { value: "900", label: "15 min" },
] as const;

type Props = {
  boards: DashboardBoard[];
  active: DashboardBoard;
  editing: boolean;
  pending: boolean;
  timeRange: string;
  refreshInterval: string;
  isAdmin: boolean;
  canDelete: boolean;
  canEdit: boolean;
  /** The viewer dismissed an unfinished getting-started checklist; offer to bring it back. */
  canRestoreFirstRun: boolean;
  onSelectBoard: (id: string) => void;
  onTimeRange: (v: string) => void;
  onRefreshInterval: (v: string) => void;
  onRefresh: () => void;
  onEdit: () => void;
  onNewBoard: () => void;
  onDuplicate: () => void;
  onPinHome: () => void;
  onExport: () => void;
  onSchedule: () => void;
  onDelete: () => void;
  onRestoreFirstRun: () => void;
};

export function DashboardChrome({
  boards,
  active,
  editing,
  pending,
  timeRange,
  refreshInterval,
  isAdmin,
  canDelete,
  canEdit,
  canRestoreFirstRun,
  onSelectBoard,
  onTimeRange,
  onRefreshInterval,
  onRefresh,
  onEdit,
  onNewBoard,
  onDuplicate,
  onPinHome,
  onExport,
  onSchedule,
  onDelete,
  onRestoreFirstRun,
}: Props) {
  const tabBoards = pickTabs(boards, active.id);

  return (
    <PageHeader
      className="mb-0"
      eyebrow="Dashboard"
      title={active.name}
      status={
        <Badge variant="outline" className="shrink-0 capitalize">
          {active.visibility}
          {active.is_default ? " · home" : ""}
        </Badge>
      }
      description={active.description || "Security posture command center"}
      actions={
        !editing ? (
          <>
            <Select value={timeRange} onValueChange={onTimeRange}>
              <SelectTrigger className="h-9 w-[160px]" aria-label="Trend time range" title="Applies to posture-trend charts">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TIME_RANGES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={refreshInterval} onValueChange={onRefreshInterval}>
              <SelectTrigger className="h-9 w-[110px]" aria-label="Auto refresh">
                <SelectValue placeholder="Refresh" />
              </SelectTrigger>
              <SelectContent>
                {REFRESH_OPTIONS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button type="button" variant="outline" size="icon" className="h-9 w-9" onClick={onRefresh} disabled={pending} aria-label="Refresh now">
              <RefreshCw className={cn("h-4 w-4", pending && "animate-spin")} />
            </Button>

            {canEdit ? (
              <Button type="button" size="sm" className="h-9" onClick={onEdit}>
                <Pencil className="mr-1.5 h-3.5 w-3.5" />
                Edit
              </Button>
            ) : null}

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button type="button" variant="outline" size="icon" className="h-9 w-9" aria-label="More actions">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel>Dashboard</DropdownMenuLabel>
                <DropdownMenuItem onClick={onDuplicate}>
                  <Copy className="h-4 w-4" />
                  Duplicate
                </DropdownMenuItem>
                <DropdownMenuItem onClick={onPinHome}>
                  <Home className="h-4 w-4" />
                  Set as my home
                </DropdownMenuItem>
                {canRestoreFirstRun ? (
                  <DropdownMenuItem onClick={onRestoreFirstRun}>
                    <ListChecks className="h-4 w-4" />
                    Show getting-started checklist
                  </DropdownMenuItem>
                ) : null}
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={onExport}>
                  <Download className="h-4 w-4" />
                  Export…
                </DropdownMenuItem>
                {isAdmin ? (
                  <DropdownMenuItem onClick={onSchedule}>
                    <CalendarClock className="h-4 w-4" />
                    Schedule email…
                  </DropdownMenuItem>
                ) : null}
                {canDelete ? (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onClick={onDelete}
                      className="text-destructive focus:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                      Delete dashboard…
                    </DropdownMenuItem>
                  </>
                ) : null}
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        ) : null
      }
    >
      {/* Board tabs + switcher */}
      <div className="flex flex-wrap items-center gap-1 border-b border-border pb-px">
        {tabBoards.map((b) => (
          <button
            key={b.id}
            type="button"
            onClick={() => onSelectBoard(b.id)}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              b.id === active.id
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {b.name}
            {b.is_default && b.name.toLowerCase() !== "home" ? (
              <span className="ml-1.5 text-[10px] font-normal uppercase tracking-wide text-muted-foreground">
                Home
              </span>
            ) : null}
          </button>
        ))}

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button type="button" variant="ghost" size="sm" className="h-8 text-muted-foreground">
              All dashboards…
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-64">
            <DropdownMenuLabel>Switch dashboard</DropdownMenuLabel>
            {boards.map((b) => (
              <DropdownMenuItem key={b.id} onClick={() => onSelectBoard(b.id)}>
                <span className="flex-1 truncate">{b.name}</span>
                <span className="text-[10px] uppercase text-muted-foreground">
                  {b.visibility}
                  {b.is_default ? " · default" : ""}
                </span>
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={onNewBoard}>
              <Plus className="h-4 w-4" />
              New dashboard
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </PageHeader>
  );
}

function pickTabs(boards: DashboardBoard[], activeId: string): DashboardBoard[] {
  const home = boards.find((b) => b.is_default);
  const active = boards.find((b) => b.id === activeId);
  const rest = boards.filter((b) => b.id !== home?.id && b.id !== active?.id).slice(0, 2);
  const out: DashboardBoard[] = [];
  if (home) out.push(home);
  if (active && active.id !== home?.id) out.push(active);
  for (const b of rest) {
    if (out.length >= 4) break;
    out.push(b);
  }
  return out;
}
