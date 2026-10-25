// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import type { ReactNode } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";

import { cn } from "@/lib/utils";
import {
  DRAWER_TABS,
  DRAWER_TAB_LABELS,
  type DrawerBadge,
  type DrawerTab,
} from "@/lib/policy-editor-state";

const TONE_DOT: Record<NonNullable<DrawerBadge["tone"]>, string> = {
  error: "bg-destructive",
  success: "bg-green-500",
  warning: "bg-amber-500",
};

/**
 * Tab strip + body for the editor results drawer.
 *
 * Panels are rendered by the parent and passed in as `children` so each one can
 * keep its own state (the fixtures editor in particular must stay mounted once
 * opened, or every tab switch would discard uncommitted edits).
 */
export function ResultsDrawer({
  active,
  onSelect,
  badges,
  collapsed,
  onToggleCollapsed,
  children,
}: {
  active: DrawerTab;
  onSelect: (tab: DrawerTab) => void;
  badges: Record<DrawerTab, DrawerBadge>;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  children: ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-md border border-border bg-elevated">
      <div className="flex items-center justify-between gap-2 border-b border-border bg-muted/40 px-2 py-1">
        <div className="flex flex-wrap items-center gap-1" role="tablist" aria-label="Editor results">
          {DRAWER_TABS.map((tab) => {
            const badge = badges[tab];
            const selected = !collapsed && active === tab;
            return (
              <button
                key={tab}
                type="button"
                role="tab"
                id={`policy-drawer-tab-${tab}`}
                aria-selected={selected}
                aria-controls={`policy-drawer-panel-${tab}`}
                onClick={() => onSelect(tab)}
                className={cn(
                  "flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors duration-150",
                  selected
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:bg-background/60 hover:text-foreground",
                )}
              >
                {DRAWER_TAB_LABELS[tab]}
                {badge.tone ? (
                  <span
                    className={cn("size-1.5 rounded-full", TONE_DOT[badge.tone])}
                    aria-hidden
                  />
                ) : null}
                {badge.count != null ? (
                  <span className="rounded bg-muted px-1 font-mono text-[10px] text-muted-foreground">
                    {badge.count}
                  </span>
                ) : null}
              </button>
            );
          })}
        </div>
        <button
          type="button"
          onClick={onToggleCollapsed}
          aria-expanded={!collapsed}
          aria-label={collapsed ? "Expand results drawer" : "Collapse results drawer"}
          title={collapsed ? "Expand results" : "Collapse results (maximize editor)"}
          className="rounded p-1 text-muted-foreground transition-colors duration-150 hover:bg-background hover:text-foreground"
        >
          {collapsed ? (
            <ChevronUp className="size-4" aria-hidden />
          ) : (
            <ChevronDown className="size-4" aria-hidden />
          )}
        </button>
      </div>
      <div hidden={collapsed}>{children}</div>
    </div>
  );
}

/** Body wrapper for a single panel — owns the drawer's scroll region. */
export function DrawerPanel({
  tab,
  active,
  children,
  className,
}: {
  tab: DrawerTab;
  active: DrawerTab;
  children: ReactNode;
  className?: string;
}) {
  const selected = tab === active;
  return (
    <div
      role="tabpanel"
      id={`policy-drawer-panel-${tab}`}
      aria-labelledby={`policy-drawer-tab-${tab}`}
      hidden={!selected}
      className={cn("max-h-[28rem] overflow-y-auto p-3", className)}
    >
      {children}
    </div>
  );
}
