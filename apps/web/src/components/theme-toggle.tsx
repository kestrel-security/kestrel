// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Monitor, Moon, Sun } from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useTheme } from "@/hooks/use-theme";
import { cn } from "@/lib/utils";
import type { ThemePreference } from "@/lib/theme";

const OPTIONS: {
  value: ThemePreference;
  label: string;
  icon: typeof Sun;
}[] = [
  { value: "light", label: "Light", icon: Sun },
  { value: "system", label: "System", icon: Monitor },
  { value: "dark", label: "Dark", icon: Moon },
];

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <div className="mb-2">
      <p className="sidebar-label text-eyebrow mb-1.5 px-1 text-sidebar-muted">Appearance</p>
      <div
        role="group"
        aria-label="Appearance"
        className="sidebar-theme-group flex rounded-md border border-sidebar-border bg-black/15 p-0.5"
      >
        {OPTIONS.map(({ value, label, icon: Icon }) => {
          const active = theme === value;
          return (
            <Tooltip key={value}>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  aria-label={label}
                  aria-pressed={active}
                  onClick={() => setTheme(value)}
                  className={cn(
                    "flex flex-1 items-center justify-center rounded-sm px-2 py-1.5 text-sidebar-muted transition-colors duration-150",
                    active
                      ? "bg-primary/20 text-white ring-1 ring-inset ring-primary/30"
                      : "hover:bg-white/5 hover:text-sidebar-foreground",
                  )}
                >
                  <Icon className="size-3.5" aria-hidden />
                </button>
              </TooltipTrigger>
              <TooltipContent side="right" sideOffset={8}>
                {label}
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </div>
  );
}
