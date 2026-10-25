// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { AlertTriangle, ArrowRight, CheckCircle2, ShieldAlert } from "lucide-react";

import { cn } from "@/lib/utils";

const TONE_CONFIG = {
  default: { bar: "bg-border", icon: null, iconClass: "" },
  danger: { bar: "bg-tone-critical", icon: ShieldAlert, iconClass: "text-tone-critical" },
  warning: { bar: "bg-tone-medium", icon: AlertTriangle, iconClass: "text-tone-medium" },
  success: { bar: "bg-tone-success", icon: CheckCircle2, iconClass: "text-tone-success" },
} as const;

export function KpiTile({
  label,
  value,
  href,
  tone = "default",
  hint,
}: {
  label: string;
  value: number | string;
  href?: string;
  tone?: "default" | "danger" | "warning" | "success";
  hint?: string;
}) {
  const config = TONE_CONFIG[tone];
  const Icon = config.icon;

  const inner = (
    <div
      className={cn(
        "group relative flex h-full flex-col gap-1 overflow-hidden rounded-lg border border-border bg-card py-2.5 pl-4 pr-3 shadow-sm transition-colors",
        href && "hover:border-primary/40 hover:bg-muted/30",
      )}
    >
      <span className={cn("absolute inset-y-0 left-0 w-0.5", config.bar)} aria-hidden />
      <div className="flex items-start justify-between gap-2">
        <p className="text-eyebrow">{label}</p>
        {Icon ? <Icon className={cn("size-3.5 shrink-0", config.iconClass)} aria-hidden /> : null}
      </div>
      <div className="flex items-end justify-between gap-2">
        <p className="text-2xl font-semibold tabular-nums leading-none tracking-tight text-foreground">
          {value}
        </p>
        {href ? (
          <ArrowRight
            className="size-3.5 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100"
            aria-hidden
          />
        ) : null}
      </div>
      {hint ? <p className="text-xs leading-snug text-muted-foreground">{hint}</p> : null}
    </div>
  );

  if (href) {
    return (
      <Link
        href={href}
        className="block h-full rounded-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {inner}
      </Link>
    );
  }
  return inner;
}
