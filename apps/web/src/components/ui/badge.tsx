// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import * as React from "react";
import { AlertTriangle, CircleAlert, Info, ShieldAlert } from "lucide-react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary/15 text-primary",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        outline: "border-border text-foreground",
        destructive: "border-transparent bg-destructive/15 text-destructive",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

const SEVERITY_CONFIG: Record<
  string,
  {
    className: string;
    iconClassName: string;
    icon: React.ComponentType<{ className?: string }>;
    label: string;
  }
> = {
  critical: {
    className: "border-tone-critical/25 bg-tone-critical/10 text-foreground",
    iconClassName: "text-tone-critical",
    icon: ShieldAlert,
    label: "Critical",
  },
  high: {
    className: "border-tone-high/25 bg-tone-high/10 text-foreground",
    iconClassName: "text-tone-high",
    icon: CircleAlert,
    label: "High",
  },
  medium: {
    className: "border-tone-medium/25 bg-tone-medium/10 text-foreground",
    iconClassName: "text-tone-medium",
    icon: AlertTriangle,
    label: "Medium",
  },
  low: {
    className: "border-tone-low/25 bg-tone-low/10 text-foreground",
    iconClassName: "text-tone-low",
    icon: Info,
    label: "Low",
  },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const config = SEVERITY_CONFIG[severity] ?? {
    className: "border-border bg-muted text-foreground",
    iconClassName: "text-muted-foreground",
    icon: Info,
    label: severity,
  };
  const Icon = config.icon;
  return (
    <Badge className={cn("capitalize", config.className)}>
      <Icon className={cn("size-3", config.iconClassName)} aria-hidden />
      <span>{config.label}</span>
    </Badge>
  );
}

type StatusStyle = { className: string; dotClass: string };

const NEUTRAL_STATUS: StatusStyle = {
  className: "border-border bg-muted text-foreground",
  dotClass: "bg-muted-foreground",
};

const STATUS_STYLES: Record<string, StatusStyle> = {
  open: {
    className: "border-primary/25 bg-primary/10 text-foreground",
    dotClass: "bg-primary",
  },
  resolved: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  suppressed: NEUTRAL_STATUS,
  exception: {
    className: "border-primary/25 bg-primary/10 text-foreground",
    dotClass: "bg-primary",
  },
  muted: {
    className: "border-tone-medium/25 bg-tone-medium/10 text-foreground",
    dotClass: "bg-tone-medium",
  },
  success: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  healthy: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  failed: {
    className: "border-tone-critical/25 bg-tone-critical/10 text-foreground",
    dotClass: "bg-tone-critical",
  },
  partial_failure: {
    className: "border-tone-high/25 bg-tone-high/10 text-foreground",
    dotClass: "bg-tone-high",
  },
  stale: {
    className: "border-tone-high/25 bg-tone-high/10 text-foreground",
    dotClass: "bg-tone-high",
  },
  never: NEUTRAL_STATUS,
  pending: NEUTRAL_STATUS,
  running: {
    className: "border-tone-info/25 bg-tone-info/10 text-foreground",
    dotClass: "bg-tone-info",
  },
  active: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  enabled: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  disabled: NEUTRAL_STATUS,
  deactivated: NEUTRAL_STATUS,
  configured: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  "not configured": NEUTRAL_STATUS,
  current: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  installed: {
    className: "border-tone-success/25 bg-tone-success/10 text-foreground",
    dotClass: "bg-tone-success",
  },
  available: NEUTRAL_STATUS,
  missing: {
    className: "border-tone-medium/25 bg-tone-medium/10 text-foreground",
    dotClass: "bg-tone-medium",
  },
};

export function StatusBadge({ status }: { status: string }) {
  const config = STATUS_STYLES[status] ?? NEUTRAL_STATUS;
  return (
    <Badge className={cn("capitalize", config.className)}>
      <span className={cn("size-1.5 rounded-full opacity-80", config.dotClass)} aria-hidden />
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

export { Badge, badgeVariants };
