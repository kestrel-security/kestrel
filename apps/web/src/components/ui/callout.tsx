// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, XCircle } from "lucide-react";

import { cn } from "@/lib/utils";

export type CalloutTone = "error" | "success" | "warning" | "info";

/**
 * Inline banner for action results and page-level notices.
 *
 * Uses muted tone tokens: tinted fill, neutral text, tone-colored icon.
 * Per the style guide, every tone carries an icon — never colour alone.
 */
const TONE_STYLES: Record<CalloutTone, string> = {
  error: "border-tone-critical/25 bg-tone-critical/10 text-foreground",
  success: "border-tone-success/25 bg-tone-success/10 text-foreground",
  warning: "border-tone-medium/25 bg-tone-medium/10 text-foreground",
  info: "border-border bg-muted/40 text-muted-foreground",
};

const TONE_ICON_CLASSES: Record<CalloutTone, string> = {
  error: "text-tone-critical",
  success: "text-tone-success",
  warning: "text-tone-medium",
  info: "text-muted-foreground",
};

const TONE_ICONS: Record<CalloutTone, typeof Info> = {
  error: XCircle,
  success: CheckCircle2,
  warning: AlertTriangle,
  info: Info,
};

export function Callout({
  tone = "info",
  children,
  className,
  icon,
  /** Override the implicit role (`alert` for error/warning, none otherwise). */
  role,
}: {
  tone?: CalloutTone;
  children: ReactNode;
  className?: string;
  /** Replace the default tone icon; pass `null` to drop it entirely. */
  icon?: ReactNode | null;
  role?: string;
}) {
  const Icon = TONE_ICONS[tone];
  const resolvedRole = role ?? (tone === "error" || tone === "warning" ? "alert" : undefined);

  return (
    <div
      role={resolvedRole}
      className={cn(
        "flex items-start gap-2 rounded-md border px-3 py-2 text-sm",
        TONE_STYLES[tone],
        className,
      )}
    >
      {icon === null ? null : (
        icon ?? <Icon className={cn("mt-0.5 size-4 shrink-0", TONE_ICON_CLASSES[tone])} aria-hidden />
      )}
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
