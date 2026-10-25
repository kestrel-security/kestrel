// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

type EmptyStateProps = {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
  className?: string;
  showMark?: boolean;
};

export function EmptyState({ title, hint, action, className, showMark = true }: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-lg border border-dashed border-border bg-card/40 px-6 py-14 text-center",
        className,
      )}
    >
      {showMark ? (
        <div className="mb-4 flex size-12 items-center justify-center rounded-xl border border-border bg-background">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/brand/kestrel-mark-color.svg" alt="" aria-hidden className="size-7 object-contain" />
        </div>
      ) : null}
      <p className="text-sm font-medium">{title}</p>
      {hint ? <p className="mt-1 max-w-sm text-sm text-muted-foreground">{hint}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
