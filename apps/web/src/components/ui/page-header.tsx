// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

type PageHeaderProps = {
  title: string;
  description?: ReactNode;
  /** Small uppercase label above the title, e.g. a breadcrumb parent ("Policies") or category. */
  eyebrow?: string;
  /** A status/badge rendered inline next to the title (e.g. connector health, finding severity). */
  status?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
};

export function PageHeader({
  title,
  description,
  eyebrow,
  status,
  actions,
  children,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn("mb-6 space-y-4", className)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1">
          {eyebrow ? <p className="text-eyebrow">{eyebrow}</p> : null}
          <div className="flex min-w-0 items-center gap-2.5">
            <h1 className="truncate text-2xl font-semibold tracking-tight">{title}</h1>
            {status}
          </div>
          {description ? <p className="max-w-2xl text-sm text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </div>
  );
}
