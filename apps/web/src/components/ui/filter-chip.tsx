// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { X } from "lucide-react";

import { cn } from "@/lib/utils";

type FilterChipProps = {
  label: string;
  active?: boolean;
  onClick?: () => void;
  onRemove?: () => void;
  className?: string;
  count?: number;
  /** When set, renders as a Next.js Link (server-friendly filter rows). */
  href?: string;
};

export function FilterChip({
  label,
  active,
  onClick,
  onRemove,
  className,
  count,
  href,
}: FilterChipProps) {
  const classes = cn(
    "inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors duration-150",
    active
      ? "border-primary/40 bg-primary/15 text-foreground"
      : "border-transparent text-muted-foreground hover:border-border hover:bg-accent hover:text-foreground",
    className,
  );

  const body = (
    <>
      <span>{label}</span>
      {typeof count === "number" ? (
        <span className="rounded bg-muted px-1 font-mono text-[10px] text-muted-foreground">{count}</span>
      ) : null}
      {onRemove ? (
        <span
          role="button"
          tabIndex={0}
          aria-label={`Remove ${label}`}
          className="rounded p-0.5 hover:bg-muted"
          onClick={(e) => {
            e.stopPropagation();
            onRemove();
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              e.stopPropagation();
              onRemove();
            }
          }}
        >
          <X className="size-3" />
        </span>
      ) : null}
    </>
  );

  if (href) {
    return (
      <Link href={href} className={classes}>
        {body}
      </Link>
    );
  }

  return (
    <button type="button" onClick={onClick} className={classes}>
      {body}
    </button>
  );
}
