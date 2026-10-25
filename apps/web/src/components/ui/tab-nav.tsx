// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { cn } from "@/lib/utils";

export type TabNavItem = {
  href: string;
  label: string;
  active: boolean;
  /** Optional count pill, e.g. open findings on a Findings tab. */
  count?: number;
};

/**
 * Underline tab strip built from links, for URL-driven section navigation.
 *
 * These are navigations, not local state, so they render as `<Link>` with
 * `aria-current="page"` rather than `role="tab"` — which also keeps the host
 * page a Server Component. The Radix pill `ui/tabs.tsx` is client-only and stays
 * reserved for genuine in-page tab state.
 *
 * Visual treatment matches the revamped Dashboard's board tabs.
 */
export function TabNav({
  items,
  ariaLabel,
  className,
}: {
  items: TabNavItem[];
  ariaLabel: string;
  className?: string;
}) {
  return (
    <nav
      aria-label={ariaLabel}
      className={cn("flex flex-wrap items-center gap-1 border-b border-border pb-px", className)}
    >
      {items.map((item) => (
        <Link
          key={item.href}
          href={item.href}
          aria-current={item.active ? "page" : undefined}
          className={cn(
            "-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium transition-colors duration-150",
            item.active
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground",
          )}
        >
          {item.label}
          {typeof item.count === "number" && item.count > 0 ? (
            <span className="rounded bg-muted px-1 font-mono text-[10px] text-muted-foreground">
              {item.count}
            </span>
          ) : null}
        </Link>
      ))}
    </nav>
  );
}
