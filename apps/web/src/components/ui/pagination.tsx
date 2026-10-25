// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";
import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Numbered pages for an in-memory list. Server Component: every page and
 * page-size choice is a link, so the state lives in the URL and is shareable.
 *
 * Shows a window of page numbers (first, last, and two either side of the
 * current page) with ellipses between gaps, so a 40-page list stays one row.
 */
export function Pagination({
  page,
  pageCount,
  per,
  perOptions,
  start,
  end,
  total,
  noun,
  hrefForPage,
  hrefForPer,
  className,
}: {
  page: number;
  pageCount: number;
  per: number;
  perOptions: readonly number[];
  start: number;
  end: number;
  total: number;
  /** Plural noun for the count line, e.g. "policies". */
  noun: string;
  hrefForPage: (page: number) => string;
  hrefForPer: (per: number) => string;
  className?: string;
}) {
  const smallest = Math.min(...perOptions);
  // Nothing to page and nothing to change: stay out of the way.
  if (total <= smallest && per === smallest) return null;

  return (
    <nav
      aria-label="Pagination"
      className={cn("flex flex-wrap items-center justify-between gap-3 text-sm", className)}
    >
      <p className="text-muted-foreground tabular-nums">
        {total === 0 ? `No ${noun}` : `Showing ${start}–${end} of ${total} ${noun}`}
      </p>

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-1" role="group" aria-label="Rows per page">
          <span className="text-xs text-muted-foreground">Per page</span>
          {perOptions.map((option) =>
            option === per ? (
              <span
                key={option}
                aria-current="true"
                className="rounded-md bg-secondary px-2 py-1 text-xs font-medium text-secondary-foreground tabular-nums"
              >
                {option}
              </span>
            ) : (
              <Link
                key={option}
                href={hrefForPer(option)}
                className="rounded-md px-2 py-1 text-xs text-muted-foreground tabular-nums transition-colors hover:bg-accent hover:text-foreground"
              >
                {option}
              </Link>
            ),
          )}
        </div>

        {pageCount > 1 ? (
          <div className="flex items-center gap-1">
            <PageStep href={page > 1 ? hrefForPage(page - 1) : null} label="Previous page">
              <ChevronLeft aria-hidden />
            </PageStep>
            {pageWindow(page, pageCount).map((item, index) =>
              item === "gap" ? (
                <span key={`gap-${index}`} className="px-1 text-muted-foreground" aria-hidden>
                  …
                </span>
              ) : item === page ? (
                <span
                  key={item}
                  aria-current="page"
                  className="inline-flex h-8 min-w-8 items-center justify-center rounded-md bg-secondary px-2 text-xs font-medium text-secondary-foreground tabular-nums"
                >
                  {item}
                </span>
              ) : (
                <Link
                  key={item}
                  href={hrefForPage(item)}
                  aria-label={`Page ${item}`}
                  className="inline-flex h-8 min-w-8 items-center justify-center rounded-md px-2 text-xs text-muted-foreground tabular-nums transition-colors hover:bg-accent hover:text-foreground"
                >
                  {item}
                </Link>
              ),
            )}
            <PageStep href={page < pageCount ? hrefForPage(page + 1) : null} label="Next page">
              <ChevronRight aria-hidden />
            </PageStep>
          </div>
        ) : null}
      </div>
    </nav>
  );
}

function PageStep({
  href,
  label,
  children,
}: {
  href: string | null;
  label: string;
  children: React.ReactNode;
}) {
  if (!href) {
    return (
      <Button type="button" variant="ghost" size="icon" className="size-8" disabled aria-label={label}>
        {children}
      </Button>
    );
  }
  return (
    <Button asChild variant="ghost" size="icon" className="size-8">
      <Link href={href} aria-label={label}>
        {children}
      </Link>
    </Button>
  );
}

/** Page numbers to show: first, last, current ±2, with "gap" where numbers are skipped. */
export function pageWindow(page: number, pageCount: number): (number | "gap")[] {
  if (pageCount <= 7) return Array.from({ length: pageCount }, (_, i) => i + 1);
  const keep = new Set<number>([1, pageCount]);
  for (let p = page - 2; p <= page + 2; p += 1) {
    if (p >= 1 && p <= pageCount) keep.add(p);
  }
  const pages = [...keep].sort((a, b) => a - b);
  const out: (number | "gap")[] = [];
  pages.forEach((p, i) => {
    if (i > 0 && p - pages[i - 1] > 1) out.push("gap");
    out.push(p);
  });
  return out;
}
