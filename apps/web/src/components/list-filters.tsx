// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

/** Compact GET search form that preserves other query params as hidden fields. */
export function ListSearchForm({
  action,
  defaultValue,
  placeholder,
  preserve,
  name = "search",
}: {
  action: string;
  defaultValue?: string;
  placeholder: string;
  /** Other query params to keep when submitting search. */
  preserve?: Record<string, string | undefined>;
  /** Query param name for the search input (default `search`). */
  name?: string;
}) {
  return (
    <form method="GET" action={action} className="flex flex-wrap items-center gap-2">
      {preserve &&
        Object.entries(preserve).map(([key, value]) =>
          value ? <input key={key} type="hidden" name={key} value={value} /> : null,
        )}
      <input
        type="search"
        name={name}
        defaultValue={defaultValue ?? ""}
        placeholder={placeholder}
        aria-label={placeholder}
        className="h-9 min-w-[16rem] flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm outline-none placeholder:text-muted-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
      />
      <button
        type="submit"
        className="h-9 rounded-md border border-border bg-secondary px-3 text-sm font-medium text-secondary-foreground transition-colors duration-150 hover:bg-accent"
      >
        Search
      </button>
      {defaultValue ? (
        <Link href={action} className="text-sm text-muted-foreground transition-colors hover:text-foreground hover:underline">
          Clear
        </Link>
      ) : null}
    </form>
  );
}

/**
 * @deprecated Prefer `FilterChip` from `@/components/ui/filter-chip` for new
 * code (it supports counts and inactive-state remove). Kept for existing
 * simple href-toggle usages; restyled to match the same visual language.
 */
export function FilterChip({
  href,
  active,
  children,
}: {
  href: string;
  active: boolean;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      className={`inline-flex h-7 items-center rounded-md border px-2.5 text-xs font-medium transition-colors duration-150 ${
        active
          ? "border-primary/40 bg-primary/15 text-foreground"
          : "border-transparent text-muted-foreground hover:border-border hover:bg-accent hover:text-foreground"
      }`}
    >
      {children}
    </Link>
  );
}
