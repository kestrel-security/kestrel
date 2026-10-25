// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

/** Shared “Load more” control for cursor-paginated list pages. */
export function LoadMoreButton({
  pending,
  error,
  onClick,
}: {
  pending: boolean;
  error: string | null;
  onClick: () => void;
}) {
  return (
    <div className="flex flex-col items-center gap-2 pt-1">
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      <button
        type="button"
        disabled={pending}
        onClick={onClick}
        className="h-8 rounded-md border border-border bg-secondary px-4 text-xs font-medium text-secondary-foreground transition-colors duration-150 hover:bg-accent disabled:pointer-events-none disabled:opacity-50"
      >
        {pending ? "Loading…" : "Load more"}
      </button>
    </div>
  );
}
