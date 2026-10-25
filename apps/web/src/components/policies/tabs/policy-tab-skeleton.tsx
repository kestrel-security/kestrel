// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { Skeleton } from "@/components/ui/skeleton";
import type { PolicyTab } from "@/lib/policy-tabs";

/**
 * Placeholder while a tab's data resolves.
 *
 * The header and tab strip stay painted above this, so switching tabs never
 * blanks the page — which is why the boundary lives around the tab body rather
 * than in a route-level `loading.tsx`.
 */
export function PolicyTabSkeleton({ tab }: { tab: PolicyTab }) {
  if (tab === "code") {
    return (
      <div className="space-y-3">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-[520px] w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-48 w-full" />
    </div>
  );
}
