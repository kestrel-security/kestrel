// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { AppPage } from "@/components/ui/app-page";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * Shown while a server component fetches. Without this, navigation appears to
 * do nothing until the data arrives -- the single most common "is it broken?"
 * moment in the product.
 */
export default function AppLoading() {
  return (
    <AppPage>
      <div className="mb-6 space-y-2">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96" />
      </div>
      <div className="space-y-3">
        <Skeleton className="h-10 w-full" />
        {Array.from({ length: 8 }).map((_, index) => (
          <Skeleton key={index} className="h-12 w-full" />
        ))}
      </div>
      <span className="sr-only" role="status">
        Loading…
      </span>
    </AppPage>
  );
}
