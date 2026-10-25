// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { Skeleton } from "@/components/ui/skeleton";

/** Explore is full-bleed, so its skeleton is the canvas, not a table. */
export default function ExploreLoading() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-9 w-full max-w-xl" />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <Skeleton className="h-[28rem] w-full" />
        <Skeleton className="h-[28rem] w-full" />
      </div>
      <span className="sr-only" role="status">
        Loading the identity graph…
      </span>
    </div>
  );
}
