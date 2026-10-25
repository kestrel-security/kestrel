// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { AppPage } from "@/components/ui/app-page";
import { Skeleton } from "@/components/ui/skeleton";

export default function FindingDetailLoading() {
  return (
    <AppPage>
      <div className="mb-6 space-y-2">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-8 w-2/3" />
      </div>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,22rem)]">
        <div className="space-y-4">
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
        <div className="space-y-4">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-48 w-full" />
        </div>
      </div>
      <span className="sr-only" role="status">
        Loading finding…
      </span>
    </AppPage>
  );
}
