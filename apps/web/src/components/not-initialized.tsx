// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { EmptyState } from "@/components/ui/empty-state";

export function NotInitialized() {
  return (
    <EmptyState
      title="Kestrel hasn't been initialized yet"
      hint={
        <>
          Run{" "}
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">
            kestrel init --seed
          </code>{" "}
          to create an organization and load demo data.
        </>
      }
    />
  );
}
