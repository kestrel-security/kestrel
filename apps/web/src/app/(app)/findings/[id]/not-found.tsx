// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import Link from "next/link";

import { EmptyState } from "@/components/ui/empty-state";

export default function FindingNotFound() {
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <EmptyState
        title="Finding not found"
        hint="It may have been auto-resolved and purged from this view, or the link is for another organization."
      />
      <p className="text-center text-sm">
        <Link href="/findings" className="text-primary underline">
          Back to Findings
        </Link>
      </p>
    </div>
  );
}
