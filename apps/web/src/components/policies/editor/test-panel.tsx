// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Callout } from "@/components/ui/callout";
import type { PolicyFixtureTestResult } from "@/lib/types";

import { PanelEmpty, StaleNotice } from "./stale-notice";

export function TestPanel({
  result,
  stale,
  error,
  busy,
  canRun,
  onRerun,
}: {
  result: PolicyFixtureTestResult | null;
  stale: boolean;
  error?: string;
  busy: boolean;
  canRun: boolean;
  onRerun: () => void;
}) {
  return (
    <div className="space-y-3">
      {error ? <Callout tone="error">{error}</Callout> : null}
      {stale ? (
        <StaleNotice
          message="Source or fixtures changed since this ran."
          onRerun={onRerun}
          rerunLabel="Re-run test"
          busy={busy}
          disabled={!canRun}
        />
      ) : null}
      {!result ? (
        <PanelEmpty>
          Click <span className="font-medium text-foreground">Run fixture test</span> to evaluate the
          policy against the fixtures and compare matches to{" "}
          <code className="rounded bg-muted px-1 font-mono">expected_match_subject_ids</code>.
        </PanelEmpty>
      ) : result.passed ? (
        <Callout tone="success">Fixture test passed.</Callout>
      ) : (
        <Callout tone="warning">
          <p className="font-medium">Fixture test failed</p>
          <p className="mt-1 font-mono text-xs">
            Expected: {result.expected.join(", ") || "(none)"}
          </p>
          <p className="font-mono text-xs">Actual: {result.actual.join(", ") || "(none)"}</p>
        </Callout>
      )}
    </div>
  );
}
