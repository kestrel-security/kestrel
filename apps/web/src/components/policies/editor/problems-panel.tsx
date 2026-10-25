// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { CheckCircle2 } from "lucide-react";

import { Callout } from "@/components/ui/callout";
import type { PolicyValidateError, PolicyValidateResult } from "@/lib/types";

import { PanelEmpty, StaleNotice } from "./stale-notice";
import { countOf } from "@/lib/plural";

export function formatValidateError(err: PolicyValidateError): string {
  if (err.line != null && err.column != null) {
    return `line ${err.line}, col ${err.column}: ${err.message}`;
  }
  if (err.line != null) {
    return `line ${err.line}: ${err.message}`;
  }
  return err.message;
}

export function ProblemsPanel({
  result,
  stale,
  error,
  busy,
  onRerun,
}: {
  result: PolicyValidateResult | null;
  stale: boolean;
  error?: string;
  busy: boolean;
  onRerun: () => void;
}) {
  return (
    <div className="space-y-3">
      {error ? <Callout tone="error">{error}</Callout> : null}
      {stale ? (
        <StaleNotice onRerun={onRerun} rerunLabel="Re-validate" busy={busy} />
      ) : null}
      {!result ? (
        <PanelEmpty>
          Click <span className="font-medium text-foreground">Validate</span> to compile the source and
          list syntax, metadata, and RestrictedPython problems here.
        </PanelEmpty>
      ) : result.valid ? (
        <Callout tone="success" icon={<CheckCircle2 className="mt-0.5 size-4 shrink-0" aria-hidden />}>
          Valid — slug <code className="font-mono">{result.slug}</code>
          {result.severity ? ` · severity ${result.severity}` : ""}
        </Callout>
      ) : (
        <Callout tone="error">
          <p className="font-medium">
            Validation failed — {countOf(result.errors.length, "problem")}
          </p>
          <ul className="mt-1 list-disc space-y-1 pl-4 font-mono text-xs">
            {result.errors.map((e) => {
              const text = formatValidateError(e);
              return <li key={text}>{text}</li>;
            })}
          </ul>
        </Callout>
      )}
    </div>
  );
}
