// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Loader2 } from "lucide-react";

import { Callout } from "@/components/ui/callout";
import type { FixturesParse } from "@/lib/policy-editor-state";

import { FIXTURE_DEMOS } from "./fixture-demos";
import { SourceEditor, type EditorMountHandler, type SourceMarker } from "./source-editor";

const FIXTURES_EDITOR_HEIGHT = 280;

export function FixturesPanel({
  value,
  onChange,
  parse,
  activeDemoKey,
  onLoadDemo,
  canSaveFixtures,
  onSaveFixtures,
  savingFixtures,
  error,
  fixturesNote,
  onEditorMount,
}: {
  value: string;
  onChange: (next: string) => void;
  parse: FixturesParse;
  /** Highlighted demo button, or null when prefilled fixtures are loaded. */
  activeDemoKey: string | null;
  onLoadDemo: (resourceType: string) => void;
  canSaveFixtures: boolean;
  onSaveFixtures: () => void;
  savingFixtures: boolean;
  error?: string;
  fixturesNote?: string | null;
  onEditorMount?: EditorMountHandler;
}) {
  const markers: SourceMarker[] =
    parse.ok || parse.line == null
      ? []
      : [{ message: parse.message, line: parse.line, column: parse.column }];

  return (
    <div className="space-y-2">
      {error ? <Callout tone="error">{error}</Callout> : null}
      <SourceEditor
        id="policy-fixtures"
        language="json"
        filename="fixtures.json"
        markerOwner="kestrel-fixtures"
        revealFirstMarker={false}
        value={value}
        onChange={onChange}
        height={FIXTURES_EDITOR_HEIGHT}
        markers={markers}
        onEditorMount={onEditorMount}
        headerRight={
          <div className="flex flex-wrap items-center gap-1">
            {Object.keys(FIXTURE_DEMOS).map((rt) => (
              <button
                key={rt}
                type="button"
                onClick={() => onLoadDemo(rt)}
                className={`rounded border px-2 py-0.5 font-mono text-[11px] transition-colors duration-150 ${
                  activeDemoKey === rt
                    ? "border-primary/40 bg-primary/15 text-foreground"
                    : "border-transparent text-muted-foreground hover:border-border hover:bg-background"
                }`}
              >
                {rt} demo
              </button>
            ))}
            {canSaveFixtures ? (
              <button
                type="button"
                onClick={onSaveFixtures}
                disabled={savingFixtures}
                className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-background disabled:opacity-50"
              >
                {savingFixtures ? <Loader2 className="size-3 animate-spin" aria-hidden /> : null}
                Save fixtures
              </button>
            ) : null}
          </div>
        }
      />
      {parse.ok ? null : (
        <Callout tone="error">
          <span className="font-mono text-xs">{parse.message}</span>
        </Callout>
      )}
      {fixturesNote ? <p className="text-xs text-muted-foreground">{fixturesNote}</p> : null}
      <p className="text-xs text-muted-foreground">
        Shape: <code className="rounded bg-muted px-1 font-mono">rows</code> +{" "}
        <code className="rounded bg-muted px-1 font-mono">expected_match_subject_ids</code>. Same
        format as <code className="rounded bg-muted px-1 font-mono">kestrel policy test</code>.
        {canSaveFixtures
          ? " Custom fixtures persist on this policy (not versioned with source)."
          : null}
      </p>
    </div>
  );
}
