// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, useTransition } from "react";
import type { editor as MonacoNs } from "monaco-editor";
import { CheckCircle2, FlaskConical, GitFork, Loader2, PlayCircle, Save } from "lucide-react";

import { DryRunPanel } from "@/components/policies/editor/dry-run-panel";
import { FixturesPanel } from "@/components/policies/editor/fixtures-panel";
import {
  FIXTURE_DEMOS,
  detectResourceType,
  fixtureDemoKey,
} from "@/components/policies/editor/fixture-demos";
import { ProblemsPanel } from "@/components/policies/editor/problems-panel";
import { ResizeHandle } from "@/components/policies/editor/resize-handle";
import { DrawerPanel, ResultsDrawer } from "@/components/policies/editor/results-drawer";
import { SourceEditor, type EditorMountHandler } from "@/components/policies/editor/source-editor";
import { TestPanel } from "@/components/policies/editor/test-panel";
import { useEditorHeight } from "@/components/policies/editor/use-editor-height";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import {
  captureFixturesFromMatches,
  createCustomPolicy,
  dryRunPolicyLive,
  publishPolicyVersion,
  savePolicyFixtures,
  testPolicyFixtures,
  validatePolicySource,
} from "@/lib/actions/policies";
import {
  drawerBadges,
  isStale,
  parseFixtures,
  runSlice,
  type DrawerTab,
  type RunSlice,
} from "@/lib/policy-editor-state";
import type {
  PolicyDryRunResult,
  PolicyFixtureTestResult,
  PolicyValidateResult,
} from "@/lib/types";
import { countOf } from "@/lib/plural";

type Mode = "create" | "edit";

/**
 * Which action is in flight. Replaces the single `pending` boolean so only the
 * clicked button spins — previously one dry-run disabled the whole toolbar.
 */
type Busy =
  | null
  | "validate"
  | "test"
  | "dryrun"
  | "save"
  | "saveFixtures"
  | "capture"
  | "fork";

export type PolicyEditorProps = {
  mode: Mode;
  policyId?: string | null;
  initialSource: string;
  /** Prefill fixtures JSON (pack or saved custom). Falls back to RESOURCE_TYPE demos. */
  initialFixtures?: string | null;
  /** Short label shown with the fixtures editor when pack/custom fixtures are loaded. */
  fixturesLabel?: string | null;
  /** Origin of loaded fixtures — enables Save for custom only. */
  fixturesSource?: "pack" | "custom" | "none" | null;
  editable: boolean;
  /** Bound server action; renders an inline fork CTA in the read-only explainer. */
  onFork?: (() => Promise<void>) | null;
  /** Drawer tab shown on first render. */
  initialDrawerTab?: DrawerTab;
  className?: string;
};

export function PolicyEditor({
  mode,
  policyId = null,
  initialSource,
  initialFixtures = null,
  fixturesLabel = null,
  fixturesSource = null,
  editable,
  onFork = null,
  initialDrawerTab = "fixtures",
  className,
}: PolicyEditorProps) {
  const router = useRouter();
  const [source, setSource] = useState(initialSource);
  const [fixtures, setFixtures] = useState(() => {
    if (initialFixtures && initialFixtures.trim()) {
      return initialFixtures;
    }
    const rt = fixtureDemoKey(detectResourceType(initialSource));
    return FIXTURE_DEMOS[rt] ?? FIXTURE_DEMOS.identity;
  });
  const [usingPrefillFixtures, setUsingPrefillFixtures] = useState(() =>
    Boolean(initialFixtures && initialFixtures.trim()),
  );
  const canSaveFixtures = editable && mode === "edit" && Boolean(policyId);

  // Each run keeps the inputs it was computed from, so the three panels coexist
  // and go *stale* instead of clearing one another.
  const [validation, setValidation] = useState<RunSlice<PolicyValidateResult> | null>(null);
  const [testResult, setTestResult] = useState<RunSlice<PolicyFixtureTestResult> | null>(null);
  const [dryRun, setDryRun] = useState<RunSlice<PolicyDryRunResult> | null>(null);

  const [tabErrors, setTabErrors] = useState<Partial<Record<DrawerTab, string>>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [, startTransition] = useTransition();

  const [activeTab, setActiveTab] = useState<DrawerTab>(initialDrawerTab);
  const [drawerCollapsed, setDrawerCollapsed] = useState(false);
  // The fixtures Monaco is mounted on first activation and never unmounted, so
  // in-progress edits survive tab switches.
  const [fixturesMounted, setFixturesMounted] = useState(initialDrawerTab === "fixtures");
  const fixturesEditorRef = useRef<MonacoNs.IStandaloneCodeEditor | null>(null);

  const { height, setHeight, resetHeight } = useEditorHeight();

  const detectedType = useMemo(() => detectResourceType(source), [source]);
  const fixturesParse = useMemo(() => parseFixtures(fixtures), [fixtures]);

  const validationStale = isStale(validation, source);
  const testStale = isStale(testResult, source, fixtures);
  const dryRunStale = isStale(dryRun, source);

  /** Publishing source you just watched fail compiles nothing but a broken version. */
  const blockedByValidation = Boolean(validation && !validationStale && !validation.data.valid);

  const sourceMarkers = useMemo(() => {
    if (!validation || validationStale || validation.data.valid) return [];
    return validation.data.errors.map((e) => ({
      message: e.message,
      line: e.line,
      column: e.column,
    }));
  }, [validation, validationStale]);

  const badges = useMemo(
    () =>
      drawerBadges({
        fixtures: fixturesParse,
        problems: validation
          ? { valid: validation.data.valid, errorCount: validation.data.errors.length }
          : null,
        test: testResult ? { passed: testResult.data.passed } : null,
        dryRun: dryRun ? { matchCount: dryRun.data.match_count } : null,
      }),
    [fixturesParse, validation, testResult, dryRun],
  );

  const openTab = useCallback((tab: DrawerTab) => {
    setActiveTab(tab);
    setDrawerCollapsed(false);
    if (tab === "fixtures") setFixturesMounted(true);
  }, []);

  const selectTab = useCallback(
    (tab: DrawerTab) => {
      // Clicking the open tab collapses the drawer; that's the fast "maximize".
      if (tab === activeTab && !drawerCollapsed) {
        setDrawerCollapsed(true);
        return;
      }
      openTab(tab);
    },
    [activeTab, drawerCollapsed, openTab],
  );

  // Monaco measures 0x0 while its panel is `display: none`; nudge it once the
  // fixtures panel is visible again or the layout height changes.
  useEffect(() => {
    if (activeTab !== "fixtures" || drawerCollapsed) return;
    const frame = requestAnimationFrame(() => fixturesEditorRef.current?.layout());
    return () => cancelAnimationFrame(frame);
  }, [activeTab, drawerCollapsed, height]);

  const setTabError = useCallback((tab: DrawerTab, message: string | undefined) => {
    setTabErrors((prev) => ({ ...prev, [tab]: message }));
  }, []);

  const run = useCallback(
    (kind: Exclude<Busy, null>, fn: () => Promise<void>) => {
      setBusy(kind);
      startTransition(async () => {
        try {
          await fn();
        } finally {
          setBusy(null);
        }
      });
    },
    [startTransition],
  );

  function loadFixtureDemo(resourceType: string) {
    const demo = FIXTURE_DEMOS[resourceType] ?? FIXTURE_DEMOS.identity;
    setFixtures(demo);
    setUsingPrefillFixtures(false);
    setTabError("fixtures", undefined);
  }

  const runValidate = useCallback(() => {
    const snapshot = source;
    setFormError(null);
    setSavedNote(null);
    setTabError("problems", undefined);
    openTab("problems");
    run("validate", async () => {
      const outcome = await validatePolicySource(snapshot);
      if (!outcome.ok) {
        setTabError("problems", outcome.error);
        return;
      }
      setValidation(runSlice(outcome.result, snapshot));
    });
  }, [source, openTab, run, setTabError]);

  const runTest = useCallback(() => {
    const snapshotSource = source;
    const snapshotFixtures = fixtures;
    setFormError(null);
    setSavedNote(null);
    setTabError("test", undefined);
    openTab("test");
    run("test", async () => {
      const outcome = await testPolicyFixtures(policyId, snapshotSource, snapshotFixtures);
      if (!outcome.ok) {
        setTabError("test", outcome.error);
        return;
      }
      setTestResult(runSlice(outcome.result, snapshotSource, snapshotFixtures));
    });
  }, [source, fixtures, policyId, openTab, run, setTabError]);

  const runDryRun = useCallback(() => {
    const snapshot = source;
    setFormError(null);
    setSavedNote(null);
    setTabError("dryrun", undefined);
    openTab("dryrun");
    run("dryrun", async () => {
      const outcome = await dryRunPolicyLive(policyId, snapshot);
      if (!outcome.ok) {
        setTabError("dryrun", outcome.error);
        return;
      }
      setDryRun(runSlice(outcome.result, snapshot));
    });
  }, [source, policyId, openTab, run, setTabError]);

  function runSaveFixtures() {
    if (!policyId || !canSaveFixtures) return;
    const snapshot = fixtures;
    setFormError(null);
    setSavedNote(null);
    setTabError("fixtures", undefined);
    run("saveFixtures", async () => {
      const outcome = await savePolicyFixtures(policyId, snapshot);
      if (!outcome.ok) {
        setTabError("fixtures", outcome.error);
        return;
      }
      setSavedNote(
        outcome.result.available
          ? `Saved fixtures (${outcome.result.fixtures?.rows?.length ?? 0} rows).`
          : "Cleared saved fixtures.",
      );
      router.refresh();
    });
  }

  function runCaptureFromDryRun() {
    const current = dryRun?.data;
    if (!current || current.matches.length === 0) return;
    const snapshot = source;
    setFormError(null);
    setSavedNote(null);
    setTabError("dryrun", undefined);
    const subjectIds = current.matches
      .map((m) => m.subject_id)
      .filter((id): id is string => Boolean(id));
    run("capture", async () => {
      const outcome = await captureFixturesFromMatches(policyId, snapshot, subjectIds, {
        persist: false,
        maxRows: 50,
      });
      if (!outcome.ok) {
        setTabError("dryrun", outcome.error);
        return;
      }
      setFixtures(JSON.stringify(outcome.result.fixtures, null, 2));
      setUsingPrefillFixtures(false);
      const note = outcome.result.truncated
        ? `Captured ${outcome.result.row_count} matching subjects as fixture (truncated at ${outcome.result.max_rows}).`
        : `Captured ${countOf(outcome.result.row_count, "matching subject")} as fixture.`;
      setSavedNote(canSaveFixtures ? `${note} Use Save fixtures to persist.` : note);
      openTab("fixtures");
    });
  }

  const runSave = useCallback(() => {
    if (!editable || blockedByValidation) return;
    const snapshot = source;
    setFormError(null);
    setSavedNote(null);
    run("save", async () => {
      if (mode === "create") {
        const outcome = await createCustomPolicy(snapshot);
        if (!outcome.ok) {
          setFormError(outcome.error);
          return;
        }
        router.push(`/policies/${outcome.id}`);
        router.refresh();
        return;
      }
      if (!policyId) return;
      const outcome = await publishPolicyVersion(policyId, snapshot);
      if (!outcome.ok) {
        setFormError(outcome.error);
        return;
      }
      // A new version genuinely obsoletes every result computed against the draft.
      setValidation(null);
      setTestResult(null);
      setDryRun(null);
      setTabErrors({});
      setSavedNote("Published a new version.");
      router.refresh();
    });
  }, [editable, blockedByValidation, source, mode, policyId, router, run]);

  function runFork() {
    if (!onFork) return;
    setFormError(null);
    setSavedNote(null);
    run("fork", async () => {
      await onFork();
    });
  }

  // Monaco commands capture their closure at mount time; route them through a
  // ref so the shortcuts always run the current handlers.
  const commandsRef = useRef({ save: runSave, test: runTest });
  useEffect(() => {
    commandsRef.current = { save: runSave, test: runTest };
  }, [runSave, runTest]);

  const bindShortcuts = useCallback<EditorMountHandler>((ed, monaco) => {
    ed.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => commandsRef.current.save());
    ed.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => commandsRef.current.test());
  }, []);

  const bindFixturesEditor = useCallback<EditorMountHandler>(
    (ed, monaco) => {
      fixturesEditorRef.current = ed;
      bindShortcuts(ed, monaco);
    },
    [bindShortcuts],
  );

  const saveLabel = mode === "create" ? "Create policy" : "Publish new version";
  const saveTitle = blockedByValidation
    ? "Validation failed for the current source — fix the problems in the Problems tab first."
    : `${saveLabel} (⌘/Ctrl+S)`;
  const testDisabledReason = fixturesParse.ok ? null : `Fixtures are not valid JSON — ${fixturesParse.message}`;

  const fixturesNote =
    usingPrefillFixtures || fixturesLabel
      ? `${
          fixturesLabel ||
          (fixturesSource === "custom"
            ? "Loaded saved custom fixtures."
            : "Loaded pack fixture file.")
        } Demo buttons replace this with a generic scaffold.`
      : null;

  return (
    <div className={className}>
      <div className="space-y-3">
        {formError && <Callout tone="error">{formError}</Callout>}
        {savedNote && <Callout tone="success">{savedNote}</Callout>}

        {/* Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border bg-muted/30 px-3 py-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-eyebrow">
              {editable ? (mode === "create" ? "Author" : "Edit") : "Source"}
            </span>
            <span
              className="inline-flex items-center rounded border border-border bg-elevated px-2 py-0.5 font-mono text-[11px] text-muted-foreground"
              title="Parsed from RESOURCE_TYPE in source"
            >
              RESOURCE_TYPE={detectedType}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={runValidate}
              disabled={busy === "validate"}
              title="Compile and check the source"
            >
              {busy === "validate" ? (
                <Loader2 className="animate-spin" aria-hidden />
              ) : (
                <CheckCircle2 aria-hidden />
              )}
              Validate
            </Button>
            <span title={testDisabledReason ?? "Run the fixture test (⌘/Ctrl+Enter)"}>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={runTest}
                disabled={busy === "test" || !fixturesParse.ok}
              >
                {busy === "test" ? (
                  <Loader2 className="animate-spin" aria-hidden />
                ) : (
                  <FlaskConical aria-hidden />
                )}
                Run fixture test
              </Button>
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={runDryRun}
              disabled={busy === "dryrun"}
              title="Preview matches against live inventory — nothing is persisted"
            >
              {busy === "dryrun" ? (
                <Loader2 className="animate-spin" aria-hidden />
              ) : (
                <PlayCircle aria-hidden />
              )}
              Dry-run on live inventory
            </Button>
            {editable && (
              <span title={saveTitle}>
                <Button
                  type="button"
                  size="sm"
                  onClick={runSave}
                  disabled={busy === "save" || blockedByValidation}
                >
                  {busy === "save" ? (
                    <Loader2 className="animate-spin" aria-hidden />
                  ) : (
                    <Save aria-hidden />
                  )}
                  {saveLabel}
                </Button>
              </span>
            )}
          </div>
        </div>

        {/* Full-width editor */}
        <SourceEditor
          id="policy-source"
          language="python"
          filename="policy.py"
          markerOwner="kestrel-policy"
          value={source}
          onChange={setSource}
          readOnly={!editable}
          height={height}
          markers={sourceMarkers}
          onEditorMount={bindShortcuts}
        />

        {!editable && (
          <Callout tone="info" className="text-xs">
            <p>
              Pack policies are file-owned — re-install the pack to update source. You can still
              enable/disable evaluation and run fixture tests.
            </p>
            {onFork ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="mt-2"
                onClick={runFork}
                disabled={busy === "fork"}
                title="Copy this policy into an editable custom policy"
              >
                {busy === "fork" ? (
                  <Loader2 className="animate-spin" aria-hidden />
                ) : (
                  <GitFork aria-hidden />
                )}
                Fork to custom
              </Button>
            ) : null}
          </Callout>
        )}

        <ResizeHandle height={height} onResize={setHeight} onReset={resetHeight} />

        <ResultsDrawer
          active={activeTab}
          onSelect={selectTab}
          badges={badges}
          collapsed={drawerCollapsed}
          onToggleCollapsed={() => setDrawerCollapsed((prev) => !prev)}
        >
          <DrawerPanel tab="fixtures" active={activeTab}>
            {fixturesMounted ? (
              <FixturesPanel
                value={fixtures}
                onChange={setFixtures}
                parse={fixturesParse}
                activeDemoKey={usingPrefillFixtures ? null : fixtureDemoKey(detectedType)}
                onLoadDemo={loadFixtureDemo}
                canSaveFixtures={canSaveFixtures}
                onSaveFixtures={runSaveFixtures}
                savingFixtures={busy === "saveFixtures"}
                error={tabErrors.fixtures}
                fixturesNote={fixturesNote}
                onEditorMount={bindFixturesEditor}
              />
            ) : null}
          </DrawerPanel>

          <DrawerPanel tab="problems" active={activeTab}>
            <ProblemsPanel
              result={validation?.data ?? null}
              stale={validationStale}
              error={tabErrors.problems}
              busy={busy === "validate"}
              onRerun={runValidate}
            />
          </DrawerPanel>

          <DrawerPanel tab="test" active={activeTab}>
            <TestPanel
              result={testResult?.data ?? null}
              stale={testStale}
              error={tabErrors.test}
              busy={busy === "test"}
              canRun={fixturesParse.ok}
              onRerun={runTest}
            />
          </DrawerPanel>

          <DrawerPanel tab="dryrun" active={activeTab}>
            <DryRunPanel
              result={dryRun?.data ?? null}
              stale={dryRunStale}
              error={tabErrors.dryrun}
              busy={busy === "dryrun"}
              capturing={busy === "capture"}
              onRerun={runDryRun}
              onCapture={runCaptureFromDryRun}
            />
          </DrawerPanel>
        </ResultsDrawer>
      </div>
    </div>
  );
}
