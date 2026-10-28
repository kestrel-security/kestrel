// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, useTransition } from "react";
import { ChevronDown, Sparkles } from "lucide-react";

import { PolicyEditor } from "@/components/policies/policy-editor";
import { fetchPolicyGenerateCatalog, generatePolicyDraft } from "@/lib/actions/policies";
import {
  SCOPE_OPTIONS,
  describeIntentAnalysis,
  describeScope,
  scopeForRequest,
  summarizeAssessability,
} from "@/lib/policy-generate";
import type {
  ConnectorInstanceSummary,
  PolicyGenerateAssessability,
  PolicyGenerateCatalog,
  PolicyGenerateFixtureTest,
  PolicyGenerateIntentAnalysis,
  PolicyGenerateIntentChip,
  PolicyGenerateProbeTest,
  PolicyGenerateScope,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Card, CardContent } from "@/components/ui/card";

export function PolicyNewWorkbench({
  starterSource,
  connectors,
  initialCatalog,
}: {
  starterSource: string;
  connectors: ConnectorInstanceSummary[];
  initialCatalog: PolicyGenerateCatalog | null;
}) {
  const [editorSource, setEditorSource] = useState(starterSource);
  const [editorFixtures, setEditorFixtures] = useState<string | null>(null);
  const [editorKey, setEditorKey] = useState(0);
  const [intent, setIntent] = useState("");
  const [scope, setScope] = useState<PolicyGenerateScope>("single_app");
  const [resourceType, setResourceType] = useState("");
  const [applicationInstanceId, setApplicationInstanceId] = useState(
    () => connectors.find((c) => c.connector_name === "okta")?.application_instance_id ?? "",
  );
  const [includeFixtures, setIncludeFixtures] = useState(true);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [generateMeta, setGenerateMeta] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [fixtureTest, setFixtureTest] = useState<PolicyGenerateFixtureTest | null>(null);
  const [probeTest, setProbeTest] = useState<PolicyGenerateProbeTest | null>(null);
  const [analysis, setAnalysis] = useState<PolicyGenerateIntentAnalysis | null>(null);
  const [assessability, setAssessability] = useState<PolicyGenerateAssessability[] | null>(null);
  const [scopeErrors, setScopeErrors] = useState<string[]>([]);
  const [loadedFixtures, setLoadedFixtures] = useState(false);
  const [hasGenerated, setHasGenerated] = useState(false);
  const [catalog, setCatalog] = useState<PolicyGenerateCatalog | null>(initialCatalog);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const selectedConnector = connectors.find((c) => c.application_instance_id === applicationInstanceId);
  const connectorHint = selectedConnector?.connector_name ?? undefined;

  const loadCatalog = useCallback(
    async (appInstanceId: string, nextScope: PolicyGenerateScope) => {
      setCatalogError(null);
      const outcome = await fetchPolicyGenerateCatalog({
        application_instance_id: appInstanceId || undefined,
        connector_hint: appInstanceId ? undefined : connectorHint,
        scope: nextScope,
      });
      if (!outcome.ok) {
        setCatalogError(outcome.error);
        setCatalog(null);
        return;
      }
      setCatalog(outcome.catalog);
    },
    [connectorHint],
  );

  useEffect(() => {
    if (applicationInstanceId || scope === "cross_app") {
      void loadCatalog(applicationInstanceId, scope);
    }
  }, [applicationInstanceId, scope, loadCatalog]);

  function applyIntentChip(chip: PolicyGenerateIntentChip) {
    setIntent(chip.intent);
    if (chip.resource_type) setResourceType(chip.resource_type);
    if (chip.scope) setScope(chip.scope);
    const match = connectors.find((c) => c.connector_name === chip.connector_hint);
    if (match) setApplicationInstanceId(match.application_instance_id);
  }

  function onGenerate() {
    setGenerateError(null);
    setGenerateMeta(null);
    setValidationErrors([]);
    setFixtureTest(null);
    setProbeTest(null);
    setAnalysis(null);
    setAssessability(null);
    setScopeErrors([]);
    setLoadedFixtures(false);
    const request = scopeForRequest(scope, connectorHint);
    startTransition(async () => {
      const outcome = await generatePolicyDraft({
        intent,
        resource_type: resourceType.trim() || undefined,
        connector_hint: request.connector_hint,
        application_instance_id: applicationInstanceId || undefined,
        include_fixtures: includeFixtures,
        scope: request.scope,
      });
      if (!outcome.ok) {
        setGenerateError(outcome.error);
        return;
      }
      const { result } = outcome;
      setAnalysis(result.intent_analysis ?? null);
      setAssessability(result.assessability ?? null);
      setScopeErrors(result.scope_errors ?? []);

      if (result.provider === "unconfigured") {
        setGenerateMeta(result.message ?? "Configure Settings → AI to generate novel policies.");
        setGenerateError(null);
        return;
      }
      if (result.provider === "error") {
        setGenerateError(result.message ?? result.error ?? "AI generation failed.");
        return;
      }

      // Fixtures ride along with the source in a single remount, so the draft
      // and its test data land together instead of behind a second click.
      const fixturesJson = result.fixtures ? JSON.stringify(result.fixtures, null, 2) : null;

      if (result.source_text) {
        setEditorSource(result.source_text);
        setEditorFixtures(fixturesJson);
        setEditorKey((k) => k + 1);
        setHasGenerated(true);
      }

      const validation = result.validation;
      if (validation && !validation.valid) {
        setValidationErrors(validation.errors?.length ? validation.errors : ["Draft failed RestrictedPython validation."]);
      } else {
        setValidationErrors([]);
      }

      setLoadedFixtures(Boolean(fixturesJson));

      if (result.fixture_test) {
        setFixtureTest(result.fixture_test);
      }
      setProbeTest(result.probe_test ?? null);

      const slugNote = validation?.slug ? ` slug=${validation.slug}` : "";
      const repairNote = result.repair_turns ? ` ${result.repair_turns} repair turn${result.repair_turns === 1 ? "" : "s"}.` : "";
      if (result.provider === "template") {
        setGenerateMeta(`Matched intent template (offline).${slugNote} Review, validate, and test before creating.`);
      } else {
        setGenerateMeta(
          `Draft from ${result.provider} (${result.model}).${slugNote}${repairNote} Validate and dry-run before creating.`,
        );
      }
    });
  }

  const connectorFields = connectorHint ? catalog?.fields?.connectors?.[connectorHint] : undefined;
  const crossAppFields = catalog?.fields?.cross_app;
  const resourceTypeOptions = catalog?.fields?.resource_types ?? [
    "identity",
    "grant",
    "tenant_setting",
    "event",
    "resource",
    "application",
    "oauth_application",
  ];
  const assessabilityNote = summarizeAssessability(assessability);

  return (
    <div className="space-y-6">
      {/* Collapses once a draft exists so the editor becomes the primary surface. */}
      <Card className="border-primary/20">
        <details open={!hasGenerated}>
          <summary className="cursor-pointer list-none border-b border-border px-4 py-3 [&::-webkit-details-marker]:hidden">
            <span className="flex items-center gap-1.5 text-sm font-semibold leading-none tracking-tight">
              <Sparkles className="size-4 text-primary" aria-hidden />
              Generate with AI
              <ChevronDown
                className="ml-auto size-4 text-muted-foreground transition-transform"
                aria-hidden
              />
            </span>
            <span className="mt-1 block text-xs text-muted-foreground">
              Describe the configuration you want to flag, in one app or across all of them. Known Okta and
              cross-app intents work offline via templates; novel intents need{" "}
              <Link href="/settings/ai" className="underline hover:text-foreground">
                Settings → AI
              </Link>
              . Drafts land in the editor below for review — they are never auto-enabled or
              auto-applied.
            </span>
          </summary>
        <CardContent className="space-y-3">

          {catalog?.intent_chips?.length ? (
            <div className="flex flex-wrap gap-2">
              {catalog.intent_chips.map((chip) => (
                <button
                  key={chip.label}
                  type="button"
                  onClick={() => applyIntentChip(chip)}
                  className="rounded-full border border-border bg-muted/40 px-3 py-1 text-xs hover:bg-muted"
                >
                  {chip.label}
                </button>
              ))}
            </div>
          ) : null}

          <label className="flex flex-col gap-1 text-sm">
            <span className="font-medium">Intent</span>
            <textarea
              value={intent}
              onChange={(e) => setIntent(e.target.value)}
              rows={4}
              placeholder="e.g. Flag Okta administrator without MFA enabled"
              className="rounded-md border border-border bg-background px-2 py-1.5 font-sans text-sm"
            />
          </label>

          <fieldset className="flex flex-wrap gap-3 text-sm">
            <legend className="sr-only">Scope</legend>
            {SCOPE_OPTIONS.map((option) => (
              <label
                key={option.value}
                className={`flex flex-1 min-w-[12rem] cursor-pointer items-start gap-2 rounded-md border px-3 py-2 ${
                  scope === option.value ? "border-primary/50 bg-primary/5" : "border-border"
                }`}
              >
                <input
                  type="radio"
                  name="policy-generate-scope"
                  value={option.value}
                  checked={scope === option.value}
                  onChange={() => setScope(option.value)}
                  className="mt-0.5"
                />
                <span className="flex flex-col">
                  <span className="font-medium">{option.label}</span>
                  <span className="text-xs text-muted-foreground">{option.hint}</span>
                </span>
              </label>
            ))}
          </fieldset>

          <div className="flex flex-wrap gap-3">
            <label className="flex min-w-[10rem] flex-1 flex-col gap-1 text-sm">
              <span className="text-muted-foreground">
                {scope === "cross_app" ? "Focus app (optional, usually the identity provider)" : "Connected app"}
              </span>
              <select
                value={applicationInstanceId}
                onChange={(e) => setApplicationInstanceId(e.target.value)}
                className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              >
                <option value="">(none)</option>
                {connectors.map((c) => (
                  <option key={c.id} value={c.application_instance_id}>
                    {c.application_display_name || c.connector_display_name || c.connector_name}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex min-w-[10rem] flex-1 flex-col gap-1 text-sm">
              <span className="text-muted-foreground">Resource type (optional)</span>
              <select
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
                className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              >
                <option value="">(auto)</option>
                {resourceTypeOptions.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {scope === "cross_app" && crossAppFields ? (
            <details className="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm">
              <summary className="cursor-pointer font-medium">Cross-app fields and helpers</summary>
              <div className="mt-2 space-y-2 text-xs text-muted-foreground">
                <p>
                  <span className="font-medium text-foreground">Cluster:</span>{" "}
                  {crossAppFields.cluster_fields.join(", ")}
                </p>
                <p>
                  <span className="font-medium text-foreground">Worker types:</span>{" "}
                  {crossAppFields.worker_types.join(", ")} (unknown is a real value)
                </p>
                <p>
                  <span className="font-medium text-foreground">Trusted activity sources:</span>{" "}
                  {crossAppFields.trusted_activity_sources.join(", ")} (profile is not activity)
                </p>
                <p>
                  <span className="font-medium text-foreground">Helpers:</span>{" "}
                  {crossAppFields.helpers.join(", ")}
                </p>
                <p>
                  <span className="font-medium text-foreground">Capabilities (REQUIRES):</span>{" "}
                  {Object.keys(crossAppFields.capabilities).join(", ")}
                </p>
              </div>
            </details>
          ) : null}

          {connectorFields ? (
            <details className="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm">
              <summary className="cursor-pointer font-medium">
                Available {connectorFields.connector} fields (from {connectorFields.policy_count} shipped policies)
              </summary>
              <div className="mt-2 space-y-2 text-xs text-muted-foreground">
                {connectorFields.identity_fields.length ? (
                  <p>
                    <span className="font-medium text-foreground">Identity:</span>{" "}
                    {connectorFields.identity_fields.join(", ")}
                  </p>
                ) : null}
                {connectorFields.privileged_roles.length ? (
                  <p>
                    <span className="font-medium text-foreground">Privileged roles:</span>{" "}
                    {connectorFields.privileged_roles.join(", ")}
                  </p>
                ) : null}
                {connectorFields.tenant_setting_keys.length ? (
                  <p>
                    <span className="font-medium text-foreground">Tenant settings:</span>{" "}
                    {connectorFields.tenant_setting_keys.join(", ")}
                  </p>
                ) : null}
                {connectorFields.event_actions.length ? (
                  <p>
                    <span className="font-medium text-foreground">Event actions:</span>{" "}
                    {connectorFields.event_actions.join(", ")}
                  </p>
                ) : null}
                {catalog?.samples?.length ? (
                  <div>
                    <p className="font-medium text-foreground">Live samples (redacted)</p>
                    <pre className="mt-1 max-h-40 overflow-auto rounded bg-background p-2 text-[11px]">
                      {JSON.stringify(catalog.samples, null, 2)}
                    </pre>
                  </div>
                ) : null}
              </div>
            </details>
          ) : null}

          {catalogError ? <p className="text-xs text-red-600 dark:text-red-400">{catalogError}</p> : null}

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={includeFixtures}
              onChange={(e) => setIncludeFixtures(e.target.checked)}
              className="rounded border-border"
            />
            <span>Include connector-aligned fixture scaffold (match + non-match)</span>
          </label>
          <Button type="button" variant="outline" size="sm" disabled={pending || !intent.trim()} onClick={onGenerate}>
            <Sparkles aria-hidden />
            {pending ? "Generating…" : "Generate draft"}
          </Button>
          {generateError ? <Callout tone="error">{generateError}</Callout> : null}
          {generateMeta ? <p className="text-xs text-muted-foreground">{generateMeta}</p> : null}
          {analysis ? (
            <Callout tone="info">
              <p className="font-medium">Intent analysis: {describeScope(analysis)}</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs">
                {describeIntentAnalysis(analysis).map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              {assessabilityNote ? <p className="mt-1 text-xs">{assessabilityNote}</p> : null}
            </Callout>
          ) : null}
          {scopeErrors.length > 0 ? (
            <Callout tone="warning">
              <p className="font-medium">Scope</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs">
                {scopeErrors.map((err) => (
                  <li key={err}>{err}</li>
                ))}
              </ul>
            </Callout>
          ) : null}
          {fixtureTest ? (
            <Callout tone={fixtureTest.passed ? "success" : fixtureTest.advisory ? "info" : "warning"}>
              <p className="font-medium">
                Fixture test: {fixtureTest.passed ? "passed" : "failed"}
                {fixtureTest.advisory ? " (generic scaffold)" : ""}
              </p>
              {!fixtureTest.passed ? (
                <p className="mt-1 font-mono text-xs">
                  expected {JSON.stringify(fixtureTest.expected)} · actual{" "}
                  {JSON.stringify(fixtureTest.actual)}
                </p>
              ) : null}
              {!fixtureTest.passed && fixtureTest.advisory ? (
                <p className="mt-1 text-xs">
                  These sample rows were not written for this intent. Edit the expected matches before relying on the
                  result.
                </p>
              ) : null}
            </Callout>
          ) : null}
          {probeTest && !probeTest.passed ? (
            <Callout tone="warning">
              <p className="font-medium">Edge-case rows: failed</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 font-mono text-xs">
                {probeTest.errors.map((err) => (
                  <li key={err}>{err}</li>
                ))}
              </ul>
            </Callout>
          ) : null}
          {validationErrors.length > 0 ? (
            <Callout tone="error">
              <p className="font-medium">Validation errors</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 font-mono text-xs">
                {validationErrors.map((err) => (
                  <li key={err}>{err}</li>
                ))}
              </ul>
            </Callout>
          ) : null}
          {loadedFixtures ? (
            <Callout tone="info">
              Fixture scaffold loaded into the editor&apos;s Fixtures panel (not persisted).
            </Callout>
          ) : null}
        </CardContent>
        </details>
      </Card>

      <PolicyEditor
        key={editorKey}
        mode="create"
        initialSource={editorSource}
        initialFixtures={editorFixtures}
        fixturesLabel={editorFixtures ? "Loaded from AI fixture scaffold (not persisted)." : null}
        initialDrawerTab={editorFixtures ? "fixtures" : undefined}
        editable
      />
    </div>
  );
}
