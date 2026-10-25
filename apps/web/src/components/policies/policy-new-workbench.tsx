// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, useTransition } from "react";
import { ChevronDown, Sparkles } from "lucide-react";

import { PolicyEditor } from "@/components/policies/policy-editor";
import { fetchPolicyGenerateCatalog, generatePolicyDraft } from "@/lib/actions/policies";
import type {
  ConnectorInstanceSummary,
  PolicyGenerateCatalog,
  PolicyGenerateFixtureTest,
  PolicyGenerateIntentChip,
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
  const [resourceType, setResourceType] = useState("");
  const [applicationInstanceId, setApplicationInstanceId] = useState(
    () => connectors.find((c) => c.connector_name === "okta")?.application_instance_id ?? "",
  );
  const [includeFixtures, setIncludeFixtures] = useState(true);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [generateMeta, setGenerateMeta] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<string[]>([]);
  const [fixtureTest, setFixtureTest] = useState<PolicyGenerateFixtureTest | null>(null);
  const [loadedFixtures, setLoadedFixtures] = useState(false);
  const [hasGenerated, setHasGenerated] = useState(false);
  const [catalog, setCatalog] = useState<PolicyGenerateCatalog | null>(initialCatalog);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const selectedConnector = connectors.find((c) => c.application_instance_id === applicationInstanceId);
  const connectorHint = selectedConnector?.connector_name ?? undefined;

  const loadCatalog = useCallback(async (appInstanceId: string) => {
    setCatalogError(null);
    const outcome = await fetchPolicyGenerateCatalog({
      application_instance_id: appInstanceId || undefined,
      connector_hint: appInstanceId ? undefined : connectorHint,
    });
    if (!outcome.ok) {
      setCatalogError(outcome.error);
      setCatalog(null);
      return;
    }
    setCatalog(outcome.catalog);
  }, [connectorHint]);

  useEffect(() => {
    if (applicationInstanceId) {
      void loadCatalog(applicationInstanceId);
    }
  }, [applicationInstanceId, loadCatalog]);

  function applyIntentChip(chip: PolicyGenerateIntentChip) {
    setIntent(chip.intent);
    if (chip.resource_type) setResourceType(chip.resource_type);
    const match = connectors.find((c) => c.connector_name === chip.connector_hint);
    if (match) setApplicationInstanceId(match.application_instance_id);
  }

  function onGenerate() {
    setGenerateError(null);
    setGenerateMeta(null);
    setValidationErrors([]);
    setFixtureTest(null);
    setLoadedFixtures(false);
    startTransition(async () => {
      const outcome = await generatePolicyDraft({
        intent,
        resource_type: resourceType.trim() || undefined,
        connector_hint: connectorHint,
        application_instance_id: applicationInstanceId || undefined,
        include_fixtures: includeFixtures,
      });
      if (!outcome.ok) {
        setGenerateError(outcome.error);
        return;
      }
      const { result } = outcome;

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

      const slugNote = validation?.slug ? ` slug=${validation.slug}` : "";
      if (result.provider === "template") {
        setGenerateMeta(`Matched intent template (offline).${slugNote} Review, validate, and test before creating.`);
      } else {
        setGenerateMeta(`Draft from ${result.provider} (${result.model}).${slugNote} Validate and dry-run before creating.`);
      }
    });
  }

  const oktaFields = catalog?.fields?.okta;

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
              Describe what you want to detect. Known Okta posture intents work offline via
              templates; novel intents need{" "}
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
              placeholder="e.g. Detect Okta administrator without MFA enabled"
              className="rounded-md border border-border bg-background px-2 py-1.5 font-sans text-sm"
            />
          </label>

          <div className="flex flex-wrap gap-3">
            <label className="flex min-w-[10rem] flex-1 flex-col gap-1 text-sm">
              <span className="text-muted-foreground">Connected app</span>
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
                <option value="identity">identity</option>
                <option value="grant">grant</option>
                <option value="tenant_setting">tenant_setting</option>
                <option value="event">event</option>
                <option value="application">application</option>
              </select>
            </label>
          </div>

          {oktaFields ? (
            <details className="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm">
              <summary className="cursor-pointer font-medium">Available Okta fields</summary>
              <div className="mt-2 space-y-2 text-xs text-muted-foreground">
                <p>
                  <span className="font-medium text-foreground">Identity:</span>{" "}
                  {oktaFields.identity_fields.join(", ")}
                </p>
                <p>
                  <span className="font-medium text-foreground">Privileged roles:</span>{" "}
                  {oktaFields.privileged_roles.join(", ")}
                </p>
                <p>
                  <span className="font-medium text-foreground">Tenant settings:</span>{" "}
                  {oktaFields.tenant_setting_keys.join(", ")}
                </p>
                <p>
                  <span className="font-medium text-foreground">Event actions:</span>{" "}
                  {oktaFields.event_actions.join(", ")}
                </p>
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
          {fixtureTest ? (
            <Callout tone={fixtureTest.passed ? "success" : "warning"}>
              <p className="font-medium">
                Fixture test: {fixtureTest.passed ? "passed" : "failed"}
              </p>
              {!fixtureTest.passed ? (
                <p className="mt-1 font-mono text-xs">
                  expected {JSON.stringify(fixtureTest.expected)} · actual{" "}
                  {JSON.stringify(fixtureTest.actual)}
                </p>
              ) : null}
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
