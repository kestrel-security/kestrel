// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState, useTransition, type FormEvent } from "react";

import { ConnectorSetupGuide } from "@/components/connectors/connector-setup-guide";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { firstMissingConfigField, isOptionalConfigField } from "@/lib/connector-config-fields";
import { createConnectorInstance, probeConnectorConfig } from "@/lib/actions/connectors";
import {
  connectorConfigFields,
  connectorConfigValues,
  connectorFormDefaults,
  followDefault,
  resolveAuthMethod,
} from "@/lib/connector-form";
import type { ConnectorProbeResult } from "@/lib/types";
import { ProbeChecklist } from "@/components/connectors/probe-checklist";
import type { ConnectorCatalogEntry } from "@/lib/types";

const CRON_PRESETS: { label: string; value: string }[] = [
  { label: "Every 15 minutes", value: "*/15 * * * *" },
  { label: "Every hour", value: "0 * * * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Daily at 02:00 UTC", value: "0 2 * * *" },
];

function fieldLabel(name: string): string {
  return name.replaceAll("_", " ");
}

function isJsonSecret(name: string): boolean {
  return name.endsWith("_json") || name.includes("service_account");
}

type Step = "basics" | "config" | "secrets" | "schedule";

function catalogSource(entry: ConnectorCatalogEntry): "builtin" | "custom" {
  return entry.source === "custom" || entry.source === "community" ? "custom" : "builtin";
}

export function ConnectorCreateForm({ catalog }: { catalog: ConnectorCatalogEntry[] }) {
  const router = useRouter();
  const [step, setStep] = useState<Step>("basics");
  const hasCustom = catalog.some((c) => catalogSource(c) === "custom");
  const [catalogKind, setCatalogKind] = useState<"builtin" | "custom">("builtin");
  const visibleCatalog = useMemo(
    () => catalog.filter((c) => catalogSource(c) === catalogKind),
    [catalog, catalogKind],
  );
  const [connectorName, setConnectorName] = useState(
    () => catalog.find((c) => catalogSource(c) === "builtin")?.name ?? catalog[0]?.name ?? "",
  );
  const selected = useMemo(
    () => catalog.find((c) => c.name === connectorName) ?? catalog[0] ?? null,
    [catalog, connectorName],
  );
  const [displayName, setDisplayName] = useState("");
  const [externalTenantRef, setExternalTenantRef] = useState("");
  const [authMethodChoice, setAuthMethod] = useState(
    () => (selected ? connectorFormDefaults(selected).authMethod : ""),
  );
  // Live is the primary product path; fixtures remain for CI / offline demos.
  const [syncMode, setSyncMode] = useState("live");
  // Always one of the selected connector's methods, even if the stored choice
  // went stale, so the Auth method select is never blank.
  const authSpec = useMemo(
    () => resolveAuthMethod(selected, authMethodChoice),
    [selected, authMethodChoice],
  );
  const authMethod = authSpec?.id ?? "";
  const configFields = selected ? connectorConfigFields(selected, authSpec) : [];
  const secretFields = authSpec?.secret_fields ?? [];
  const [configValues, setConfigValues] = useState<Record<string, string>>(
    () => (selected ? connectorFormDefaults(selected).configValues : {}),
  );
  const [secretValues, setSecretValues] = useState<Record<string, string>>({});
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [scheduleCron, setScheduleCron] = useState(CRON_PRESETS[1].value);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function onConnectorChange(name: string) {
    const next = catalog.find((c) => c.name === name);
    if (!next) return;
    const previous = selected ? connectorFormDefaults(selected) : null;
    const defaults = connectorFormDefaults(next);
    setConnectorName(name);
    // Everything connector-specific starts over: auth method, config fields,
    // secrets, and the name and tenant ref unless the operator typed their own.
    setAuthMethod(defaults.authMethod);
    setConfigValues(defaults.configValues);
    setSecretValues({});
    setSyncMode("live");
    setProbe(null);
    setDisplayName((current) => followDefault(current, previous?.displayName, defaults.displayName));
    setExternalTenantRef((current) =>
      followDefault(current, previous?.externalTenantRef, defaults.externalTenantRef),
    );
    setStep("basics");
  }

  function onAuthChange(id: string) {
    const method = selected?.auth_methods.find((m) => m.id === id);
    // Radix Select can report "" while its options are being replaced; ignore
    // anything that isn't one of this connector's methods.
    if (!method || !selected) return;
    setAuthMethod(id);
    setConfigValues(connectorConfigValues(selected, method, configValues));
    setSecretValues({});
  }

  function buildConfig(): Record<string, unknown> {
    const config: Record<string, unknown> = {};
    for (const field of configFields) {
      const raw = (configValues[field] ?? "").trim();
      if (raw) config[field] = raw;
    }
    return config;
  }

  function validateBasics(): string | null {
    if (!connectorName) return "Select a connector";
    if (!displayName.trim()) return "Display name is required";
    if (!externalTenantRef.trim()) return "External tenant ref is required";
    return null;
  }

  function validateConfig(): string | null {
    const missing = firstMissingConfigField(configFields, authSpec?.optional_config_fields, configValues);
    return missing ? `${fieldLabel(missing)} is required` : null;
  }

  function validateSecrets(): string | null {
    if (syncMode !== "live") return null;
    for (const field of secretFields) {
      if (!(secretValues[field] ?? "").trim()) {
        return `Live mode requires ${fieldLabel(field)}`;
      }
    }
    return null;
  }

  const [probe, setProbe] = useState<ConnectorProbeResult | null>(null);
  const [probing, setProbing] = useState(false);

  function collectSecrets(): Record<string, string> {
    const secrets: Record<string, string> = {};
    if (syncMode === "live") {
      for (const field of secretFields) {
        const v = secretValues[field] ?? "";
        if (v.trim()) secrets[field] = isJsonSecret(field) ? v : v.trim();
      }
    }
    return secrets;
  }

  async function runProbe(): Promise<ConnectorProbeResult | null> {
    setProbing(true);
    setProbe(null);
    try {
      const outcome = await probeConnectorConfig({
        connector_name: connectorName,
        auth_method: authMethod,
        sync_mode: syncMode,
        config: buildConfig(),
        secrets: collectSecrets(),
      });
      if (!outcome.ok) {
        setError(outcome.error);
        return null;
      }
      setProbe(outcome.result);
      return outcome.result;
    } finally {
      setProbing(false);
    }
  }

  function goNext() {
    setError(null);
    if (step === "basics") {
      const err = validateBasics();
      if (err) {
        setError(err);
        return;
      }
      setStep("config");
      return;
    }
    if (step === "config") {
      const err = validateConfig();
      if (err) {
        setError(err);
        return;
      }
      setStep(syncMode === "live" && secretFields.length > 0 ? "secrets" : "schedule");
      return;
    }
    if (step === "secrets") {
      const err = validateSecrets();
      if (err) {
        setError(err);
        return;
      }
      // Verify before moving on: a wrong token or a missing scope should be
      // caught here, not after the connector exists. "Save anyway" is explicit.
      void runProbe().then((result) => {
        if (result?.ok) setStep("schedule");
      });
    }
  }

  function goBack() {
    setError(null);
    if (step === "schedule") {
      setStep(syncMode === "live" && secretFields.length > 0 ? "secrets" : "config");
      return;
    }
    if (step === "secrets") {
      setStep("config");
      return;
    }
    if (step === "config") setStep("basics");
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const basicsErr = validateBasics();
    if (basicsErr) {
      setError(basicsErr);
      setStep("basics");
      return;
    }
    const configErr = validateConfig();
    if (configErr) {
      setError(configErr);
      setStep("config");
      return;
    }
    const secretsErr = validateSecrets();
    if (secretsErr) {
      setError(secretsErr);
      setStep("secrets");
      return;
    }

    const secrets = collectSecrets();

    startTransition(async () => {
      const outcome = await createConnectorInstance({
        connector_name: connectorName,
        display_name: displayName,
        external_tenant_ref: externalTenantRef,
        config: buildConfig(),
        auth_method: authMethod,
        sync_mode: syncMode,
        schedule_cron: scheduleEnabled ? scheduleCron.trim() || null : null,
        secrets,
      });
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      router.push(`/connectors/${outcome.id}`);
      router.refresh();
    });
  }

  if (catalog.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        No connector packages are installed in this deployment. Install a connector package (for
        example <code className="rounded bg-muted px-1 font-mono">kestrel-connector-github</code>) and
        restart the API.
      </p>
    );
  }

  const steps: { id: Step; label: string }[] = [
    { id: "basics", label: "Basics" },
    { id: "config", label: "Config" },
    ...(syncMode === "live" && secretFields.length > 0
      ? [{ id: "secrets" as const, label: "Secrets" }]
      : []),
    { id: "schedule", label: "Schedule" },
  ];
  const stepIndex = steps.findIndex((s) => s.id === step);

  const fieldHelp = authSpec?.field_help ?? {};
  const showSetupGuide = step === "basics" || step === "config" || step === "secrets";

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(16rem,20rem)]">
      <form onSubmit={onSubmit} className="space-y-5">
        <nav aria-label="Setup progress" className="flex flex-wrap items-center gap-1.5">
          {steps.map((s, i) => (
            <div key={s.id} className="flex items-center gap-1.5">
              <span
                className={cn(
                  "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                  s.id === step
                    ? "bg-primary text-primary-foreground"
                    : i < stepIndex
                      ? "text-muted-foreground"
                      : "border border-border text-muted-foreground",
                )}
              >
                <span
                  className={cn(
                    "flex size-4 items-center justify-center rounded-full text-[10px]",
                    s.id === step ? "bg-primary-foreground/20" : "bg-muted",
                  )}
                >
                  {i + 1}
                </span>
                {s.label}
              </span>
              {i < steps.length - 1 ? <span className="h-px w-3 bg-border" aria-hidden /> : null}
            </div>
          ))}
        </nav>

        {error && (
          <p
            role="alert"
            className="whitespace-pre-wrap rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
          >
            {error}
          </p>
        )}

        {step === "basics" && (
          <div className="space-y-4">
            {hasCustom && (
              <div className="space-y-1.5">
                <Label>Integration type</Label>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant={catalogKind === "builtin" ? "default" : "outline"}
                    onClick={() => {
                      setCatalogKind("builtin");
                      const next = catalog.find((c) => catalogSource(c) === "builtin");
                      if (next) onConnectorChange(next.name);
                    }}
                  >
                    First-party
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant={catalogKind === "custom" ? "default" : "outline"}
                    onClick={() => {
                      setCatalogKind("custom");
                      const next = catalog.find((c) => catalogSource(c) === "custom");
                      if (next) onConnectorChange(next.name);
                    }}
                  >
                    Custom
                  </Button>
                </div>
              </div>
            )}
            <div className="space-y-1.5">
              <Label htmlFor="connector-select">Connector</Label>
              {visibleCatalog.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No custom connector packages are installed. Scaffold one with{" "}
                  <code className="rounded bg-muted px-1 font-mono">
                    kestrel connector create &lt;name&gt;
                  </code>
                  , add it to the workspace or{" "}
                  <code className="rounded bg-muted px-1 font-mono">KESTREL_CUSTOM_CONNECTORS_DIR</code>,
                  then restart the API.
                </p>
              ) : (
                <Select value={connectorName} onValueChange={onConnectorChange}>
                  <SelectTrigger id="connector-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {visibleCatalog.map((c) => (
                      <SelectItem key={c.name} value={c.name}>
                        {c.display_name} ({c.name})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
              {selected && <p className="text-xs text-muted-foreground">{selected.description}</p>}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="display-name">Display name</Label>
                <Input
                  id="display-name"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  required
                  placeholder="Acme Corp GitHub"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="tenant-ref">External tenant ref</Label>
                <Input
                  id="tenant-ref"
                  value={externalTenantRef}
                  onChange={(e) => setExternalTenantRef(e.target.value)}
                  required
                  placeholder="org login or domain"
                />
                <p className="text-xs text-muted-foreground">
                  Stable provider id for this tenant (GitHub org login, Workspace domain, …). Match
                  the primary config field (for example org_login).
                </p>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="auth-method">Auth method</Label>
                <Select key={selected?.name} value={authMethod} onValueChange={onAuthChange}>
                  <SelectTrigger id="auth-method">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(selected?.auth_methods ?? []).map((m) => (
                      <SelectItem key={m.id} value={m.id}>
                        {m.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sync-mode">Data source</Label>
                <Select value={syncMode} onValueChange={setSyncMode}>
                  <SelectTrigger id="sync-mode">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="live">Connect to my tenant</SelectItem>
                    <SelectItem value="fixtures">Sample data (no credentials)</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {syncMode === "live"
                    ? "Reads your real tenant with read-only credentials, stored envelope-encrypted. Follow the setup guide for the exact scopes."
                    : "Bundled sample data for trying the product offline. Nothing connects to a real tenant, and findings describe the sample estate rather than yours."}
                </p>
              </div>
            </div>
          </div>
        )}

        {step === "config" && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Guided fields from the connector manifest — follow the setup guide for where each
              value comes from.
            </p>
            {configFields.length === 0 ? (
              <p className="text-sm text-muted-foreground">This connector declares no config fields.</p>
            ) : (
              configFields.map((field) => (
                <div key={field} className="space-y-1.5">
                  <Label htmlFor={`config-${field}`} className="capitalize">
                    {fieldLabel(field)}
                    {isOptionalConfigField(field, authSpec?.optional_config_fields) && (
                      <span className="ml-1 font-normal normal-case text-muted-foreground">(optional)</span>
                    )}
                  </Label>
                  <Input
                    id={`config-${field}`}
                    value={configValues[field] ?? ""}
                    onChange={(e) =>
                      setConfigValues((prev) => ({ ...prev, [field]: e.target.value }))
                    }
                    required={!isOptionalConfigField(field, authSpec?.optional_config_fields)}
                  />
                  {fieldHelp[field] && (
                    <p className="text-xs text-muted-foreground">
                      {fieldHelp[field].replace(/\s+/g, " ").trim()}
                    </p>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {step === "secrets" && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Credentials are envelope-encrypted (ADR-0004) and never shown again after save. Follow
              the setup guide to create the API key / token / app before pasting.
            </p>
            {secretFields.map((field) => (
              <div key={field} className="space-y-1.5">
                <Label htmlFor={`secret-${field}`} className="capitalize">
                  {fieldLabel(field)}
                </Label>
                {isJsonSecret(field) || field === "private_key" ? (
                  <Textarea
                    id={`secret-${field}`}
                    value={secretValues[field] ?? ""}
                    onChange={(e) =>
                      setSecretValues((prev) => ({ ...prev, [field]: e.target.value }))
                    }
                    rows={field === "private_key" ? 8 : 6}
                    spellCheck={false}
                    required={syncMode === "live"}
                    className="font-mono"
                  />
                ) : (
                  <Input
                    id={`secret-${field}`}
                    type="password"
                    autoComplete="off"
                    value={secretValues[field] ?? ""}
                    onChange={(e) =>
                      setSecretValues((prev) => ({ ...prev, [field]: e.target.value }))
                    }
                    required={syncMode === "live"}
                  />
                )}
                {fieldHelp[field] && (
                  <p className="text-xs text-muted-foreground">
                    {fieldHelp[field].replace(/\s+/g, " ").trim()}
                  </p>
                )}
              </div>
            ))}
            {probe && <ProbeChecklist result={probe} />}
            {probe && !probe.ok && (
              <p className="text-xs text-muted-foreground">
                Fix the credentials and continue to test again, or save anyway and test from the
                integration page later.
              </p>
            )}
          </div>
        )}

        {step === "schedule" && (
          <fieldset className="space-y-3 rounded-md border border-border p-3">
            <legend className="px-1 text-xs text-muted-foreground">Periodic sync schedule</legend>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={scheduleEnabled}
                onCheckedChange={(checked) => setScheduleEnabled(checked === true)}
              />
              Enable scheduled syncs
            </label>
            {scheduleEnabled && (
              <div className="space-y-2">
                <Select
                  value={CRON_PRESETS.some((p) => p.value === scheduleCron) ? scheduleCron : "custom"}
                  onValueChange={(value) => {
                    if (value !== "custom") setScheduleCron(value);
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="custom">Custom expression…</SelectItem>
                    {CRON_PRESETS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label} ({p.value})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  value={scheduleCron}
                  onChange={(e) => setScheduleCron(e.target.value)}
                  placeholder="*/30 * * * *"
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  Standard 5-field cron (UTC). Missed fires are not backfilled.
                </p>
              </div>
            )}
          </fieldset>
        )}

        <div className="flex flex-wrap gap-2">
          {step !== "basics" && (
            <Button type="button" variant="outline" size="sm" onClick={goBack}>
              Back
            </Button>
          )}
          {step !== "schedule" ? (
            <>
              <Button type="button" size="sm" onClick={goNext} disabled={probing}>
                {step === "secrets" ? (probing ? "Testing connection…" : "Test connection & continue") : "Continue"}
              </Button>
              {step === "secrets" && probe && !probe.ok && (
                <Button type="button" size="sm" variant="outline" onClick={() => setStep("schedule")}>
                  Save anyway
                </Button>
              )}
            </>
          ) : (
            <Button type="submit" size="sm" disabled={pending}>
              {pending ? "Creating…" : "Create integration"}
            </Button>
          )}
        </div>
      </form>

      {showSetupGuide && (
        <div className="lg:sticky lg:top-4 lg:self-start">
          <ConnectorSetupGuide connector={selected} authMethod={authSpec} />
        </div>
      )}
    </div>
  );
}
