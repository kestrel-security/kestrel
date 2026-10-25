// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition, type FormEvent } from "react";

import { StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { updateConnectorInstance, upsertConnectorSecrets } from "@/lib/actions/connectors";
import { changedEndpointFields } from "@/lib/connector-endpoints";
import type { ConnectorInstanceDetail } from "@/lib/types";

function fieldLabel(name: string): string {
  return name.replaceAll("_", " ");
}

function isJsonSecret(name: string): boolean {
  return name.endsWith("_json") || name.includes("service_account");
}

export function ConnectorEditForm({ detail }: { detail: ConnectorInstanceDetail }) {
  const router = useRouter();
  const [displayName, setDisplayName] = useState(detail.application_display_name ?? "");
  const [syncMode, setSyncMode] = useState(detail.sync_mode);
  const [initialConfig] = useState<Record<string, string>>(() => {
    const initial: Record<string, string> = {};
    const fields =
      detail.config_fields.length > 0 ? detail.config_fields : Object.keys(detail.config ?? {});
    for (const field of fields) {
      const v = detail.config?.[field];
      initial[field] = v == null ? "" : String(v);
    }
    return initial;
  });
  const [configValues, setConfigValues] = useState<Record<string, string>>(initialConfig);
  const [secretValues, setSecretValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const configFields =
    detail.config_fields.length > 0 ? detail.config_fields : Object.keys(detail.config ?? {});
  const secretFields = detail.secrets.declared_fields;
  // Changing where the connector sends requests clears its stored secrets
  // server-side, so they are re-entered and saved together with the change.
  const endpointChanges = changedEndpointFields(initialConfig, configValues);
  const secretsAtRisk = endpointChanges.length > 0 && detail.secrets.configured_fields.length > 0;

  function enteredSecrets(): Record<string, string> {
    const secrets: Record<string, string> = {};
    for (const field of secretFields) {
      const v = secretValues[field] ?? "";
      if (v.trim()) secrets[field] = isJsonSecret(field) ? v : v.trim();
    }
    return secrets;
  }

  function onSaveSettings(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    const config: Record<string, unknown> = {};
    for (const field of configFields) {
      const raw = (configValues[field] ?? "").trim();
      if (raw) config[field] = raw;
    }
    const secrets = endpointChanges.length > 0 ? enteredSecrets() : {};
    startTransition(async () => {
      const outcome = await updateConnectorInstance(detail.id, {
        display_name: displayName.trim() || undefined,
        sync_mode: syncMode,
        config,
        ...(Object.keys(secrets).length > 0 ? { secrets } : {}),
      });
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      if (Object.keys(secrets).length > 0) setSecretValues({});
      if (outcome.secretsCleared.length > 0) {
        setError(
          `Settings saved. ${endpointChanges.join(", ") || "The connection URL"} changed, so the stored ` +
            `secrets (${outcome.secretsCleared.join(", ")}) were cleared. Re-enter them below before ` +
            "testing or syncing.",
        );
      } else {
        setMessage("Settings saved.");
      }
      router.refresh();
    });
  }

  function onSaveSecrets(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setMessage(null);
    const secrets = enteredSecrets();
    if (Object.keys(secrets).length === 0) {
      setError("Enter at least one secret to update (leave blank to keep existing values).");
      return;
    }
    startTransition(async () => {
      const outcome = await upsertConnectorSecrets(detail.id, secrets);
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      setSecretValues({});
      setMessage("Secrets updated (encrypted at rest).");
      router.refresh();
    });
  }

  return (
    <div className="space-y-6">
      {error && (
        <p className="whitespace-pre-wrap rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}
      {message && (
        <p className="rounded-md border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-800 dark:text-green-300">
          {message}
        </p>
      )}

      <form onSubmit={onSaveSettings} className="space-y-4">
        <h2 className="text-sm font-medium">Settings</h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="edit-display-name">Display name</Label>
            <Input
              id="edit-display-name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edit-sync-mode">Sync mode</Label>
            <Select value={syncMode} onValueChange={setSyncMode}>
              <SelectTrigger id="edit-sync-mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="fixtures">fixtures</SelectItem>
                <SelectItem value="live">live</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Config fields from the connector manifest (never put credentials here).
          </p>
          {configFields.map((field) => (
            <div key={field} className="space-y-1.5">
              <Label htmlFor={`edit-config-${field}`} className="capitalize">
                {fieldLabel(field)}
              </Label>
              <Input
                id={`edit-config-${field}`}
                value={configValues[field] ?? ""}
                onChange={(e) =>
                  setConfigValues((prev) => ({ ...prev, [field]: e.target.value }))
                }
              />
            </div>
          ))}
        </div>
        {secretsAtRisk && (
          <p className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-900 dark:text-amber-200">
            Changing {endpointChanges.join(", ")} clears this integration&apos;s stored secrets, so they are
            never sent to a new host. Fill in the secret fields below before saving to keep the
            integration working; they are saved together with these settings.
          </p>
        )}
        <Button type="submit" size="sm" disabled={pending}>
          {pending ? "Saving…" : "Save settings"}
        </Button>
      </form>

      <form onSubmit={onSaveSecrets} className="space-y-4 border-t border-border pt-6">
        <div>
          <h2 className="text-sm font-medium">Secrets</h2>
          <p className="mt-1 text-xs text-muted-foreground">
            Envelope-encrypted at rest. Leave a field blank to keep the existing value. Plaintext is
            never returned by the API.
          </p>
        </div>
        {secretFields.length === 0 ? (
          <p className="text-sm text-muted-foreground">No secret fields declared for this auth method.</p>
        ) : (
          secretFields.map((field) => {
            const configured = detail.secrets.configured_fields.includes(field);
            return (
              <div key={field} className="space-y-1.5">
                <Label htmlFor={`edit-secret-${field}`} className="flex items-center gap-2 capitalize">
                  <span>{fieldLabel(field)}</span>
                  <StatusBadge status={configured ? "configured" : "missing"} />
                </Label>
                {isJsonSecret(field) ? (
                  <Textarea
                    id={`edit-secret-${field}`}
                    value={secretValues[field] ?? ""}
                    onChange={(e) =>
                      setSecretValues((prev) => ({ ...prev, [field]: e.target.value }))
                    }
                    rows={5}
                    spellCheck={false}
                    placeholder={configured ? "•••••••• (leave blank to keep)" : ""}
                    className="font-mono"
                  />
                ) : (
                  <Input
                    id={`edit-secret-${field}`}
                    type="password"
                    autoComplete="off"
                    value={secretValues[field] ?? ""}
                    onChange={(e) =>
                      setSecretValues((prev) => ({ ...prev, [field]: e.target.value }))
                    }
                    placeholder={configured ? "•••••••• (leave blank to keep)" : ""}
                  />
                )}
              </div>
            );
          })
        )}
        {secretFields.length > 0 && (
          <Button type="submit" variant="outline" size="sm" disabled={pending}>
            {pending ? "Saving…" : "Update secrets"}
          </Button>
        )}
      </form>
    </div>
  );
}
