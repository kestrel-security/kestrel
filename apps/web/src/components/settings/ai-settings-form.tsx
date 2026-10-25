// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition, type FormEvent } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { clearAiSettings, saveAiSettings } from "@/lib/actions/settings";
import type { AiSettings } from "@/lib/types";

const PROVIDERS = [
  { id: "openai", label: "OpenAI (ChatGPT)" },
  { id: "anthropic", label: "Anthropic (Claude)" },
] as const;

export function AiSettingsForm({ initial }: { initial: AiSettings }) {
  const router = useRouter();
  const [provider, setProvider] = useState(initial.provider ?? "openai");
  const [model, setModel] = useState(
    initial.model ?? initial.defaults.models[initial.provider ?? "openai"] ?? "gpt-4o-mini",
  );
  const [baseUrl, setBaseUrl] = useState(initial.base_url ?? "");
  const [apiKey, setApiKey] = useState("");
  const [enabled, setEnabled] = useState(initial.configured ? initial.is_enabled : true);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [clearOpen, setClearOpen] = useState(false);
  const endpointChanged =
    initial.configured &&
    (provider !== initial.provider ||
      baseUrl.trim().replace(/\/+$/, "") !== (initial.base_url ?? "").replace(/\/+$/, ""));

  function onProviderChange(next: string) {
    setProvider(next);
    const defaultModel = initial.defaults.models[next];
    if (defaultModel) setModel(defaultModel);
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNote(null);
    startTransition(async () => {
      const outcome = await saveAiSettings({
        provider,
        model: model.trim() || null,
        base_url: baseUrl.trim() || null,
        api_key: apiKey.trim() || null,
        is_enabled: enabled,
      });
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      setApiKey("");
      setNote(
        outcome.result.configured
          ? `Saved ${outcome.result.provider} · ${outcome.result.model}. API key is stored encrypted and never shown again.`
          : "Saved.",
      );
      router.refresh();
    });
  }

  function onClear() {
    setError(null);
    setNote(null);
    startTransition(async () => {
      const outcome = await clearAiSettings();
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      setClearOpen(false);
      setNote(outcome.cleared ? "Cleared org AI settings." : "No AI settings were configured.");
      setApiKey("");
      router.refresh();
    });
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      {error && <p className="text-sm text-destructive">{error}</p>}
      {note && (
        <p className="rounded-md border border-green-500/30 bg-green-500/10 px-3 py-2 text-sm text-green-800 dark:text-green-300">
          {note}
        </p>
      )}

      <p className="text-sm text-muted-foreground">
        {initial.configured ? (
          <>
            Status: <span className="font-medium text-foreground">configured</span>
            {initial.api_key_configured ? " · API key on file" : ""}
            {!initial.is_enabled ? " · disabled" : ""}
          </>
        ) : (
          <>
            Status: <span className="font-medium text-foreground">not configured</span> — Generate
            with AI uses an offline stub unless a server env key is set.
          </>
        )}
      </p>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor="ai-provider">Provider</Label>
          <Select value={provider} onValueChange={onProviderChange}>
            <SelectTrigger id="ai-provider">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PROVIDERS.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label htmlFor="ai-model">Model</Label>
          <Input
            id="ai-model"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder={initial.defaults.models[provider] ?? "model id"}
            className="font-mono"
          />
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor="ai-api-key">API key</Label>
        <Input
          id="ai-api-key"
          type="password"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder={
            initial.api_key_configured ? "Leave blank to keep existing key" : "sk-… or sk-ant-…"
          }
          autoComplete="off"
          className="font-mono"
        />
        <span className="block text-xs text-muted-foreground">
          Encrypted at rest with the org master key. Never returned by the API after save.
        </span>
        {endpointChanged && (
          <span className="block text-xs text-amber-700 dark:text-amber-300">
            Changing the provider or base URL requires re-entering the API key: the stored key is
            never sent to a new endpoint.
          </span>
        )}
      </div>

      <div className="space-y-1">
        <Label htmlFor="ai-base-url">Base URL (optional)</Label>
        <Input
          id="ai-base-url"
          value={baseUrl}
          onChange={(e) => setBaseUrl(e.target.value)}
          placeholder={initial.defaults.base_urls[provider] ?? "https://…"}
          className="font-mono"
        />
        <span className="block text-xs text-muted-foreground">
          Leave blank for the provider default. OpenAI-compatible proxies work with provider OpenAI.
        </span>
      </div>

      <label className="flex items-center gap-2 text-sm">
        <Checkbox checked={enabled} onCheckedChange={(checked) => setEnabled(checked === true)} />
        Enable for policy AI drafts
      </label>

      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" disabled={pending}>
          Save
        </Button>
        {initial.configured && (
          <Dialog open={clearOpen} onOpenChange={(next) => { setClearOpen(next); if (next) setError(null); }}>
            <DialogTrigger asChild>
              <Button type="button" variant="outline" size="sm" disabled={pending}>
                Clear
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Remove org AI credentials?</DialogTitle>
                <DialogDescription>
                  Policy generate will fall back to server env or an offline stub.
                </DialogDescription>
              </DialogHeader>
              {error ? <p className="text-sm text-destructive">{error}</p> : null}
              <DialogFooter>
                <Button type="button" variant="outline" size="sm" onClick={() => setClearOpen(false)} disabled={pending}>
                  Cancel
                </Button>
                <Button type="button" variant="destructive" size="sm" onClick={onClear} disabled={pending}>
                  {pending ? "Clearing…" : "Clear"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </form>
  );
}
