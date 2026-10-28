// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { Button } from "@/components/ui/button";
import { Callout } from "@/components/ui/callout";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { previewClassificationRules, saveClassificationRules } from "@/lib/actions/settings";
import type {
  ClassificationMatchKind,
  ClassificationPreview,
  ClassificationRuleInput,
  ClassificationRules,
  WorkerType,
} from "@/lib/types";
import { MATCH_KIND_HINTS, MATCH_KIND_LABELS, WORKER_TYPE_LABELS } from "@/lib/worker-type";

type Draft = ClassificationRuleInput & { key: string };

function toDrafts(settings: ClassificationRules): Draft[] {
  return settings.rules.map((rule) => ({
    key: rule.id,
    id: rule.id,
    is_enabled: rule.is_enabled,
    worker_type: rule.worker_type,
    match_kind: rule.match_kind,
    match_value: rule.match_value,
    application_type: rule.application_type,
    label: rule.label,
  }));
}

function toInput(drafts: Draft[]): ClassificationRuleInput[] {
  return drafts.map((draft) => ({
    id: draft.id,
    is_enabled: draft.is_enabled,
    worker_type: draft.worker_type,
    match_kind: draft.match_kind,
    match_value: draft.match_value,
    application_type: draft.application_type?.trim() || null,
    label: draft.label?.trim() || null,
  }));
}

let nextKey = 0;

export function IdentityClassificationForm({ initial }: { initial: ClassificationRules }) {
  const router = useRouter();
  const [drafts, setDrafts] = useState<Draft[]>(() => toDrafts(initial));
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [preview, setPreview] = useState<ClassificationPreview | null>(null);
  const [pending, startTransition] = useTransition();

  function update(index: number, patch: Partial<Draft>) {
    setPreview(null);
    setDrafts((current) => current.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  }

  function move(index: number, delta: number) {
    setPreview(null);
    setDrafts((current) => {
      const target = index + delta;
      if (target < 0 || target >= current.length) return current;
      const next = [...current];
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });
  }

  function remove(index: number) {
    setPreview(null);
    setDrafts((current) => current.filter((_, i) => i !== index));
  }

  function add() {
    setPreview(null);
    nextKey += 1;
    setDrafts((current) => [
      ...current,
      {
        key: `new-${nextKey}`,
        is_enabled: true,
        worker_type: "contractor",
        match_kind: "email_domain",
        match_value: "",
        application_type: null,
        label: null,
      },
    ]);
  }

  function onPreview() {
    setError(null);
    setNote(null);
    startTransition(async () => {
      const outcome = await previewClassificationRules(toInput(drafts));
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      setPreview(outcome.result);
    });
  }

  function onSave() {
    setError(null);
    setNote(null);
    startTransition(async () => {
      const outcome = await saveClassificationRules(toInput(drafts));
      if (!outcome.ok) {
        setError(outcome.error);
        return;
      }
      setDrafts(toDrafts(outcome.result));
      setPreview(null);
      setNote(
        `Saved ${outcome.result.rules.length} rule${outcome.result.rules.length === 1 ? "" : "s"}; ${
          outcome.result.reclassified ?? 0
        } identit${outcome.result.reclassified === 1 ? "y" : "ies"} reclassified.`,
      );
      router.refresh();
    });
  }

  return (
    <div className="space-y-4">
      {error ? <Callout tone="error">{error}</Callout> : null}
      {note ? <Callout tone="success">{note}</Callout> : null}
      {preview ? (
        <Callout tone="info">
          <span className="font-medium text-foreground">Preview:</span>{" "}
          {preview.changed} identit{preview.changed === 1 ? "y" : "ies"} would change.{" "}
          {Object.entries(preview.counts)
            .filter(([, count]) => count > 0)
            .map(([type, count]) => `${WORKER_TYPE_LABELS[type as WorkerType] ?? type}: ${count}`)
            .join(" · ")}
        </Callout>
      ) : null}

      {drafts.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No rules yet. Accounts keep whatever their provider says, and Google Workspace users stay unknown.
        </p>
      ) : null}

      <ol className="space-y-3">
        {drafts.map((rule, index) => (
          <li key={rule.key} className="rounded-md border border-border p-3">
            <div className="grid gap-3 md:grid-cols-[auto_1fr_1fr_1.4fr_1fr] md:items-end">
              <div className="flex items-center gap-2 pb-2 md:pb-0">
                <span className="w-5 text-right font-mono text-xs text-muted-foreground">{index + 1}</span>
                <Checkbox
                  id={`rule-${rule.key}-enabled`}
                  checked={rule.is_enabled}
                  onCheckedChange={(checked) => update(index, { is_enabled: checked === true })}
                  aria-label="Rule enabled"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor={`rule-${rule.key}-kind`}>Match</Label>
                <Select
                  value={rule.match_kind}
                  onValueChange={(value) => update(index, { match_kind: value as ClassificationMatchKind })}
                >
                  <SelectTrigger id={`rule-${rule.key}-kind`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {initial.match_kinds.map((kind) => (
                      <SelectItem key={kind} value={kind}>
                        {MATCH_KIND_LABELS[kind] ?? kind}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor={`rule-${rule.key}-value`}>Value</Label>
                <Input
                  id={`rule-${rule.key}-value`}
                  value={rule.match_value}
                  onChange={(e) => update(index, { match_value: e.target.value })}
                  placeholder={MATCH_KIND_HINTS[rule.match_kind]}
                  className="font-mono"
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor={`rule-${rule.key}-type`}>Classify as</Label>
                <Select
                  value={rule.worker_type}
                  onValueChange={(value) => update(index, { worker_type: value as WorkerType })}
                >
                  <SelectTrigger id={`rule-${rule.key}-type`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {initial.worker_types.map((type) => (
                      <SelectItem key={type} value={type}>
                        {WORKER_TYPE_LABELS[type] ?? type}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor={`rule-${rule.key}-app`}>Only in (optional)</Label>
                <Input
                  id={`rule-${rule.key}-app`}
                  value={rule.application_type ?? ""}
                  onChange={(e) => update(index, { application_type: e.target.value || null })}
                  placeholder="google_workspace"
                  className="font-mono"
                />
              </div>
            </div>
            <div className="mt-3 flex flex-wrap items-end gap-3">
              <div className="min-w-[16rem] flex-1 space-y-1">
                <Label htmlFor={`rule-${rule.key}-label`}>Label (optional)</Label>
                <Input
                  id={`rule-${rule.key}-label`}
                  value={rule.label ?? ""}
                  onChange={(e) => update(index, { label: e.target.value || null })}
                  placeholder="Contractors org unit"
                />
              </div>
              <div className="flex gap-1">
                <Button type="button" variant="ghost" size="sm" disabled={index === 0} onClick={() => move(index, -1)}>
                  Up
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={index === drafts.length - 1}
                  onClick={() => move(index, 1)}
                >
                  Down
                </Button>
                <Button type="button" variant="ghost" size="sm" onClick={() => remove(index)}>
                  Remove
                </Button>
              </div>
              {preview?.matched_by_rule[index] !== undefined ? (
                <span className="text-xs text-muted-foreground">
                  matches {preview.matched_by_rule[index]} account{preview.matched_by_rule[index] === 1 ? "" : "s"}
                </span>
              ) : null}
            </div>
          </li>
        ))}
      </ol>

      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" size="sm" onClick={add} disabled={pending}>
          Add rule
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={onPreview} disabled={pending}>
          Preview
        </Button>
        <Button type="button" size="sm" onClick={onSave} disabled={pending}>
          Save and reclassify
        </Button>
      </div>
    </div>
  );
}
