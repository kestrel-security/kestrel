// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { Check, Copy, Download } from "lucide-react";
import { useId, useState } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { recoveryCodesText } from "@/lib/mfa";

/**
 * Freshly issued recovery codes, shown this once. Continue stays disabled
 * until the operator says they have kept them somewhere.
 */
export function RecoveryCodesPanel({
  codes,
  account,
  continueLabel = "Continue",
  onContinue,
  pending = false,
}: {
  codes: string[];
  account?: string;
  continueLabel?: string;
  onContinue: () => void;
  pending?: boolean;
}) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const checkboxId = useId();

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function download() {
    const text = recoveryCodesText(codes, { account, generatedAt: new Date() });
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "kestrel-recovery-codes.txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Each code signs you in once if you lose your authenticator. They won&apos;t be shown again,
        so keep them somewhere safe, such as a password manager.
      </p>
      <ul
        aria-label="Recovery codes"
        className="grid grid-cols-2 gap-x-4 gap-y-1.5 rounded-md border border-border bg-muted/40 p-3 font-mono text-sm"
      >
        {codes.map((code) => (
          <li key={code} className="select-all text-center">
            {code}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" size="sm" onClick={copyAll}>
          {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
          {copied ? "Copied" : "Copy all"}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={download}>
          <Download aria-hidden />
          Download .txt
        </Button>
        <span className="sr-only" aria-live="polite">
          {copied ? "Recovery codes copied to the clipboard" : ""}
        </span>
      </div>
      <div className="flex items-start gap-2">
        <Checkbox
          id={checkboxId}
          checked={saved}
          onCheckedChange={(value) => setSaved(value === true)}
          className="mt-0.5"
        />
        <label htmlFor={checkboxId} className="text-sm leading-snug">
          I&apos;ve saved these somewhere safe
        </label>
      </div>
      <Button type="button" onClick={onContinue} disabled={!saved || pending}>
        {pending ? "Continuing…" : continueLabel}
      </Button>
    </div>
  );
}
