// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState } from "react";
import { Check, ClipboardCopy, Download } from "lucide-react";

import { Button } from "@/components/ui/button";

export function CopyHandoffButton({ findingId }: { findingId: string }) {
  const [status, setStatus] = useState<"idle" | "copied" | "error">("idle");

  async function copyMarkdown() {
    try {
      const response = await fetch(`/api/findings/${findingId}/handoff?format=markdown`, {
        cache: "no-store",
      });
      // An expired session comes back as a redirect to the sign-in page,
      // which fetch follows to a 200 HTML page; never copy that.
      const contentType = response.headers.get("Content-Type") ?? "";
      if (!response.ok || response.redirected || !contentType.toLowerCase().startsWith("text/markdown")) {
        setStatus("error");
        return;
      }
      const text = await response.text();
      await navigator.clipboard.writeText(text);
      setStatus("copied");
      window.setTimeout(() => setStatus("idle"), 2000);
    } catch {
      setStatus("error");
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <Button
        type="button"
        size="sm"
        variant="outline"
        onClick={() => void copyMarkdown()}
        aria-live="polite"
      >
        {status === "copied" ? <Check aria-hidden /> : <ClipboardCopy aria-hidden />}
        {status === "copied" ? "Copied" : status === "error" ? "Copy failed" : "Copy for ticket"}
      </Button>
      <Button type="button" size="sm" variant="ghost" asChild>
        <a href={`/api/findings/${findingId}/handoff?format=markdown`}>
          <Download aria-hidden />
          Markdown
        </a>
      </Button>
      <Button type="button" size="sm" variant="ghost" asChild>
        <a href={`/api/findings/${findingId}/handoff?format=json`}>
          <Download aria-hidden />
          JSON
        </a>
      </Button>
    </div>
  );
}
