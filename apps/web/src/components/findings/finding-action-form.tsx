// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import { useState, useTransition, type FormEvent, type ReactNode } from "react";

import { localDateTimeToIso } from "@/lib/expiry";
import { cn } from "@/lib/utils";

export type FindingActionResult = { ok: true } | { ok: false; error: string };

/**
 * A form for one finding mutation whose failure shows up next to the form
 * instead of throwing to the page's error boundary (which replaced the whole
 * finding with an error screen on any 4xx).
 *
 * Fields are kept on failure so a note or reason is not lost; on success the
 * form resets and the page re-renders from the action's revalidatePath.
 *
 * `localDateTimeFields` maps a `datetime-local` input's name to the field that
 * should carry its value as an absolute ISO timestamp, converted here in the
 * operator's zone (see lib/expiry.ts).
 */
export function FindingActionForm({
  action,
  className,
  errorClassName,
  localDateTimeFields,
  children,
}: {
  action: (formData: FormData) => Promise<FindingActionResult>;
  className?: string;
  errorClassName?: string;
  localDateTimeFields?: Record<string, string>;
  children: ReactNode;
}) {
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const form = event.currentTarget;
    const formData = new FormData(form);
    for (const [localName, isoName] of Object.entries(localDateTimeFields ?? {})) {
      const local = formData.get(localName);
      const iso = typeof local === "string" && local ? localDateTimeToIso(local) : null;
      formData.set(isoName, iso ?? "");
    }
    setError(null);
    startTransition(async () => {
      const result = await action(formData);
      if (result.ok) {
        form.reset();
      } else {
        setError(result.error);
      }
    });
  }

  return (
    <form onSubmit={onSubmit} aria-busy={pending} className={className}>
      <fieldset disabled={pending} className="contents">
        {children}
      </fieldset>
      {error ? (
        <p role="alert" className={cn("w-full basis-full text-sm text-destructive", errorClassName)}>
          {error}
        </p>
      ) : null}
    </form>
  );
}
