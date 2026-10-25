// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { unstable_rethrow } from "next/navigation";

import { ApiError } from "@/lib/api";

/**
 * Join FastAPI's validation-error shape (`detail: [{loc, msg, type}, ...]`)
 * into one line. Null when `detail` is not that shape.
 */
export function validationDetailMessage(detail: unknown): string | null {
  if (!Array.isArray(detail)) return null;
  const messages = detail
    .map((item) => (item as { msg?: unknown } | null)?.msg)
    .filter((msg): msg is string => typeof msg === "string" && msg.length > 0);
  return messages.length > 0 ? messages.join("; ") : null;
}

/**
 * Turn a failed API call into a short message a server action can return to
 * the UI. Lives outside the `"use server"` modules under `lib/actions/` because
 * those may only export async functions.
 *
 * Next's own control-flow errors are rethrown first: lib/api.ts calls
 * `redirect()` on an expired session (to /login) and on a session limited to
 * MFA enrolment (to /mfa/setup), and an action that swallowed those would
 * report "Request failed" instead of sending the operator where they belong.
 */
export function formatActionError(err: unknown): string {
  unstable_rethrow(err);
  if (!(err instanceof ApiError)) return "Request failed";
  if (err.status === 429) {
    return "Rate limit reached — wait a moment and try again.";
  }
  try {
    const parsed = JSON.parse(err.message) as { detail?: unknown };
    if (typeof parsed.detail === "string") return parsed.detail;
    // FastAPI request validation (422): a list of {loc, msg, type}.
    const validation = validationDetailMessage(parsed.detail);
    if (validation) return validation;
    // Structured details, e.g. {code: "mfa_enrollment_required", message}.
    const message = (parsed.detail as { message?: unknown } | null)?.message;
    if (typeof message === "string") return message;
    // JSON, but not a shape with a message: never show the raw body.
    return "Request failed";
  } catch {
    // body wasn't JSON
  }
  return err.message;
}
