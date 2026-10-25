// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
/**
 * Pure helpers for two-factor authentication (TOTP). The API's scheme lives in
 * kestrel/src/kestrel/auth/mfa.py: 6-digit codes on a 30-second step, and
 * recovery codes of 8 characters shown as `xxxx-xxxx`.
 */

import { DEFAULT_AFTER_LOGIN } from "@/lib/login-redirect";

/** Cookie holding the 5-minute challenge token between password and code. */
export const MFA_CHALLENGE_COOKIE_NAME = "kestrel_mfa";
export const MFA_CHALLENGE_MAX_AGE_SECONDS = 5 * 60;

export const TOTP_DIGITS = 6;
const RECOVERY_CODE_LENGTH = 8;

export type MfaCodeKind = "totp" | "recovery";

export type NormalizedMfaCode = { code: string; kind: MfaCodeKind } | null;

/**
 * Strip what people paste or type around a code (spaces, dashes, case), the
 * same normalisation the API applies, and say which kind it looks like.
 * Null when it is neither a 6-digit code nor an 8-character recovery code,
 * so the form can say so without spending one of the challenge's attempts.
 */
export function normalizeMfaCode(raw: string): NormalizedMfaCode {
  const code = raw.trim().toLowerCase().replace(/[\s-]+/g, "");
  if (code.length === TOTP_DIGITS && /^\d+$/.test(code)) return { code, kind: "totp" };
  if (code.length === RECOVERY_CODE_LENGTH && /^[a-z0-9]+$/.test(code)) {
    return { code, kind: "recovery" };
  }
  return null;
}

/** A base32 secret in groups of four for typing into an authenticator app. */
export function formatSecret(secret: string): string {
  const compact = secret.replace(/\s+/g, "").toUpperCase();
  return (compact.match(/.{1,4}/g) ?? []).join(" ");
}

/** The body of the downloadable recovery-codes file. */
export function recoveryCodesText(
  codes: readonly string[],
  options: { account?: string; generatedAt?: Date } = {},
): string {
  const lines = ["Kestrel recovery codes"];
  if (options.account) lines.push(`Account: ${options.account}`);
  if (options.generatedAt) lines.push(`Generated: ${options.generatedAt.toISOString()}`);
  lines.push(
    "",
    "Each code signs you in once if you lose your authenticator.",
    "Generating new codes invalidates these.",
    "",
    ...codes,
    "",
  );
  return lines.join("\n");
}

export interface LoginResult {
  token: string;
  mfa_required?: boolean;
  mfa_enrollment_required?: boolean;
}

/**
 * Where the browser goes after `POST /auth/login` succeeds. `next` must
 * already be sanitised (safeNextPath); it rides along to the MFA steps so the
 * operator still lands where they were headed.
 */
export function routeAfterLogin(result: LoginResult, next: string | null): string {
  if (result.mfa_required) return withNext("/login/mfa", next);
  if (result.mfa_enrollment_required) return withNext("/mfa/setup", next);
  return next ?? DEFAULT_AFTER_LOGIN;
}

/** Where enrolment continues once MFA is on: `next`, unless it points back at setup. */
export function routeAfterEnrolment(next: string | null): string {
  if (!next || next === "/mfa" || next.startsWith("/mfa/") || next.startsWith("/mfa?")) {
    return DEFAULT_AFTER_LOGIN;
  }
  return next;
}

/** `path`, carrying `?next=` when there is somewhere other than the default to go. */
export function withNext(path: string, next: string | null): string {
  if (!next || next === DEFAULT_AFTER_LOGIN) return path;
  return `${path}?${new URLSearchParams({ next }).toString()}`;
}

/** The `code` of a structured API error detail, e.g. `{detail: {code: "mfa_enrollment_required"}}`. */
export function apiErrorCode(body: string): string | null {
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    const detail = parsed.detail;
    if (detail && typeof detail === "object" && "code" in detail) {
      const code = (detail as { code: unknown }).code;
      return typeof code === "string" ? code : null;
    }
  } catch {
    // not JSON
  }
  return null;
}
