// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { redirect, unstable_rethrow } from "next/navigation";

import { formatActionError } from "@/lib/action-error";
import { ApiError, api } from "@/lib/api";
import { isNotInitialized } from "@/lib/api-state";
import { SESSION_COOKIE_NAME } from "@/lib/constants";
import { DEFAULT_AFTER_LOGIN, safeNextPath } from "@/lib/login-redirect";
import {
  MFA_CHALLENGE_COOKIE_NAME,
  MFA_CHALLENGE_MAX_AGE_SECONDS,
  type LoginResult,
  apiErrorCode,
  normalizeMfaCode,
  routeAfterEnrolment,
  routeAfterLogin,
} from "@/lib/mfa";
import { sessionCookieSecure } from "@/lib/session-cookie";
import type { MfaSetup } from "@/lib/types";

// Matches the server's absolute session lifetime (kestrel/src/kestrel/auth/service.py's
// SESSION_ABSOLUTE_LIFETIME) -- the cookie itself can safely outlive that,
// since the server-side session row is what actually expires/revokes.
const SESSION_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;

type ActionResult<T = object> = ({ ok: true } & T) | { ok: false; error: string };

function loginRetryPath(error: string, next: string | null): string {
  const query = new URLSearchParams({ error });
  if (next) query.set("next", next);
  return `/login?${query.toString()}`;
}

async function setSessionCookie(token: string) {
  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: sessionCookieSecure(process.env),
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_COOKIE_MAX_AGE_SECONDS,
  });
}

export async function login(formData: FormData) {
  const email = formData.get("email") as string;
  const password = formData.get("password") as string;
  // Where the proxy or a 401 interrupted the operator; sanitised again
  // here because the form field is as attacker-controlled as the query string.
  const next = safeNextPath(formData.get("next"));

  let result: LoginResult;
  try {
    result = await api.post<LoginResult>("/auth/login", { email, password });
  } catch (error) {
    unstable_rethrow(error);
    if (error instanceof ApiError && error.status === 401) {
      redirect(loginRetryPath("1", next));
    }
    // A fresh deployment has no Organization until `kestrel init` runs. That's
    // an expected first-run state, not a crash -- rethrowing gave the very
    // first screen a new user sees a stack-trace error page. Only the API's
    // own answer says so; an unreachable API is "unavailable" below.
    if (isNotInitialized(error)) {
      redirect(loginRetryPath("not-initialized", next));
    }
    if (error instanceof ApiError && error.status === 429) {
      redirect(loginRetryPath("rate-limited", next));
    }
    // API down, a 5xx, an unexpected 4xx: say so on the sign-in form rather
    // than throwing the first screen into an error page.
    console.error("Sign-in failed:", error instanceof Error ? error.message : error);
    redirect(loginRetryPath("unavailable", next));
  }

  const cookieStore = await cookies();
  if (result.mfa_required) {
    // A challenge token, good for five minutes and for POST /auth/login/mfa
    // only. It lives in its own cookie so it is never sent as a session.
    cookieStore.set(MFA_CHALLENGE_COOKIE_NAME, result.token, {
      httpOnly: true,
      secure: sessionCookieSecure(process.env),
      sameSite: "lax",
      path: "/",
      maxAge: MFA_CHALLENGE_MAX_AGE_SECONDS,
    });
  } else {
    // A full session, or one limited to enrolment (/mfa/setup upgrades it).
    cookieStore.delete(MFA_CHALLENGE_COOKIE_NAME);
    await setSessionCookie(result.token);
  }

  redirect(routeAfterLogin(result, next));
}

/**
 * Finish a sign-in with the second factor. A wrong code (400) leaves the
 * challenge usable and comes back as an error; a spent or expired one (401)
 * starts over at /login.
 */
export async function verifyMfaCode(input: { code: string; next?: string | null }): Promise<ActionResult> {
  const next = safeNextPath(input.next);
  const normalized = normalizeMfaCode(input.code);
  if (!normalized) {
    return { ok: false, error: "Enter the 6-digit code from your app, or a recovery code." };
  }

  const cookieStore = await cookies();
  const challenge = cookieStore.get(MFA_CHALLENGE_COOKIE_NAME)?.value;
  if (!challenge) {
    redirect(loginRetryPath("mfa-expired", next));
  }

  let token: string;
  try {
    const result = await api.postWithToken<LoginResult>("/auth/login/mfa", challenge, {
      code: normalized.code,
    });
    token = result.token;
  } catch (err) {
    if (err instanceof ApiError && err.status === 400 && apiErrorCode(err.message) === "code_already_used") {
      return { ok: false, error: "That code was just used. Wait for the next code from your app." };
    }
    if (err instanceof ApiError && err.status === 400) {
      return {
        ok: false,
        error:
          normalized.kind === "recovery"
            ? "That recovery code is not valid, or it has already been used."
            : "That code is not valid. Check your authenticator app and try again.",
      };
    }
    if (err instanceof ApiError && err.status === 429 && apiErrorCode(err.message) === "account_locked") {
      // The challenge is gone; the account unlocks after the lockout window.
      cookieStore.delete(MFA_CHALLENGE_COOKIE_NAME);
      redirect(loginRetryPath("locked", next));
    }
    if (err instanceof ApiError && err.status === 429) {
      return { ok: false, error: "Too many sign-in attempts. Wait a minute and try again." };
    }
    // 401: five wrong codes or past five minutes. 403: the cookie held
    // something other than a challenge. Either way, sign in again.
    if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
      cookieStore.delete(MFA_CHALLENGE_COOKIE_NAME);
      redirect(loginRetryPath("mfa-expired", next));
    }
    return { ok: false, error: formatActionError(err) };
  }

  cookieStore.delete(MFA_CHALLENGE_COOKIE_NAME);
  await setSessionCookie(token);
  redirect(next ?? DEFAULT_AFTER_LOGIN);
}

export async function logout() {
  try {
    await api.post("/auth/logout");
  } catch {
    // Best-effort: even if the server-side session is already gone (e.g.
    // already expired), still clear the browser's cookie below.
  }
  const cookieStore = await cookies();
  cookieStore.delete(SESSION_COOKIE_NAME);
  cookieStore.delete(MFA_CHALLENGE_COOKIE_NAME);
  redirect("/login");
}

/**
 * Replace the caller's password. The API keeps this session and revokes every
 * other one; API tokens are unaffected. A wrong current password is a 400.
 */
export async function changePassword(input: {
  currentPassword: string;
  newPassword: string;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post("/auth/change-password", {
      old_password: input.currentPassword,
      new_password: input.newPassword,
    });
    return { ok: true };
  } catch (err) {
    if (err instanceof ApiError && err.status === 400) {
      return { ok: false, error: "Your current password is incorrect." };
    }
    return { ok: false, error: formatActionError(err) };
  }
}

/** Start (or restart) enrolment: a new secret, not in force until activated. */
export async function startMfaSetup(): Promise<ActionResult<{ setup: MfaSetup }>> {
  try {
    const setup = await api.post<MfaSetup>("/auth/mfa/setup");
    return { ok: true, setup };
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) {
      return { ok: false, error: "Two-factor authentication is already on." };
    }
    return { ok: false, error: formatActionError(err) };
  }
}

/**
 * Turn MFA on with a first code. Returns the recovery codes (shown once) and
 * where to continue. A session that was limited to enrolment comes back as
 * a full one, which replaces the cookie here.
 */
export async function activateMfa(input: {
  code: string;
  next?: string | null;
}): Promise<ActionResult<{ recoveryCodes: string[]; continueTo: string }>> {
  const normalized = normalizeMfaCode(input.code);
  if (!normalized || normalized.kind !== "totp") {
    return { ok: false, error: "Enter the 6-digit code your authenticator app shows." };
  }
  let result: { recovery_codes: string[]; token: string | null };
  try {
    result = await api.post("/auth/mfa/activate", { code: normalized.code });
  } catch (err) {
    if (err instanceof ApiError && err.status === 400) {
      return {
        ok: false,
        error: "That code didn't match. Check the time on your device and try the current code.",
      };
    }
    return { ok: false, error: formatActionError(err) };
  }
  if (result.token) {
    await setSessionCookie(result.token);
  }
  revalidatePath("/settings/account");
  return {
    ok: true,
    recoveryCodes: result.recovery_codes,
    continueTo: routeAfterEnrolment(safeNextPath(input.next)),
  };
}

/** Turn MFA off. Needs the password and a current code. */
export async function disableMfa(input: { password: string; code: string }): Promise<ActionResult> {
  const normalized = normalizeMfaCode(input.code);
  if (!normalized) {
    return { ok: false, error: "Enter the 6-digit code from your app, or a recovery code." };
  }
  try {
    await api.post("/auth/mfa/disable", { password: input.password, code: normalized.code });
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
  revalidatePath("/settings/account");
  return { ok: true };
}

/** Replace every recovery code. The new ones are shown once. */
export async function regenerateRecoveryCodes(input: {
  code: string;
}): Promise<ActionResult<{ recoveryCodes: string[] }>> {
  const normalized = normalizeMfaCode(input.code);
  if (!normalized) {
    return { ok: false, error: "Enter the 6-digit code from your app, or a recovery code." };
  }
  try {
    const result = await api.post<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", {
      code: normalized.code,
    });
    revalidatePath("/settings/account");
    return { ok: true, recoveryCodes: result.recovery_codes };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
