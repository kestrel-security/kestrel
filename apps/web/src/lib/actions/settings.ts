// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";

import { api, segment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import type {
  AiSettings,
  AuditLogEntry,
  ClassificationPreview,
  ClassificationRuleInput,
  ClassificationRules,
  EmailSecurity,
  EmailSettings,
  EmailTestResult,
  OrgSecurity,
  Page,
} from "@/lib/types";

/** Next page for admin audit log. */
export async function fetchAuditLogPage(
  filters: { action?: string },
  cursor: string,
  limit: number,
): Promise<
  | { ok: true; items: AuditLogEntry[]; next_cursor: string | null }
  | { ok: false; error: string }
> {
  try {
    const query = new URLSearchParams();
    if (filters.action) query.set("action", filters.action);
    query.set("limit", String(limit));
    query.set("cursor", cursor);
    const page = await api.get<Page<AuditLogEntry>>(
      `/audit-log?${query.toString()}`,
    );
    return { ok: true, items: page.items, next_cursor: page.next_cursor };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function createOperator(input: {
  email: string;
  display_name: string | null;
  role: string;
  password: string;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post("/operators", {
      email: input.email,
      display_name: input.display_name,
      role: input.role,
      password: input.password,
    });
    revalidatePath("/settings/operators");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function setOperatorRole(
  operatorId: string,
  role: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.patch(`/operators/${segment(operatorId)}`, { role });
    revalidatePath("/settings/operators");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function setOperatorActive(
  operatorId: string,
  isActive: boolean,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.patch(`/operators/${segment(operatorId)}`, { is_active: isActive });
    revalidatePath("/settings/operators");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Admin reset: sets a temporary password and ends the operator's sessions
 * (and, by default, revokes their API tokens). */
export async function resetOperatorPassword(
  operatorId: string,
  input: { password: string; revokeApiTokens: boolean },
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post(`/operators/${segment(operatorId)}/set-password`, {
      password: input.password,
      revoke_api_tokens: input.revokeApiTokens,
    });
    revalidatePath("/settings/operators");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function saveAiSettings(input: {
  provider: string;
  model: string | null;
  base_url: string | null;
  api_key: string | null;
  is_enabled: boolean;
}): Promise<{ ok: true; result: AiSettings } | { ok: false; error: string }> {
  try {
    const result = await api.put<AiSettings>("/settings/ai", input);
    revalidatePath("/settings/ai");
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function clearAiSettings(): Promise<
  { ok: true; cleared: boolean } | { ok: false; error: string }
> {
  try {
    const result = await api.delete<{ cleared: boolean }>("/settings/ai");
    revalidatePath("/settings/ai");
    return { ok: true, cleared: result.cleared };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function saveClassificationRules(
  rules: ClassificationRuleInput[],
): Promise<{ ok: true; result: ClassificationRules } | { ok: false; error: string }> {
  try {
    const result = await api.put<ClassificationRules>("/settings/identity-classification", { rules });
    revalidatePath("/settings/identity-classification");
    revalidatePath("/identities");
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function previewClassificationRules(
  rules: ClassificationRuleInput[],
): Promise<{ ok: true; result: ClassificationPreview } | { ok: false; error: string }> {
  try {
    const result = await api.post<ClassificationPreview>("/settings/identity-classification/preview", {
      rules,
    });
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Remove another operator's authenticator (lost device). Ends their sessions. */
export async function resetOperatorMfa(
  operatorId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post(`/operators/${segment(operatorId)}/mfa/reset`);
    revalidatePath("/settings/operators");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Require (or stop requiring) two-factor authentication for every operator. */
export async function setRequireMfa(
  requireMfa: boolean,
): Promise<{ ok: true; security: OrgSecurity } | { ok: false; error: string }> {
  try {
    const security = await api.patch<OrgSecurity>("/org/security", { require_mfa: requireMfa });
    revalidatePath("/settings/operators");
    return { ok: true, security };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function saveEmailSettings(input: {
  host: string;
  port: number;
  security: EmailSecurity;
  username: string | null;
  password: string | null;
  from_address: string;
  is_enabled: boolean;
}): Promise<{ ok: true; result: EmailSettings } | { ok: false; error: string }> {
  try {
    const result = await api.put<EmailSettings>("/settings/email", input);
    revalidatePath("/settings/email");
    revalidatePath("/settings/notifications");
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function clearEmailSettings(): Promise<
  { ok: true; cleared: boolean } | { ok: false; error: string }
> {
  try {
    const result = await api.delete<{ cleared: boolean }>("/settings/email");
    revalidatePath("/settings/email");
    revalidatePath("/settings/notifications");
    return { ok: true, cleared: result.cleared };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Send a test message to the signed-in admin with the mail server in force. */
export async function sendTestEmail(): Promise<
  { ok: true; result: EmailTestResult } | { ok: false; error: string }
> {
  try {
    const result = await api.post<EmailTestResult>("/settings/email/test");
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
