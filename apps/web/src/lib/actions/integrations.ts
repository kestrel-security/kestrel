// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";

import { api, segment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";

export async function createWebhook(input: {
  name: string;
  url: string;
  events: string[];
  description: string | null;
}): Promise<{ ok: true; id: string; signing_secret: string } | { ok: false; error: string }> {
  if (input.events.length === 0) {
    return { ok: false, error: "Select at least one event" };
  }
  try {
    const created = await api.post<{ id: string; signing_secret: string }>("/webhooks", input);
    revalidatePath("/settings/webhooks");
    return { ok: true, id: created.id, signing_secret: created.signing_secret };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function setWebhookEnabled(
  webhookId: string,
  isEnabled: boolean,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.patch(`/webhooks/${segment(webhookId)}`, { is_enabled: isEnabled });
    revalidatePath("/settings/webhooks");
    revalidatePath(`/settings/webhooks/${webhookId}`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function rotateWebhookSecret(
  webhookId: string,
): Promise<{ ok: true; signing_secret: string } | { ok: false; error: string }> {
  try {
    const result = await api.post<{ signing_secret: string }>(`/webhooks/${segment(webhookId)}/rotate-secret`);
    revalidatePath("/settings/webhooks");
    revalidatePath(`/settings/webhooks/${webhookId}`);
    return { ok: true, signing_secret: result.signing_secret };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function deleteWebhook(
  webhookId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.delete(`/webhooks/${segment(webhookId)}`);
    revalidatePath("/settings/webhooks");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function createTicketIntegration(input: {
  name: string;
  provider: string;
  api_token: string;
  config: Record<string, unknown>;
  description: string | null;
}): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  try {
    const created = await api.post<{ id: string }>("/ticket-integrations", input);
    revalidatePath("/settings/ticketing");
    return { ok: true, id: created.id };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function setTicketIntegrationEnabled(
  integrationId: string,
  isEnabled: boolean,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.patch(`/ticket-integrations/${segment(integrationId)}`, { is_enabled: isEnabled });
    revalidatePath("/settings/ticketing");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function deleteTicketIntegration(
  integrationId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.delete(`/ticket-integrations/${segment(integrationId)}`);
    revalidatePath("/settings/ticketing");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function rotateTicketIntegrationToken(
  integrationId: string,
  apiToken: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post(`/ticket-integrations/${segment(integrationId)}/rotate-token`, {
      api_token: apiToken,
    });
    revalidatePath("/settings/ticketing");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function retryWebhookDelivery(
  webhookId: string,
  deliveryId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.post(`/webhooks/${segment(webhookId)}/deliveries/${segment(deliveryId)}/retry`);
    revalidatePath("/settings/webhooks");
    revalidatePath(`/settings/webhooks/${webhookId}`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
