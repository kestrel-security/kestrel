// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use server";

import { revalidatePath } from "next/cache";

import { ApiError, api, segment } from "@/lib/api";
import { formatActionError } from "@/lib/action-error";
import type { ConnectorProbeResult, ConnectorRun } from "@/lib/types";

export async function triggerConnectorSync(
  connectorInstanceId: string,
): Promise<{ ok: true; taskId: string | null } | { ok: false; error: string; alreadyRunning: boolean }> {
  try {
    const result = await api.post<{ task_id?: string }>(`/connector-instances/${segment(connectorInstanceId)}/sync`);
    revalidatePath("/connectors");
    revalidatePath(`/connectors/${connectorInstanceId}`);
    return { ok: true, taskId: result?.task_id ?? null };
  } catch (err) {
    const alreadyRunning = err instanceof ApiError && err.status === 409;
    return {
      ok: false,
      alreadyRunning,
      error: alreadyRunning ? "A sync is already running for this integration." : formatActionError(err),
    };
  }
}

/**
 * Latest run for an instance, for the Sync-now poll. Throws only Next's own
 * redirect (expired session, MFA enrolment); `stop` marks an answer that will
 * not change on retry (no access, instance gone), so the poll gives up.
 */
export async function fetchLatestConnectorRun(
  connectorInstanceId: string,
): Promise<{ ok: true; run: ConnectorRun | null } | { ok: false; error: string; stop: boolean }> {
  try {
    const runs = await api.get<ConnectorRun[]>(`/connector-instances/${segment(connectorInstanceId)}/runs?limit=1`);
    return { ok: true, run: runs[0] ?? null };
  } catch (err) {
    const error = formatActionError(err);
    const stop = err instanceof ApiError && [401, 403, 404].includes(err.status);
    return { ok: false, error, stop };
  }
}

export async function testConnectorConnection(
  connectorInstanceId: string,
): Promise<
  | {
      ok: true;
      result: {
        ok: boolean;
        healthy: boolean;
        message: string;
        sync_mode: string;
        auth_method: string;
      };
    }
  | { ok: false; error: string }
> {
  try {
    const result = await api.post<{
      ok: boolean;
      healthy: boolean;
      message: string;
      sync_mode: string;
      auth_method: string;
    }>(`/connector-instances/${segment(connectorInstanceId)}/test-connection`);
    revalidatePath(`/connectors/${connectorInstanceId}`);
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

/** Test unsaved connector credentials from the wizard. Never persists anything. */
export async function probeConnectorConfig(input: {
  connector_name: string;
  auth_method: string;
  sync_mode: string;
  config: Record<string, unknown>;
  secrets: Record<string, string>;
}): Promise<{ ok: true; result: ConnectorProbeResult } | { ok: false; error: string }> {
  try {
    const result = await api.post<ConnectorProbeResult>("/connectors/probe", input);
    return { ok: true, result };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function createConnectorInstance(input: {
  connector_name: string;
  display_name: string;
  external_tenant_ref: string;
  config: Record<string, unknown>;
  auth_method: string;
  sync_mode: string;
  schedule_cron: string | null;
  secrets?: Record<string, string>;
}): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  try {
    const created = await api.post<{ id: string }>("/connector-instances", input);
    revalidatePath("/connectors");
    revalidatePath("/inventory");
    if (created.id) revalidatePath(`/connectors/${created.id}`);
    return { ok: true, id: created.id };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function deleteConnectorInstance(
  connectorInstanceId: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.delete(`/connector-instances/${segment(connectorInstanceId)}`);
    revalidatePath("/connectors");
    revalidatePath("/connectors/health");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function updateConnectorInstance(
  connectorInstanceId: string,
  input: {
    config?: Record<string, unknown>;
    sync_mode?: string;
    auth_method?: string;
    display_name?: string;
    // Sent with a URL/host change: the API clears stored secrets when the
    // endpoint changes and keeps only what arrives in the same request.
    secrets?: Record<string, string>;
  },
): Promise<{ ok: true; secretsCleared: string[] } | { ok: false; error: string }> {
  try {
    const result = await api.patch<{ secrets_cleared?: string[] }>(
      `/connector-instances/${segment(connectorInstanceId)}`,
      input,
    );
    revalidatePath("/connectors");
    revalidatePath(`/connectors/${connectorInstanceId}`);
    return { ok: true, secretsCleared: result?.secrets_cleared ?? [] };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function upsertConnectorSecrets(
  connectorInstanceId: string,
  secrets: Record<string, string>,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.put(`/connector-instances/${segment(connectorInstanceId)}/secrets`, { secrets });
    revalidatePath("/connectors");
    revalidatePath(`/connectors/${connectorInstanceId}`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}

export async function updateConnectorSchedule(
  connectorInstanceId: string,
  scheduleCron: string | null,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await api.patch(`/connector-instances/${segment(connectorInstanceId)}/schedule`, {
      schedule_cron: scheduleCron,
    });
    revalidatePath("/connectors");
    return { ok: true };
  } catch (err) {
    return { ok: false, error: formatActionError(err) };
  }
}
