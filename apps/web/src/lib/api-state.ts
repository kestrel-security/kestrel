// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { ApiError } from "@/lib/api";

/**
 * Telling "the API is down" apart from "the API is up but Kestrel has not been
 * set up". Both used to be a 503 here -- request() threw ApiError(503) for a
 * network failure -- so an unreachable API showed the "run kestrel init"
 * first-run screen, sending operators of a working install to re-initialise.
 */

/** `ApiError.code` for a request that never got an HTTP answer. */
export const API_UNREACHABLE = "api_unreachable";

/** Status for that error: the gateway (this server) could not reach upstream. */
export const API_UNREACHABLE_STATUS = 502;

export function isApiUnreachable(err: unknown): boolean {
  return err instanceof ApiError && err.code === API_UNREACHABLE;
}

function apiDetail(err: ApiError): string | null {
  try {
    const detail = (JSON.parse(err.message) as { detail?: unknown } | null)?.detail;
    return typeof detail === "string" ? detail : null;
  } catch {
    return null;
  }
}

/**
 * The API's own first-run answer: a 503 whose detail points at `kestrel init`
 * ("No organization configured yet -- run `kestrel init` first.", or the
 * not-migrated database variant). Other 503s -- a worker that cannot enqueue,
 * a degraded dependency -- are not this.
 */
export function isNotInitialized(err: unknown): boolean {
  if (!(err instanceof ApiError) || err.status !== 503 || err.code) return false;
  const detail = apiDetail(err);
  return detail !== null && /kestrel init/i.test(detail);
}
