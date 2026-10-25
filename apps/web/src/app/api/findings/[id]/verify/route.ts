// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/constants";
import { isUuid } from "@/lib/route-params";
import { apiUrl, forwardedForHeader } from "@/lib/api";

/** Proxies `POST /findings/{id}/verify` for the remediation re-check button. */
export async function POST(
  request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  // Interpolated into the upstream path: anything but a UUID could retarget it.
  if (!isUuid(id)) {
    return NextResponse.json({ detail: "not found" }, { status: 404 });
  }
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;
  if (!token) {
    return NextResponse.json({ detail: "Unauthorized" }, { status: 401 });
  }

  const body = await request.text();
  // Forward the browser's Origin so the API's OriginCheckMiddleware sees the
  // real caller; this handler authenticates by cookie, unlike Server Actions,
  // which get Next's own origin check.
  const origin = request.headers.get("origin");
  const response = await fetch(apiUrl(`/findings/${encodeURIComponent(id)}/verify`), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`, ...(await forwardedForHeader()),
      "Content-Type": "application/json",
      ...(origin ? { Origin: origin } : {}),
    },
    body: body || "{}",
    cache: "no-store",
  });

  const text = await response.text();
  return new NextResponse(text, {
    status: response.status,
    headers: { "Content-Type": response.headers.get("Content-Type") || "application/json" },
  });
}
