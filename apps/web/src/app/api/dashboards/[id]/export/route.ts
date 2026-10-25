// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/constants";
import { dashboardExportFormat, isUuid } from "@/lib/route-params";
import { apiUrl, forwardedForHeader } from "@/lib/api";

/** Proxy dashboard export so the browser can download PDF/CSV/JSON. */
export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const format = dashboardExportFormat(request.nextUrl.searchParams.get("format"));
  if (!isUuid(id) || format === null) {
    return NextResponse.json({ detail: "not found" }, { status: 404 });
  }
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;
  if (!token) {
    return NextResponse.json({ detail: "unauthorized" }, { status: 401 });
  }
  const res = await fetch(
    apiUrl(`/dashboards/${id}/export?format=${format}`),
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, ...(await forwardedForHeader()) },
      cache: "no-store",
    },
  );
  if (!res.ok) {
    const body = await res.text();
    return NextResponse.json({ detail: body || res.statusText }, { status: res.status });
  }
  const buf = await res.arrayBuffer();
  const disposition = res.headers.get("Content-Disposition") || `attachment; filename="dashboard.${format}"`;
  return new NextResponse(buf, {
    status: 200,
    headers: {
      "Content-Type": res.headers.get("Content-Type") || "application/octet-stream",
      "Content-Disposition": disposition,
    },
  });
}
