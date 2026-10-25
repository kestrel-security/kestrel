// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

import { SESSION_COOKIE_NAME } from "@/lib/constants";
import { apiUrl, forwardedForHeader, loginRedirectUrl } from "@/lib/api";

/** Proxies `GET /audit-log/export` for browser download (admin-only upstream). */
export async function GET(request: NextRequest) {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;
  if (!token) {
    return NextResponse.redirect(loginRedirectUrl(request));
  }

  const upstream = new URLSearchParams(request.nextUrl.searchParams);
  if (!upstream.get("format")) upstream.set("format", "csv");

  const response = await fetch(apiUrl(`/audit-log/export?${upstream}`), {
    headers: { Authorization: `Bearer ${token}`, ...(await forwardedForHeader()) },
    cache: "no-store",
  });

  if (response.status === 401) {
    return NextResponse.redirect(loginRedirectUrl(request));
  }
  if (!response.ok) {
    const body = await response.text();
    return new NextResponse(body || response.statusText, { status: response.status });
  }

  const headers = new Headers();
  const contentType = response.headers.get("Content-Type");
  const disposition = response.headers.get("Content-Disposition");
  if (contentType) headers.set("Content-Type", contentType);
  if (disposition) headers.set("Content-Disposition", disposition);

  return new NextResponse(await response.arrayBuffer(), { status: 200, headers });
}
