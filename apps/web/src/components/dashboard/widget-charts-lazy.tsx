// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import dynamic from "next/dynamic";

import { Skeleton } from "@/components/ui/skeleton";

function ChartSkeleton() {
  return <Skeleton className="h-full min-h-[120px] w-full" />;
}

export const DashboardBarChart = dynamic(
  () => import("@/components/dashboard/widget-charts").then((m) => m.DashboardBarChart),
  { ssr: false, loading: () => <ChartSkeleton /> },
);

export const DashboardPieChart = dynamic(
  () => import("@/components/dashboard/widget-charts").then((m) => m.DashboardPieChart),
  { ssr: false, loading: () => <ChartSkeleton /> },
);

export const DashboardLineChart = dynamic(
  () => import("@/components/dashboard/widget-charts").then((m) => m.DashboardLineChart),
  { ssr: false, loading: () => <ChartSkeleton /> },
);

export const DashboardAreaChart = dynamic(
  () => import("@/components/dashboard/widget-charts").then((m) => m.DashboardAreaChart),
  { ssr: false, loading: () => <ChartSkeleton /> },
);
