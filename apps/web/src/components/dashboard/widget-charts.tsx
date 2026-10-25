// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import type { ReactElement, ReactNode } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  chartDotClassFor,
  chartFillClassFor,
  formatChartCategory,
  inferChartKind,
} from "@/lib/chart-colors";
import { cn } from "@/lib/utils";

export type SeriesPoint = { name: string; value: number };

const tooltipStyle = {
  backgroundColor: "hsl(var(--popover))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 8,
  fontSize: 12,
  color: "hsl(var(--popover-foreground))",
};

const axisTick = { fontSize: 11, fill: "hsl(var(--muted-foreground))" };

export { KpiTile } from "@/components/dashboard/kpi-tile";

type ChartSizeProps = {
  /** Fixed pixel height for catalog previews; omit to fill the widget card. */
  height?: number;
};

function ChartFrame({
  children,
  height,
  className,
  label,
}: {
  children: ReactNode;
  height?: number;
  className?: string;
  label: string;
}) {
  if (height != null) {
    return (
      <div role="img" aria-label={label} className={cn("relative", className)} style={{ height }}>
        {children}
      </div>
    );
  }
  return (
    <div role="img" aria-label={label} className={cn("relative h-full min-h-[120px]", className)}>
      {children}
    </div>
  );
}

function SizedResponsiveContainer({
  children,
  height,
}: {
  children: ReactElement;
  height?: number;
}) {
  if (height != null) {
    return (
      <ResponsiveContainer width="100%" height={height}>
        {children}
      </ResponsiveContainer>
    );
  }
  return (
    <div className="absolute inset-0">
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}

export function DashboardBarChart({
  series,
  height,
}: {
  series: SeriesPoint[];
} & ChartSizeProps) {
  const kind = inferChartKind(series);
  const data = series.map((s) => ({
    ...s,
    label: formatChartCategory(s.name),
  }));

  if (!data.length) return <ChartEmpty height={height} />;

  return (
    <ChartFrame label="Bar chart" height={height}>
      <ChartSummary series={series} />
      <SizedResponsiveContainer height={height}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 4, right: 12, left: 4, bottom: 4 }}
        >
          <CartesianGrid stroke="hsl(var(--chart-grid))" horizontal={false} />
          <XAxis
            type="number"
            allowDecimals={false}
            tick={axisTick}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="label"
            width={72}
            tick={axisTick}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={tooltipStyle}
            cursor={{ fill: "hsl(var(--muted))", opacity: 0.4 }}
            formatter={(value: number) => [value, "Count"]}
            labelFormatter={(_, payload) =>
              payload?.[0]?.payload?.label ?? ""
            }
          />
          <Bar dataKey="value" radius={[0, 3, 3, 0]} maxBarSize={18}>
            {data.map((s) => (
              <Cell key={s.name} className={chartFillClassFor(s.name, kind)} />
            ))}
          </Bar>
        </BarChart>
      </SizedResponsiveContainer>
    </ChartFrame>
  );
}

function ChartLegend({
  series,
  kind,
}: {
  series: SeriesPoint[];
  kind: ReturnType<typeof inferChartKind>;
}) {
  return (
    <ul className="flex flex-wrap gap-x-3 gap-y-1.5 px-1 pt-2" aria-hidden>
      {series.map((s) => (
        <li key={s.name} className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <span
            className={cn("size-2 shrink-0 rounded-full", chartDotClassFor(s.name, kind))}
          />
          <span>{formatChartCategory(s.name)}</span>
        </li>
      ))}
    </ul>
  );
}

export function DashboardPieChart({
  series,
  donut = false,
  height,
}: {
  series: SeriesPoint[];
  donut?: boolean;
} & ChartSizeProps) {
  const kind = inferChartKind(series);
  const visible = series.filter((s) => s.value > 0);

  if (!visible.length) return <ChartEmpty height={height} />;

  const total = visible.reduce((a, s) => a + s.value, 0);

  return (
    <ChartFrame label={donut ? "Donut chart" : "Pie chart"} height={height}>
      <ChartSummary series={visible} />
      <div
        className={cn(
          "flex flex-col",
          height == null ? "absolute inset-0" : "h-full",
        )}
      >
        <div className="relative min-h-0 flex-1">
          <SizedResponsiveContainer height={height != null ? Math.max(100, (height ?? 220) - 40) : undefined}>
            <PieChart margin={{ top: 4, right: 4, left: 4, bottom: 4 }}>
              <Pie
                data={visible}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={donut ? "52%" : 0}
                outerRadius="78%"
                paddingAngle={1}
                stroke="hsl(var(--card))"
                strokeWidth={2}
              >
                {visible.map((s) => (
                  <Cell key={s.name} className={chartFillClassFor(s.name, kind)} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={tooltipStyle}
                formatter={(value: number, name: string) => [
                  value,
                  formatChartCategory(String(name)),
                ]}
              />
            </PieChart>
          </SizedResponsiveContainer>
          {donut ? (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <p className="text-2xl font-semibold tabular-nums">{total}</p>
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Total</p>
              </div>
            </div>
          ) : null}
        </div>
        <ChartLegend series={visible} kind={kind} />
      </div>
    </ChartFrame>
  );
}

export function DashboardLineChart({
  series,
  height,
}: {
  series: { name: string; value: number }[];
} & ChartSizeProps) {
  if (!series.length) {
    return <ChartEmpty message="No trend data in this range" height={height} />;
  }
  return (
    <ChartFrame label="Line chart" height={height}>
      <ChartSummary series={series} />
      <SizedResponsiveContainer height={height}>
        <LineChart data={series} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="hsl(var(--chart-grid))" vertical={false} />
          <XAxis dataKey="name" tick={axisTick} axisLine={false} tickLine={false} />
          <YAxis
            allowDecimals={false}
            tick={axisTick}
            axisLine={false}
            tickLine={false}
            width={32}
          />
          <Tooltip contentStyle={tooltipStyle} />
          <Line
            type="monotone"
            dataKey="value"
            stroke="hsl(var(--primary))"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
          />
        </LineChart>
      </SizedResponsiveContainer>
    </ChartFrame>
  );
}

export function DashboardAreaChart({
  series,
  height,
}: {
  series: { name: string; value: number }[];
} & ChartSizeProps) {
  if (!series.length) {
    return <ChartEmpty message="No trend data in this range" height={height} />;
  }
  return (
    <ChartFrame label="Area chart" height={height}>
      <ChartSummary series={series} />
      <SizedResponsiveContainer height={height}>
        <AreaChart data={series} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="hsl(var(--chart-grid))" vertical={false} />
          <XAxis dataKey="name" tick={axisTick} axisLine={false} tickLine={false} />
          <YAxis
            allowDecimals={false}
            tick={axisTick}
            axisLine={false}
            tickLine={false}
            width={32}
          />
          <Tooltip contentStyle={tooltipStyle} />
          <Area
            type="monotone"
            dataKey="value"
            stroke="hsl(var(--primary))"
            fill="hsl(var(--primary) / 0.15)"
            strokeWidth={2}
          />
        </AreaChart>
      </SizedResponsiveContainer>
    </ChartFrame>
  );
}

/** Screen-reader-only text alternative for a chart — recharts SVGs aren't otherwise announced. */
function ChartSummary({ series }: { series: { name: string; value: number }[] }) {
  return (
    <span className="sr-only">
      {series.map((s) => `${formatChartCategory(s.name)}: ${s.value}`).join(", ")}
    </span>
  );
}

function ChartEmpty({
  message = "No data in this range",
  height,
}: {
  message?: string;
  height?: number;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-center rounded-md border border-dashed border-border text-sm text-muted-foreground",
        height != null ? "" : "h-full min-h-[120px]",
      )}
      style={height != null ? { height } : undefined}
    >
      {message}
    </div>
  );
}
