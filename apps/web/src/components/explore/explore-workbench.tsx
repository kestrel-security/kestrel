// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useMemo, useRef, useState, useTransition } from "react";

import { ExploreGraphCanvas } from "@/components/explore/explore-graph-canvas";
import { ExploreNodeGlyph } from "@/components/explore/explore-node-silhouettes";
import { ExplorePathCard } from "@/components/explore/explore-path-card";
import { ExploreSearch } from "@/components/explore/explore-search";
import { AppMark, AppMarkStack } from "@/components/brand/app-mark";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { FilterChip } from "@/components/ui/filter-chip";
import { fetchGraphEdgeContext, fetchGraphNodeContext } from "@/lib/actions/explore";
import { resolveAppMark } from "@/lib/app-mark";
import {
  compactEdgeLabel,
  type GraphLabelMode,
} from "@/lib/graph-edge-label";
import { defaultExploreDirection, type GraphLayoutMode } from "@/lib/graph-layout";
import {
  ACCESS_PATH_META,
  KNOWN_NODE_TYPES,
  NODE_TYPE_META,
  accessPathMeta,
  nodeTypeMeta,
} from "@/lib/graph-style";
import type {
  GraphEdge,
  GraphEdgeContext,
  GraphNeighborsResponse,
  GraphNode,
  GraphNodeContext,
  GraphReachabilityPath,
  GraphReachabilityResponse,
} from "@/lib/types";
import { countOf } from "@/lib/plural";

const FILTER_NODE_TYPES = [
  "identity",
  "group",
  "role",
  "oauth_application",
  "resource",
] as const;

const FILTER_ACCESS_PATHS = [
  "direct",
  "inherited_group",
  "inherited_role",
  "oauth_derived",
  "federated",
] as const;

const NODE_TYPE_GROUP_ORDER = [
  "role",
  "oauth_application",
  "resource",
  "group",
  "permission",
  "identity",
  "application",
  "setting",
] as const;

function buildHref(params: Record<string, string | undefined>) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v) q.set(k, v);
  }
  return `/explore?${q.toString()}`;
}

function toggleCsv(current: string | undefined, token: string): string | undefined {
  const set = new Set(
    (current || "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
  );
  if (set.has(token)) set.delete(token);
  else set.add(token);
  if (set.size === 0) return undefined;
  return Array.from(set).sort().join(",");
}

function formatMaybeDate(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function propString(props: Record<string, unknown> | undefined, key: string): string | null {
  const v = props?.[key];
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

function propBool(props: Record<string, unknown> | undefined, key: string): boolean | null {
  const v = props?.[key];
  return typeof v === "boolean" ? v : null;
}

function scopesFromProps(
  props: Record<string, unknown> | undefined,
): { name: string; is_sensitive: boolean }[] {
  const raw = props?.scopes;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((s): s is { name: string; is_sensitive?: boolean } => Boolean(s && typeof s === "object"))
    .map((s) => ({
      name: String((s as { name?: unknown }).name ?? ""),
      is_sensitive: Boolean((s as { is_sensitive?: unknown }).is_sensitive),
    }))
    .filter((s) => s.name);
}

function groupPaths(
  paths: GraphReachabilityPath[],
): { type: string; paths: GraphReachabilityPath[] }[] {
  const buckets = new Map<string, GraphReachabilityPath[]>();
  for (const path of paths) {
    const t = path.destination.node_type;
    const list = buckets.get(t) ?? [];
    list.push(path);
    buckets.set(t, list);
  }
  const ordered: { type: string; paths: GraphReachabilityPath[] }[] = [];
  for (const type of NODE_TYPE_GROUP_ORDER) {
    const list = buckets.get(type);
    if (list?.length) ordered.push({ type, paths: list });
    buckets.delete(type);
  }
  for (const [type, list] of buckets) {
    if (list.length) ordered.push({ type, paths: list });
  }
  return ordered;
}

export function ExploreWorkbench({
  focus,
  focusType,
  direction,
  depth,
  layout,
  labelMode,
  nodeTypes,
  accessPaths,
  start,
  neighbors,
  reach,
  initialContext,
  suggestions,
}: {
  focus?: string;
  focusType?: string;
  direction: "out" | "in" | "both";
  depth: number;
  layout: GraphLayoutMode;
  labelMode: GraphLabelMode;
  nodeTypes?: string;
  accessPaths?: string;
  start: GraphNode | null;
  neighbors: GraphNeighborsResponse | null;
  reach: GraphReachabilityResponse | null;
  initialContext: GraphNodeContext | null;
  suggestions: {
    id: string;
    display_name: string | null;
    email: string | null;
    application_types?: string[];
    account_count?: number;
  }[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [highlightedPathKey, setHighlightedPathKey] = useState<string | null>(null);
  const [inspectNode, setInspectNode] = useState<GraphNodeContext | null>(initialContext);
  const [inspectEdge, setInspectEdge] = useState<GraphEdgeContext | null>(null);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const selectedNodeIdRef = useRef<string | null>(initialContext?.node.id ?? null);
  const selectedEdgeIdRef = useRef<string | null>(null);
  const fetchGenRef = useRef(0);

  const selectedNodeTypes = useMemo(
    () =>
      new Set(
        (nodeTypes || "")
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      ),
    [nodeTypes],
  );
  const selectedAccessPaths = useMemo(
    () =>
      new Set(
        (accessPaths || "")
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      ),
    [accessPaths],
  );

  const highlightedPath = useMemo(() => {
    if (!reach || !highlightedPathKey) return null;
    return (
      reach.paths.find(
        (p) => `${p.destination.id}-${p.hop_count}` === highlightedPathKey,
      ) ?? null
    );
  }, [reach, highlightedPathKey]);

  const graphNodes: GraphNode[] = neighbors?.nodes ?? (start ? [start] : []);
  const graphEdges: GraphEdge[] = neighbors?.edges ?? [];
  const pathGroups = useMemo(
    () => (reach ? groupPaths(reach.paths) : []),
    [reach],
  );

  function navigate(patch: Record<string, string | undefined>) {
    startTransition(() => {
      router.push(
        buildHref({
          focus,
          focus_type: focusType,
          direction,
          depth: String(depth),
          layout,
          labels: labelMode === "compact" ? undefined : labelMode,
          node_types: nodeTypes,
          access_paths: accessPaths,
          ...patch,
        }),
      );
    });
  }

  const onSelectNode = useCallback(
    async (nodeId: string | null) => {
      if (!nodeId) {
        selectedNodeIdRef.current = null;
        // Invalidate any context fetch still in flight, or it would land
        // after the clear and reopen the inspector on a deselected node.
        fetchGenRef.current += 1;
        setInspectError(null);
        setInspectNode(initialContext);
        return;
      }
      // Skip duplicate selects — a prior fitView/onSelectionChange loop re-fired
      // the same node thousands of times and tripped the API rate limit (429).
      if (selectedNodeIdRef.current === nodeId) return;
      selectedNodeIdRef.current = nodeId;
      selectedEdgeIdRef.current = null;
      setInspectEdge(null);
      setInspectError(null);
      const gen = ++fetchGenRef.current;
      const result = await fetchGraphNodeContext(nodeId);
      if (gen !== fetchGenRef.current) return;
      if (!result.ok) {
        setInspectError(result.error);
        setInspectNode(null);
        return;
      }
      setInspectNode(result.context);
    },
    [initialContext],
  );

  const onSelectEdge = useCallback(async (edgeId: string | null) => {
    if (!edgeId) {
      selectedEdgeIdRef.current = null;
      fetchGenRef.current += 1;
      setInspectEdge(null);
      return;
    }
    if (selectedEdgeIdRef.current === edgeId) return;
    selectedEdgeIdRef.current = edgeId;
    selectedNodeIdRef.current = null;
    setInspectError(null);
    const gen = ++fetchGenRef.current;
    const result = await fetchGraphEdgeContext(edgeId);
    if (gen !== fetchGenRef.current) return;
    if (!result.ok) {
      setInspectError(result.error);
      setInspectEdge(null);
      return;
    }
    setInspectEdge(result.context);
    setInspectNode(null);
  }, []);

  return (
    <div className="flex h-[calc(100vh-3.5rem)] flex-col">
      {/* Toolbar */}
      <header className="shrink-0 border-b border-border bg-card px-4 py-3">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Explore</h1>
            <p className="text-xs text-muted-foreground">
              Identity graph — who can reach what, with what permission, and how.
            </p>
          </div>
          <div
            className="flex flex-col items-end gap-2.5 text-[11px] text-muted-foreground"
            role="group"
            aria-label="Graph legend"
          >
            <div className="flex flex-col items-end gap-1">
              <p className="text-eyebrow">Node types</p>
              <div className="flex flex-wrap justify-end gap-2">
                {KNOWN_NODE_TYPES.map((id) => {
                  const meta = NODE_TYPE_META[id];
                  return (
                    <span key={id} className="inline-flex items-center gap-1">
                      <ExploreNodeGlyph meta={meta} size={14} />
                      {meta.label}
                    </span>
                  );
                })}
              </div>
            </div>
            <div className="flex flex-col items-end gap-1">
              <p className="text-eyebrow">How access flows</p>
              <div className="flex flex-wrap justify-end gap-3">
                {Object.entries(ACCESS_PATH_META).map(([id, meta]) => (
                  <span key={id} className="inline-flex items-center gap-1.5">
                    <span
                      className="inline-block h-0.5 w-5 rounded-full"
                      style={{
                        background: meta.stroke,
                        borderTop: meta.dash ? `2px dashed ${meta.stroke}` : undefined,
                        backgroundColor: meta.dash ? "transparent" : meta.stroke,
                      }}
                    />
                    {meta.label}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto]">
          <ExploreSearch depth={depth} />
          <div className="flex flex-wrap items-center gap-1.5 text-sm">
            {(
              [
                { id: "out", label: "Outbound" },
                { id: "in", label: "Inbound" },
                { id: "both", label: "Both" },
              ] as const
            ).map((opt) => (
              <FilterChip
                key={opt.id}
                label={opt.label}
                active={direction === opt.id}
                onClick={() => navigate({ direction: opt.id })}
              />
            ))}
            <span className="mx-1 text-xs text-muted-foreground">Depth</span>
            {[1, 2, 3, 4, 5, 6].map((d) => (
              <FilterChip
                key={d}
                label={String(d)}
                active={depth === d}
                onClick={() => navigate({ depth: String(d) })}
              />
            ))}
            <span className="mx-1 text-muted-foreground">·</span>
            {(
              [
                { id: "hierarchical", label: "Hierarchical" },
                { id: "free", label: "Free" },
              ] as const
            ).map((opt) => (
              <FilterChip
                key={opt.id}
                label={opt.label}
                active={layout === opt.id}
                onClick={() => navigate({ layout: opt.id })}
              />
            ))}
            <span className="mx-1 text-xs text-muted-foreground">Labels</span>
            {(
              [
                { id: "compact", label: "Compact" },
                { id: "hover", label: "Hover" },
                { id: "off", label: "Off" },
              ] as const
            ).map((opt) => (
              <FilterChip
                key={opt.id}
                label={opt.label}
                active={labelMode === opt.id}
                onClick={() =>
                  navigate({ labels: opt.id === "compact" ? undefined : opt.id })
                }
              />
            ))}
            {pending && <span className="text-xs text-muted-foreground">Updating…</span>}
          </div>
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-sm">
          <span className="text-xs text-muted-foreground">Show</span>
          {FILTER_NODE_TYPES.map((t) => (
            <FilterChip
              key={t}
              label={NODE_TYPE_META[t]?.label ?? t}
              active={selectedNodeTypes.size === 0 || selectedNodeTypes.has(t)}
              onClick={() =>
                navigate({ node_types: toggleCsv(nodeTypes, t) })
              }
            />
          ))}
          <span className="mx-1 text-muted-foreground">·</span>
          <span className="text-xs text-muted-foreground">How</span>
          {FILTER_ACCESS_PATHS.map((p) => (
            <FilterChip
              key={p}
              label={ACCESS_PATH_META[p]?.label ?? p}
              active={selectedAccessPaths.size === 0 || selectedAccessPaths.has(p)}
              onClick={() =>
                navigate({ access_paths: toggleCsv(accessPaths, p) })
              }
            />
          ))}
          {(nodeTypes || accessPaths) && (
            <button
              type="button"
              className="ml-1 text-xs text-primary underline-offset-2 hover:underline"
              onClick={() =>
                navigate({ node_types: undefined, access_paths: undefined })
              }
            >
              Clear filters
            </button>
          )}
        </div>
      </header>

      {/* Body — stacks the inspect rail below the canvas below the `lg` breakpoint so it
          doesn't get squeezed into an unusable sliver on tablet widths. */}
      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <div className="relative min-h-[50vh] min-w-0 flex-1 lg:min-h-0">
          {!start || !neighbors ? (
            <EmptyGraph suggestions={suggestions} depth={depth} />
          ) : (
            <>
              <div className="absolute left-3 top-3 z-10 flex flex-wrap gap-2">
                <Badge className="bg-card text-foreground shadow-sm">
                  {neighbors.node_count ?? graphNodes.length} nodes ·{" "}
                  {neighbors.edge_count ?? graphEdges.length} edges
                </Badge>
                {neighbors.truncated && (
                  <Badge className="bg-amber-100 text-amber-900 shadow-sm dark:bg-amber-950 dark:text-amber-200">
                    Truncated — lower depth
                  </Badge>
                )}
                {start && (
                  <Badge
                    className={`${nodeTypeMeta(start.node_type).bg} ${nodeTypeMeta(start.node_type).text} shadow-sm`}
                  >
                    Focus: {start.label}
                  </Badge>
                )}
              </div>
              <ExploreGraphCanvas
                graphNodes={graphNodes}
                graphEdges={graphEdges}
                focusNodeId={start.id}
                direction={direction}
                layout={layout}
                labelMode={labelMode}
                highlightedPath={highlightedPath}
                onSelectNode={onSelectNode}
                onSelectEdge={onSelectEdge}
              />
            </>
          )}
        </div>

        {/* Inspect + paths rail — floats structured detail above the canvas, so it
            takes the elevated surface tone rather than the base card tone. */}
        <aside className="flex max-h-[50vh] w-full shrink-0 flex-col overflow-hidden border-t border-border bg-elevated text-elevated-foreground lg:h-auto lg:max-h-none lg:w-[360px] lg:border-l lg:border-t-0">
          <InspectPanel
            inspectNode={inspectNode}
            inspectEdge={inspectEdge}
            inspectError={inspectError}
            depth={depth}
            onRefocus={(objectId, nodeType) =>
              navigate({
                focus: objectId,
                focus_type: nodeType,
                direction: defaultExploreDirection(nodeType),
              })
            }
          />
          {reach && reach.paths.length > 0 && (
            <div className="min-h-0 flex-1 overflow-auto border-t border-border">
              <div className="sticky top-0 z-10 border-b border-border bg-elevated px-3 py-2">
                <p className="text-eyebrow">
                  Access paths ({reach.total}
                  {reach.truncated ? "+" : ""})
                </p>
                <p className="text-[11px] text-muted-foreground">
                  Grouped by destination. Click to highlight; expand for hops.
                </p>
                {reach.summary && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {Object.entries(reach.summary.by_node_type).map(([t, n]) => (
                      <span
                        key={t}
                        className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
                      >
                        {(NODE_TYPE_META[t]?.label ?? t).replace(/_/g, " ")} {n}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              {pathGroups.map((group) => (
                <div key={group.type}>
                  <div className="sticky top-[4.5rem] border-b border-border bg-elevated/95 px-3 py-1.5 backdrop-blur-sm">
                    <p className="text-eyebrow">
                      {NODE_TYPE_META[group.type]?.label ?? group.type.replace(/_/g, " ")}{" "}
                      ({group.paths.length})
                    </p>
                  </div>
                  <ul className="divide-y divide-border">
                    {group.paths.map((path) => {
                      const key = `${path.destination.id}-${path.hop_count}`;
                      const active = highlightedPathKey === key;
                      const meta = accessPathMeta(path.primary_access_path);
                      return (
                        <li
                          key={key}
                          className={active ? "border-l-2 border-primary bg-primary/10" : "border-l-2 border-transparent"}
                        >
                          <button
                            type="button"
                            onClick={() =>
                              setHighlightedPathKey((cur) => (cur === key ? null : key))
                            }
                            aria-expanded={active}
                            aria-label={`${path.destination.label}, ${countOf(path.hop_count, "hop")}`}
                            className="w-full px-3 py-2.5 text-left hover:bg-muted/60"
                          >
                            <div className="flex items-center gap-2">
                              <Badge
                                className={
                                  NODE_TYPE_META[path.destination.node_type]
                                    ? `${nodeTypeMeta(path.destination.node_type).bg} ${nodeTypeMeta(path.destination.node_type).text}`
                                    : "bg-muted"
                                }
                              >
                                {path.destination.node_type.replace(/_/g, " ")}
                              </Badge>
                              {path.primary_access_path && (
                                <span className="text-[10px]" style={{ color: meta.stroke }}>
                                  {meta.label}
                                </span>
                              )}
                            </div>
                            <div className="mt-1 truncate text-sm font-medium">
                              {path.destination.label}
                            </div>
                            <div className="text-[11px] text-muted-foreground">
                              {countOf(path.hop_count, "hop")}
                              {path.hops[path.hops.length - 1] &&
                                ` · ${compactEdgeLabel(
                                  path.hops[path.hops.length - 1].edge_type,
                                  path.hops[path.hops.length - 1].properties,
                                )}`}
                            </div>
                          </button>
                          {active && start && (
                            <div className="border-t border-border bg-background px-2 py-2">
                              <ExplorePathCard
                                path={path}
                                startLabel={start.label}
                                direction={direction === "in" ? "in" : "out"}
                              />
                            </div>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function EmptyGraph({
  suggestions,
  depth,
}: {
  suggestions: {
    id: string;
    display_name: string | null;
    email: string | null;
    application_types?: string[];
    account_count?: number;
  }[];
  depth: number;
}) {
  return (
    // Scrolls rather than centring: a long suggestion list centred in a
    // fixed-height box overflows upward over the toolbar.
    <div className="flex h-full flex-col items-center overflow-y-auto p-8">
      <div className="my-auto flex w-full flex-col items-center gap-6">
        <EmptyState
          className="w-full max-w-md border-0 bg-transparent p-0"
          title="Select a starting node"
          hint="Search above, or open a privileged identity. The canvas expands their access relationships across every connected SaaS."
        />
        {suggestions.length > 0 && (
          <ul className="w-full max-w-md divide-y divide-border rounded-lg border border-border bg-card">
            {suggestions.map((identity) => {
              const apps = identity.application_types ?? [];
              return (
                <li key={identity.id}>
                  <Link
                    href={`/explore?focus=${identity.id}&focus_type=identity&direction=out&depth=${depth}&layout=hierarchical`}
                    className="flex items-center justify-between gap-3 px-4 py-3 text-sm transition-colors hover:bg-muted/50"
                  >
                    <span className="min-w-0">
                      <span className="block truncate font-medium">
                        {identity.display_name || identity.email || identity.id}
                      </span>
                      {apps.length > 0 && (
                        <span className="mt-1 flex items-center gap-1.5">
                          <AppMarkStack applicationTypes={apps} size={14} limit={4} />
                          {identity.account_count != null && identity.account_count > 1 ? (
                            <span className="text-[11px] text-muted-foreground">
                              {identity.account_count} apps
                            </span>
                          ) : null}
                        </span>
                      )}
                    </span>
                    <span className="shrink-0 text-xs text-muted-foreground">Open graph →</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function InspectPanel({
  inspectNode,
  inspectEdge,
  inspectError,
  depth,
  onRefocus,
}: {
  inspectNode: GraphNodeContext | null;
  inspectEdge: GraphEdgeContext | null;
  inspectError: string | null;
  depth: number;
  onRefocus: (objectId: string, nodeType: string) => void;
}) {
  const edgeProps = inspectEdge?.edge.properties;
  const permission = propString(edgeProps, "permission_level");
  const membership = propString(edgeProps, "membership_role");
  const scopes = scopesFromProps(edgeProps);
  const firstSeen = formatMaybeDate(inspectEdge?.edge.first_seen_at);
  const lastSeen = formatMaybeDate(inspectEdge?.edge.last_seen_at);

  const nodeProps = inspectNode?.node.properties;
  const email = propString(nodeProps, "email");
  const privileged = propBool(nodeProps, "is_privileged");
  const mfa = propBool(nodeProps, "mfa_enabled");

  return (
    <div className="max-h-[45%] shrink-0 overflow-auto border-b border-border p-3">
      <p className="mb-2 text-eyebrow">
        Inspector
      </p>
      {inspectError && (
        <p className="text-xs text-red-700 dark:text-red-300">{inspectError}</p>
      )}
      {inspectEdge && (
        <div className="space-y-2 text-sm">
          <div className="flex flex-wrap gap-1.5">
            <Badge className="bg-muted text-foreground">
              {inspectEdge.edge.edge_type.replace(/_/g, " ")}
            </Badge>
            {inspectEdge.edge.access_path && (
              <Badge className="bg-muted text-foreground">
                {inspectEdge.edge.access_path.replace(/_/g, " ")}
              </Badge>
            )}
            {permission && (
              <Badge className="bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200">
                {permission}
              </Badge>
            )}
            {membership && (
              <Badge className="bg-violet-100 text-violet-900 dark:bg-violet-950 dark:text-violet-200">
                {membership}
              </Badge>
            )}
          </div>
          <p className="leading-relaxed text-foreground">{inspectEdge.explanation}</p>
          <p className="text-xs text-muted-foreground">
            {inspectEdge.source.label} → {inspectEdge.target.label}
          </p>
          {(firstSeen || lastSeen) && (
            <p className="text-[11px] text-muted-foreground">
              {firstSeen ? `First seen ${firstSeen}` : null}
              {firstSeen && lastSeen ? " · " : null}
              {lastSeen ? `Last seen ${lastSeen}` : null}
            </p>
          )}
          {scopes.length > 0 && (
            <div className="space-y-1 border-t border-border pt-2">
              <p className="text-eyebrow">
                OAuth scopes
              </p>
              <ul className="flex flex-wrap gap-1">
                {scopes.map((s) => (
                  <li key={s.name}>
                    <Badge
                      className={
                        s.is_sensitive
                          ? "bg-fuchsia-100 text-fuchsia-950 dark:bg-fuchsia-950 dark:text-fuchsia-100"
                          : "bg-muted text-foreground"
                      }
                    >
                      {s.name}
                      {s.is_sensitive ? " · sensitive" : ""}
                    </Badge>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            <button
              type="button"
              onClick={() =>
                onRefocus(inspectEdge.source.object_id, inspectEdge.source.node_type)
              }
              className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-muted"
            >
              Refocus source
            </button>
            <button
              type="button"
              onClick={() =>
                onRefocus(inspectEdge.target.object_id, inspectEdge.target.node_type)
              }
              className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-muted"
            >
              Refocus target
            </button>
          </div>
        </div>
      )}
      {!inspectEdge && inspectNode && (
        <div className="space-y-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Badge
              className={`${nodeTypeMeta(inspectNode.node.node_type).bg} ${nodeTypeMeta(inspectNode.node.node_type).text}`}
            >
              {inspectNode.node.node_type.replace(/_/g, " ")}
            </Badge>
            {privileged === true && (
              <Badge className="bg-amber-100 text-amber-950 dark:bg-amber-950 dark:text-amber-100">
                Privileged
              </Badge>
            )}
            {inspectNode.open_finding_count > 0 && inspectNode.entity.findings_list_path && (
              <Link
                href={inspectNode.entity.findings_list_path}
                className="text-xs text-primary underline-offset-2 hover:underline"
              >
                {inspectNode.open_finding_count} open findings
              </Link>
            )}
          </div>
          <p className="text-base font-semibold">{inspectNode.node.label}</p>
          {email && <p className="text-xs text-muted-foreground">{email}</p>}
          <p className="text-xs text-muted-foreground">
            {inspectNode.neighbor_counts.outgoing} out · {inspectNode.neighbor_counts.incoming}{" "}
            in edges
            {mfa !== null ? ` · MFA ${mfa ? "on" : "off"}` : ""}
          </p>
          {inspectNode.accounts && inspectNode.accounts.length > 0 && (
            <div className="space-y-1.5 border-t border-border pt-2">
              <p className="text-eyebrow">
                Accounts
                {inspectNode.accounts.length > 1
                  ? ` · ${inspectNode.accounts.length} apps`
                  : ""}
              </p>
              <ul className="space-y-1.5">
                {inspectNode.accounts.map((acct) => (
                  <li
                    key={acct.identity_id}
                    className="rounded-md border border-border/60 bg-muted/40 px-2 py-1.5 text-xs"
                  >
                    <div className="flex flex-wrap items-center gap-1.5">
                      <AppMark
                        mark={resolveAppMark({
                          applicationType: acct.application_type,
                          label: acct.application_display_name,
                        })}
                        size={14}
                      />
                      <Badge className="bg-indigo-100 text-indigo-900 dark:bg-indigo-950 dark:text-indigo-200">
                        {(acct.application_type || "app").replace(/_/g, " ")}
                      </Badge>
                      {acct.is_disabled && (
                        <Badge className="bg-muted text-muted-foreground">Disabled</Badge>
                      )}
                      {acct.mfa_enabled !== null && (
                        <span className="text-[10px] text-muted-foreground">
                          MFA {acct.mfa_enabled ? "on" : "off"}
                        </span>
                      )}
                    </div>
                    {acct.email && (
                      <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
                        {acct.email}
                      </p>
                    )}
                    {acct.application_display_name && (
                      <p className="truncate text-[10px] text-muted-foreground">
                        {acct.application_display_name}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="flex flex-wrap gap-2 pt-1">
            <button
              type="button"
              onClick={() =>
                onRefocus(inspectNode.node.object_id, inspectNode.node.node_type)
              }
              className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-muted"
            >
              Refocus graph
            </button>
            {inspectNode.entity.detail_path && (
              <Link
                href={inspectNode.entity.detail_path}
                className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-muted"
              >
                Open entity
              </Link>
            )}
            {inspectNode.entity.findings_list_path && (
              <Link
                href={inspectNode.entity.findings_list_path}
                className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-muted"
              >
                Findings
              </Link>
            )}
          </div>
          {inspectNode.open_findings.length > 0 && (
            <ul className="mt-2 space-y-1 border-t border-border pt-2">
              {inspectNode.open_findings.slice(0, 4).map((f) => (
                <li key={f.id}>
                  <Link
                    href={`/findings/${f.id}`}
                    className="text-xs text-primary underline-offset-2 hover:underline"
                  >
                    {f.title}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {!inspectEdge && !inspectNode && !inspectError && (
        <p className="text-xs text-muted-foreground">
          Click a node or edge on the canvas. Depth {depth}.
        </p>
      )}
    </div>
  );
}
