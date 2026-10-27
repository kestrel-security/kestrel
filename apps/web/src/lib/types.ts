// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0

export interface Identity {
  id: string;
  identity_type: string;
  email: string | null;
  display_name: string | null;
  is_disabled: boolean;
  mfa_enabled: boolean | null;
  is_external: boolean;
  /** Graph-derived: holds at least one role marked privileged. Same
   * definition the API's `?privileged=` filter and Python policy `roles` checks use. */
  privileged: boolean;
  last_active_at?: string | null;
  /** Where `last_active_at` came from: `login`, `audit`, or `profile`
   * (a profile-updated timestamp, which is not activity). */
  last_active_source?: string | null;
  application_instance_id?: string | null;
  /** Present when the list was requested with `collapse=true`. */
  application_types?: string[];
  account_count?: number;
  explore_path?: string;
}

/** One correlated account of a person, as the cluster reports it. */
export interface IdentityClusterAccount {
  identity_id: string;
  application_type: string | null;
  application_display_name: string | null;
  email: string | null;
  display_name: string | null;
  mfa_enabled: boolean | null;
  is_disabled: boolean;
  match_kind: string;
}

export interface IdentityCluster {
  representative_identity_id: string;
  identity_ids: string[];
  member_count: number;
  application_types: string[];
  accounts: IdentityClusterAccount[];
  display_name: string | null;
  email: string | null;
}

/** Everything `/identities/{id}/overview` returns, in one round trip. */
export interface IdentityOverview {
  identity: Identity;
  application: {
    application_instance_id: string | null;
    application_instance_display_name: string | null;
    application_type: string | null;
  };
  cluster: IdentityCluster | null;
  groups: { id: string; name: string; description: string | null; identity_id: string }[];
  grants: Record<string, unknown>[];
  oauth_grants: Record<string, unknown>[];
  access_preview: {
    reachable: { id: string; node_type: string; object_id: string; label: string }[];
    truncated: boolean;
    total: number;
  };
  findings: {
    open_count?: number;
    by_severity?: Record<string, number>;
    items?: { id: string; title: string; severity: string; status: string }[];
  } | null;
  risk_factors: Record<string, unknown> | null;
  timeline: { kind?: string; at?: string | null; summary?: string }[];
  explore_path: string;
}

export interface IdentityDetail {
  identity: Identity;
  application: {
    application_instance_id: string | null;
    application_instance_display_name: string | null;
    application_type: string | null;
  };
  groups: { id: string; name: string }[];
  grants: {
    id: string;
    granted_via: string;
    permission_level: string | null;
    resource_id: string | null;
    resource_name: string | null;
    resource_type: string | null;
    role_id: string | null;
    role_name: string | null;
    role_is_privileged: boolean | null;
    source_group_id: string | null;
    source_group_name: string | null;
    application_instance_id: string | null;
    application_instance_display_name: string | null;
    application_type: string | null;
  }[];
  oauth_grants: {
    id: string;
    oauth_application_id: string;
    oauth_application_name: string | null;
    publisher: string | null;
    granted_at: string;
    last_used_at: string | null;
    application_instance_id: string | null;
    application_instance_display_name: string | null;
    application_type: string | null;
  }[];
  findings: { id: string; title: string; severity: string; status: string }[];
  /** Findings posture rollup. */
  findings_summary?: IdentityFindingsSummary | null;
  access_preview: {
    reachable: { id: string; node_type: string; object_id: string; label: string }[];
    truncated: boolean;
    total: number;
  };
  /** Labeled risk inputs for investigation. */
  risk_factors?: IdentityRiskFactors | null;
}

/** GET /identities/{id}/findings-summary. */
export interface IdentityFindingsSummary {
  kind: string;
  as_of: string;
  identity_id: string;
  total_count: number;
  open_count: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_policy: {
    policy_slug: string;
    policy_title: string | null;
    open_count: number;
    total_count: number;
    list_path: string;
  }[];
  items: {
    id: string;
    title: string;
    severity: string;
    status: string;
    policy_slug: string | null;
    policy_title: string | null;
    first_seen_at: string;
    last_seen_at: string;
    detail_path: string;
  }[];
  items_truncated: boolean;
  list_path: string;
  open_list_path: string;
  notes: string;
}

/** GET /identities/{id}/risk-factors. */
export interface IdentityRiskFactor {
  id: string;
  label: string;
  value: number;
  detail: string;
  href: string | null;
}

export interface IdentityRiskFactors {
  kind: string;
  as_of: string;
  identity_id: string;
  notes: string;
  privileged_role_count: number;
  privileged_roles: string[];
  open_finding_count: number;
  open_critical: number;
  open_high: number;
  application_type_count: number;
  peer: {
    is_outlier: boolean;
    peer_group_name?: string;
    peer_group_size?: number;
    peer_median_privileged_roles?: number;
    privileged_role_count?: number;
    excess_over_median?: number;
    explanation?: string;
  };
  factors: IdentityRiskFactor[];
  report_path: string;
  findings_list_path: string;
}

/** Full reachability from `GET /identities/{id}/access`. */
export interface IdentityAccessNode {
  id: string;
  node_type: string;
  object_id: string;
  label: string;
  properties?: Record<string, unknown>;
}

export interface IdentityAccessGroup {
  node_type: string;
  count: number;
  nodes: IdentityAccessNode[];
}

export interface IdentityAccess {
  depth: number;
  total: number;
  reachable: IdentityAccessNode[];
  groups: IdentityAccessGroup[];
}

/** Chronological identity activity from `GET /identities/{id}/timeline`. */
export interface IdentityTimelineEvent {
  at: string;
  kind: "sync" | "grant" | "oauth_grant" | "finding" | string;
  action: string;
  summary: string;
  href: string | null;
  context: Record<string, unknown>;
}

export interface IdentityTimeline {
  identity_id: string;
  limit: number;
  items: IdentityTimelineEvent[];
}

export interface AssignedOperator {
  id: string;
  email: string;
  display_name: string | null;
}

export interface FindingSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  subject_type: string;
  subject_id: string;
  /** Human label for list/detail (identity name, setting label, …). */
  subject_label?: string | null;
  /** Secondary context for list rows (email, setting key=value, …). */
  subject_secondary?: string | null;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  /** Mute expiry when status=muted. */
  muted_until?: string | null;
  mute_reason?: string | null;
  assigned_to: AssignedOperator | null;
  policy_version_id: string;
  policy_slug: string | null;
  /** Whole days since first_seen_at (list/export/detail). */
  age_days: number;
}

/** Open-finding ownership rollup from GET /findings/queues. */
export interface FindingOwnershipQueues {
  open_total: number;
  open_unassigned: number;
  open_assigned_to_me: number;
  by_assignee: {
    operator_id: string;
    email: string;
    display_name: string | null;
    open_count: number;
  }[];
}

export interface FindingPolicyContext {
  id: string | null;
  slug: string | null;
  title: string | null;
  description: string | null;
  version: number;
  version_id: string;
  remediation: string | null;
  compliance_mappings: Record<string, string[]>;
  /** Resolved control catalog links. */
  compliance_controls?: {
    framework: string;
    control_id: string;
    title: string | null;
    id: string | null;
    detail_path: string | null;
    resolved: boolean;
  }[];
  /** pack | custom | system. */
  source?: string;
  is_system_toxic?: boolean;
}

export interface FindingSubject {
  type: string;
  id: string;
  label: string | null;
  detail_path: string | null;
  secondary: string | null;
  /** Findings list scoped to this subject. */
  findings_list_path?: string | null;
  /** Explore graph focus for identity subjects. */
  graph_focus_path?: string | null;
  /** Legacy inventory path; prefer connector_path. */
  inventory_path?: string | null;
  /** Integrations connector instance for this subject's app. */
  connector_path?: string | null;
  /** External SaaS console URL for remediation. */
  provider_console_url?: string | null;
  provider_console_label?: string | null;
  /** Correlated accounts for an identity subject: the same person elsewhere. */
  cluster?: IdentityCluster | null;
  /** Identity detail page for an identity subject. */
  identity_path?: string | null;
  /** Typed remediator fields (setting value, MFA, app name, …). */
  context?: Record<string, unknown>;
}

export interface FindingEvidenceLink {
  rel: string;
  href: string;
  title: string;
}

export interface FindingEvidenceRow {
  label: string;
  value: unknown;
  /** Friendly remediator label (falls back to dotted label). */
  display_label?: string;
  /** Grouping prefix: setting | identity | grant | … */
  group?: string;
  /** Highlight fields that explain the violation. */
  highlight?: boolean;
  /** Deep-links into connectors / findings / provider console. */
  links?: FindingEvidenceLink[];
}

/** GET /findings/{id}/provenance. */
export interface FindingProvenance {
  finding_id: string;
  subject_type: string;
  subject_id: string;
  available: boolean;
  trimmed: boolean;
  truncated: boolean;
  approx_bytes: number;
  last_seen_at: string | null;
  first_seen_at: string | null;
  raw_source: Record<string, unknown> | null;
  message: string | null;
}

export interface FindingBlastRadiusNeighbor {
  node_id: string;
  node_type: string;
  object_id: string;
  label: string;
  /** Connector application_type stamped on the graph node. */
  application_type?: string | null;
  detail_path: string | null;
  graph_focus_path: string | null;
  findings_list_path: string | null;
  open_finding_count: number;
  open_findings: {
    id: string;
    title: string;
    severity: string;
    status: string;
    last_seen_at: string;
  }[];
}

export interface FindingBlastRadius {
  depth: number;
  subject_node_id: string | null;
  neighbor_count: number;
  open_finding_count: number;
  neighbors: FindingBlastRadiusNeighbor[];
  findings: {
    id: string;
    title: string;
    severity: string;
    status: string;
    subject_type: string;
    subject_id: string;
    subject_label: string | null;
    last_seen_at: string;
  }[];
}

export interface FindingException {
  id: string;
  reason: string;
  created_at: string | null;
  expires_at: string | null;
  created_by: AssignedOperator | null;
}

/** Append-only investigation note. */
export interface FindingNote {
  id: string;
  finding_id: string;
  body: string;
  created_at: string | null;
  author: AssignedOperator | null;
}

/** Ticket created from a finding via TicketProvider. */
export interface FindingTicketRef {
  id: string;
  finding_id: string;
  ticket_integration_id: string | null;
  provider: string;
  external_id: string;
  url: string;
  created_by_operator_id: string | null;
  created_at: string | null;
}

export interface FindingActivityEvent {
  at: string;
  kind: "detected" | "audit" | string;
  action: string;
  summary: string;
  actor: AssignedOperator | null;
  context: Record<string, unknown>;
}

export interface FindingRemediationPlaybookStep {
  id: string;
  kind: "investigate" | "remediate" | "verify" | "document" | string;
  title: string;
  instruction: string;
  href: string | null;
}

export interface FindingDetail extends FindingSummary {
  evidence: FindingEvidenceRow[];
  policy: FindingPolicyContext | null;
  subject: FindingSubject;
  exceptions: FindingException[];
  /** Recent investigation notes, newest first. */
  notes: FindingNote[];
  /** Tickets created via TicketProvider. */
  tickets?: FindingTicketRef[];
  /** Newest-first investigation timeline. */
  activity: FindingActivityEvent[];
  /** Other findings on the same subject. */
  related_findings: {
    id: string;
    title: string;
    severity: string;
    status: string;
    first_seen_at: string;
    last_seen_at: string;
  }[];
  /** Other findings for the same policy. */
  same_policy_cohort?: SamePolicyCohort;
  /** Exception ↔ compliance control investigation bridges. */
  control_cross_links?: ControlCrossLinks;
  /** Graph-neighbor open findings beyond the subject. */
  blast_radius?: FindingBlastRadius;
  /** Ordered hops over real graph edges; never fabricated. */
  attack_path?: FindingAttackPath;
  /** Guided checklist beyond policy remediation prose. */
  remediation_playbook?: FindingRemediationPlaybookStep[];
  /** Calling operator is subscribed for in-app updates. */
  watching?: boolean;
}

/** Same-policy finding cohort on finding detail. */
export interface SamePolicyCohort {
  policy_id: string | null;
  policy_slug: string | null;
  policy_title: string | null;
  open_other_count: number;
  total_other_count: number;
  items: {
    id: string;
    title: string;
    severity: string;
    status: string;
    subject_type: string;
    subject_id: string;
    first_seen_at: string;
    last_seen_at: string;
    detail_path: string;
  }[];
  list_path: string | null;
}

/** Exception ↔ control cross-links on finding detail. */
export interface ControlCrossLinks {
  kind: string;
  controls: {
    id: string;
    framework: string;
    control_id: string;
    title: string;
    detail_path: string;
    open_peer_count: number;
    open_peers: {
      id: string;
      title: string;
      severity: string;
      status: string;
      detail_path: string;
    }[];
    exception_peer_count: number;
    exception_peers: {
      id: string;
      title: string;
      severity: string;
      status: string;
      detail_path: string;
    }[];
    muted_peer_count?: number;
    muted_peers?: {
      id: string;
      title: string;
      severity: string;
      status: string;
      muted_until?: string | null;
      detail_path: string;
    }[];
  }[];
  notes: string;
}

/** GET /findings/watched/digest. */
export interface WatchDigest {
  as_of: string;
  kind: string;
  window_days: number;
  since: string;
  subject: string;
  body_text: string;
  href: string;
  summary: {
    watched_total: number;
    still_open: number;
    resolved_in_window: number;
    activity_in_window: number;
    aging_open: number;
    by_severity: Record<string, number>;
    window_days: number;
  };
  still_open: FindingSummary[];
  resolved_in_window: FindingSummary[];
  activity_in_window: FindingSummary[];
  aging_open: FindingSummary[];
}

/** `POST /findings/watched/digest-preview`: the digest plus whether the next scheduled run sends it. */
export interface WatchDigestPreview extends WatchDigest {
  email_configured: boolean;
  would_send: boolean;
  /** Why `would_send` is false; null when it would send. */
  reason:
    | "email_not_configured"
    | "email_disabled"
    | "no_email_address"
    | "no_watches"
    | "no_changes"
    | "already_sent_this_window"
    | null;
  recipient: string | null;
  last_sent_at: string | null;
}

export interface FindingAttackPathHop {
  order: number;
  edge_id: string;
  edge_type: string;
  access_path: string | null;
  explanation: string;
  source: {
    id: string;
    node_type: string;
    object_id: string;
    label: string;
    properties?: Record<string, unknown>;
  };
  target: {
    id: string;
    node_type: string;
    object_id: string;
    label: string;
    properties?: Record<string, unknown>;
  };
}

export interface FindingAttackPath {
  finding_id?: string;
  subject_node_id?: string | null;
  algorithm?: string;
  max_depth?: number;
  hop_count: number;
  hops: FindingAttackPathHop[];
  summary: string;
  /** True when hop_count > 0 (handoff compact shape). */
  available?: boolean;
  path?: string | null;
}

export interface FindingExceptionExpiryItem {
  exception_id: string;
  finding_id: string;
  finding_title: string;
  severity: string;
  status: string;
  reason: string;
  expires_at: string;
  state: "expired" | "expiring_soon" | string;
  created_at: string | null;
  created_by: { id: string; email: string; display_name: string | null } | null;
  detail_path: string;
}

export interface FindingExceptionExpiryQueue {
  within_days: number;
  as_of: string;
  expired_count: number;
  expiring_soon_count: number;
  truncated?: boolean;
  items: FindingExceptionExpiryItem[];
}

/** GET /findings/mutes/expiring. */
export interface FindingMuteExpiryItem {
  finding_id: string;
  finding_title: string;
  severity: string;
  status: string;
  reason: string | null;
  muted_until: string;
  state: "expired" | "expiring_soon";
  detail_path: string;
}

export interface FindingMuteExpiryQueue {
  within_days: number;
  as_of: string;
  expired_count: number;
  expiring_soon_count: number;
  truncated?: boolean;
  items: FindingMuteExpiryItem[];
}

/** Operator home posture overview from GET /dashboard. */
export interface DashboardOverview {
  findings: {
    open_total: number;
    by_status: Record<string, number>;
    open_by_severity: Record<string, number>;
    open_by_age: Record<string, number>;
    ownership?: FindingOwnershipQueues;
    viewer_operator_id?: string;
    mine_preview?: {
      id: string;
      title: string;
      severity: string;
      status: string;
      first_seen_at: string;
      last_seen_at: string;
    }[];
    unassigned_preview?: {
      id: string;
      title: string;
      severity: string;
      status: string;
      first_seen_at: string;
      last_seen_at: string;
    }[];
    recent_open: {
      id: string;
      title: string;
      severity: string;
      status: string;
      first_seen_at: string;
      last_seen_at: string;
    }[];
  };
  connectors: {
    connector_count: number;
    healthy: number;
    never_synced: number;
    failed: number;
    stale: number;
    running: number;
    stale_after_hours: number;
  };
  webhooks?: {
    pending: number;
    success: number;
    failed: number;
    endpoints_with_failures: number;
  };
  policies?: {
    top_failing: {
      policy_id: string;
      slug: string;
      title: string;
      severity: string;
      open_count: number;
    }[];
  };
  first_run?: {
    complete: boolean;
    /** The viewer dismissed the checklist (per operator; restorable from the board menu). */
    dismissed: boolean;
    fixture_demo: boolean;
    steps: {
      id: string;
      label: string;
      done: boolean;
      path: string;
      hint: string;
    }[];
  };
}

/** Built-in dashboard widget ids (shell + catalog). */
export type DashboardWidgetId =
  | "first_run"
  | "summary_metrics"
  | "open_by_severity"
  | "by_status"
  | "top_failing_policies"
  | "recent_open_findings"
  | "aging_open_findings"
  | "connector_health"
  | "my_open_findings"
  | "unassigned_open"
  | string;

export interface DashboardLayoutWidget {
  id: DashboardWidgetId;
}

export interface DashboardLayout {
  version: number;
  widgets: DashboardLayoutWidget[];
}

export interface DashboardWidgetCatalogEntry {
  id: DashboardWidgetId;
  title: string;
  description: string;
  /** Present on catalog responses. */
  in_default?: boolean;
}

/** GET /dashboard/layout */
export interface DashboardLayoutResponse {
  layout: DashboardLayout;
  default_layout: DashboardLayout;
  catalog: DashboardWidgetCatalogEntry[];
  is_default: boolean;
}

/** Multi-dashboard boards (DEC-023). */
export interface DashboardWidget {
  id: string;
  widget_key: string;
  title: string;
  viz_type: string;
  query_spec: Record<string, unknown>;
  layout: { x: number; y: number; w: number; h: number; [key: string]: unknown };
  refresh_seconds: number | null;
  sort_order: number;
  body_markdown: string | null;
}

export interface DashboardBoard {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  is_default: boolean;
  visibility: string;
  created_by_operator_id: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  widgets: DashboardWidget[];
}

export interface DashboardPresetCatalog {
  presets: {
    id: string;
    title: string;
    description: string;
    viz_type: string;
    query_spec: Record<string, unknown>;
    layout: { x: number; y: number; w: number; h: number };
    in_default: boolean;
  }[];
  templates: { slug: string; name: string; description: string; widget_keys: string[] }[];
}

export interface DashboardQueryResult {
  kind?: string;
  entity?: string;
  series?: { name: string; value: number }[];
  rows?: Record<string, unknown>[];
  total?: number;
  drilldown?: Record<string, unknown>;
  message?: string;
  cached?: boolean;
}

export interface DashboardSchedule {
  id: string;
  dashboard_id: string;
  cron: string;
  timezone: string;
  format: string;
  recipient_operator_ids: string[];
  enabled: boolean;
  last_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  created_by_operator_id: string | null;
}

/** Admin audit trail row from GET /audit-log. */
export interface AuditLogEntry {
  id: string;
  actor: { id: string; email: string; display_name: string | null } | null;
  action: string;
  target_type: string;
  target_id: string | null;
  context: Record<string, unknown> | null;
  created_at: string;
}


export interface GraphNode {
  id: string;
  node_type: string;
  object_id: string;
  label: string;
  properties: Record<string, unknown>;
  is_start?: boolean;
  is_subject?: boolean;
}

export interface GraphEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  access_path: string | null;
  /** Edge extras (permission_level, membership_role, scopes). */
  properties?: Record<string, unknown>;
}

export interface GraphOAuthScope {
  name: string;
  is_sensitive: boolean;
}

export interface GraphNeighborsResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Soft cap hit on reachable set. */
  truncated?: boolean;
  node_count?: number;
  edge_count?: number;
  direction?: "out" | "in" | "both";
  depth?: number;
  start_node_id?: string;
  /** Correlated accounts when focus is an identity. */
  accounts?: GraphIdentityAccount[] | null;
}

/** GET /graph/nodes/{id}/paths. */
export interface GraphPathHop {
  from: GraphNode;
  to: GraphNode;
  edge_id: string;
  edge_type: string;
  access_path: string | null;
  properties?: Record<string, unknown>;
  explanation: string;
}

export interface GraphReachabilityPath {
  destination: GraphNode;
  hop_count: number;
  access_paths: string[];
  primary_access_path: string | null;
  hops: GraphPathHop[];
}

export interface GraphReachabilityResponse {
  start: GraphNode & { is_start?: boolean };
  direction: "out" | "in";
  depth: number;
  total: number;
  returned: number;
  truncated: boolean;
  paths: GraphReachabilityPath[];
  summary: {
    by_node_type: Record<string, number>;
    by_access_path: Record<string, number>;
  };
}

/** GET /graph/search. */
export interface GraphSearchItem {
  id: string;
  node_type: string;
  object_id: string;
  label: string;
  detail_path: string | null;
  graph_focus_path: string;
  /** Correlated application types when this identity spans apps. */
  application_types?: string[];
  account_count?: number;
}

export interface GraphSearchResponse {
  items: GraphSearchItem[];
}

/** Correlated per-app account on an identity focus. */
export interface GraphIdentityAccount {
  identity_id: string;
  application_type: string;
  application_display_name: string | null;
  email: string | null;
  display_name: string | null;
  mfa_enabled: boolean | null;
  is_disabled: boolean;
  match_kind: string;
}

/** GET /graph/nodes/{id}/context. */
export interface GraphNodeContext {
  node: GraphNode;
  entity: {
    detail_path: string | null;
    graph_focus_path: string | null;
    findings_list_path: string | null;
  };
  neighbor_counts: { outgoing: number; incoming: number; total: number };
  open_findings: {
    id: string;
    title: string;
    severity: string;
    status: string;
    last_seen_at: string;
  }[];
  open_finding_count: number;
  /** Present for identity nodes — correlated accounts across connectors. */
  accounts?: GraphIdentityAccount[] | null;
}

/** GET /graph/edges/{id}. */
export interface GraphEdgeContext {
  edge: {
    id: string;
    edge_type: string;
    access_path: string | null;
    first_seen_at: string | null;
    last_seen_at: string | null;
    properties: Record<string, unknown>;
    source_node_id: string;
    target_node_id: string;
  };
  source: GraphNode;
  target: GraphNode;
  provenance: {
    connector_run_id: string;
    connector_instance_id: string | null;
    status: string | null;
    triggered_by: string | null;
    started_at: string | null;
    finished_at: string | null;
  } | null;
  explanation: string;
  entity: {
    source_detail_path: string | null;
    target_detail_path: string | null;
    source_graph_focus_path: string | null;
    target_graph_focus_path: string | null;
  };
}

/** GET /reports/detection-coverage. */


export interface ConnectorSetupStep {
  title: string;
  body: string;
  link_url?: string | null;
  link_label?: string | null;
}

export interface ConnectorAuthMethod {
  id: string;
  label: string;
  config_fields: string[];
  /** Subset of config_fields the create form may leave blank. */
  optional_config_fields?: string[];
  secret_fields: string[];
  setup_overview?: string | null;
  setup_steps?: ConnectorSetupStep[];
  field_help?: Record<string, string>;
  scopes_note?: string | null;
}

export interface ConnectorCatalogEntry {
  name: string;
  display_name: string;
  version: string;
  description: string;
  required_scopes?: string[];
  setup_docs?: string | null;
  auth_methods: ConnectorAuthMethod[];
  example_config: Record<string, unknown>;
  source?: "builtin" | "custom" | "community";
}

/** Secret field status — never includes plaintext. */
export interface ConnectorSecretStatus {
  declared_fields: string[];
  configured_fields: string[];
  missing_fields: string[];
  fields: { name: string; configured: boolean }[];
}

export interface ConnectorInstanceSummary {
  id: string;
  application_instance_id: string;
  application_display_name: string | null;
  /** The tenant this instance reads: org login, workspace id, or domain. */
  external_tenant_ref?: string | null;
  connector_id: string;
  connector_name: string | null;
  connector_display_name: string | null;
  auth_method: string;
  sync_mode: string;
  /** Created by `kestrel demo up`; the API refuses to sync it. */
  is_demo?: boolean;
  schedule_cron: string | null;
  last_run_status: string | null;
  last_run_at?: string | null;
  last_success_at?: string | null;
  health?: string;
  last_run_object_counts: Record<string, number>;
  secrets?: ConnectorSecretStatus;
  detail_path?: string;
}

/** GET /connector-instances/{id}. */
export interface ConnectorInstanceDetail extends ConnectorInstanceSummary {
  config: Record<string, unknown>;
  config_fields: string[];
  secrets: ConnectorSecretStatus;
}

/** GET /connector-instances/health. */
export interface ConnectorHealthSlo {
  window_days: number;
  runs_total: number;
  runs_success: number;
  runs_failed: number;
  /** Runs that collected but could not read some object type (partial coverage). */
  runs_degraded: number;
  success_rate_pct: number | null;
  instances_total: number;
  instances_healthy: number;
  instances_degraded: number;
  instances_unhealthy: number;
  freshness_pct: number | null;
  success_target_pct: number;
  freshness_target_pct: number;
  success_slo_met: boolean;
  freshness_slo_met: boolean;
}

export interface ConnectorHealthCenter {
  stale_after_hours: number;
  summary: Record<string, number>;
  items: {
    id: string;
    application_instance_id: string;
    application_display_name: string | null;
    connector_id: string;
    connector_name: string | null;
    connector_display_name: string | null;
    auth_method: string;
    sync_mode: string;
    is_demo?: boolean;
    schedule_cron: string | null;
    last_run_status: string | null;
    last_run_at: string | null;
    last_success_at: string | null;
    hours_since_success: number | null;
    health: string;
    error_summary: string | null;
    last_run_object_counts: Record<string, number>;
  }[];
  /** Labeled 7d sync SLO strip. */
  slo?: ConnectorHealthSlo;
}

export interface ConnectorRun {
  id: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  object_counts: Record<string, number>;
  error_summary: string | null;
  triggered_by?: string | null;
  detail_path?: string;
}

/** GET /connector-runs/{id}. */
export interface ConnectorRunDetail {
  id: string;
  status: string;
  triggered_by: string;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  object_counts: Record<string, number>;
  objects_total: number;
  error_summary: string | null;
  coverage?: {
    collected: { object_type: string; count: number }[];
    skipped: { object_type: string; reason: string; detail: string }[];
    is_complete: boolean;
    notice: string | null;
  };
  connector_instance: {
    id: string;
    auth_method: string;
    sync_mode: string;
    schedule_cron: string | null;
    connector_id: string;
    connector_name: string | null;
    connector_display_name: string | null;
    detail_path: string;
  };
  application: {
    id: string | null;
    display_name: string | null;
    application_type: string | null;
    detail_path: string | null;
  };
  policy_evaluations: {
    id: string;
    status: string;
    matched_object_count: number;
    error_message: string | null;
    started_at: string | null;
    finished_at: string | null;
    policy_id: string;
    policy_slug: string;
    policy_title: string;
    policy_version: number;
    severity: string;
    policy_detail_path: string;
    findings_list_path: string;
  }[];
  policy_evaluation_count: number;
  /** Entity create/update/delete counts from sync events. */
  change_summary?: {
    total: number;
    by_change_type: { created: number; updated: number; deleted: number };
    by_entity_type: Record<string, number>;
    note?: string;
  };
  previous_successful_run?: {
    id: string;
    status: string;
    started_at: string | null;
    finished_at: string | null;
    detail_path: string;
    change_summary: {
      total: number;
      by_change_type: { created: number; updated: number; deleted: number };
      by_entity_type: Record<string, number>;
      note?: string;
    };
  } | null;
  changes_path?: string;
}

export interface ConnectorRunChange {
  id: string;
  entity_type: string;
  entity_id: string;
  change_type: string;
  field_changes: { field?: string; old?: unknown; new?: unknown }[];
  detected_at: string | null;
  label: string | null;
  detail_path: string | null;
}

export interface ConnectorRunChanges {
  run_id: string;
  limit: number;
  offset: number;
  total: number;
  truncated: boolean;
  change_summary: NonNullable<ConnectorRunDetail["change_summary"]>;
  previous_successful_run: ConnectorRunDetail["previous_successful_run"];
  changes: ConnectorRunChange[];
  filters: { change_type: string | null; entity_type: string | null };
}

export interface FindingVerifyResult {
  as_of: string;
  finding_id: string;
  result: "still_matches" | "would_resolve" | "policy_error" | string;
  still_matches: boolean | null;
  would_resolve: boolean | null;
  message: string;
  errors: string[];
  persisted: boolean;
  policy: {
    id: string;
    slug: string;
    title: string;
    version: number;
    detail_path: string;
  };
  subject: FindingSubject;
  connector_instance: {
    id: string;
    application_instance_id: string;
    detail_path: string;
    sync_path: string;
  } | null;
  sync_suggested: boolean;
  sync_enqueued: { connector_instance_id: string; task_id: string } | null;
  duration_ms: number | null;
}

export interface PolicySummary {
  id: string;
  slug: string;
  title: string;
  source: string;
  pack_name: string | null;
  /** Derived from pack_name. */
  application?: string | null;
  current_version_id: string | null;
  version: number | null;
  severity: string | null;
  is_enabled: boolean | null;
  /** From current version source_text RESOURCE_TYPE=. */
  resource_type: string | null;
  /** Open findings across all versions of this policy (tenant-scoped). */
  open_finding_count: number;
  last_evaluation_status: string | null;
  last_evaluated_at: string | null;
}

export interface PackSummary {
  name: string;
  version: string;
  description: string;
  policy_count: number;
  installed: boolean;
  policy_slugs?: string[];
  detail_path?: string;
  display_name?: string;
  summary?: string;
  application?: string | null;
  categories?: string[];
  frameworks?: string[];
  vendor_baselines?: string[];
}

/** GET /packs/{name}. */
export interface PackDetail extends PackSummary {
  policies: {
    slug: string;
    title: string;
    severity: string | null;
    description: string | null;
    present: boolean;
    installed: boolean;
    policy_id: string | null;
    policy_path: string | null;
    resource_type?: string | null;
    category?: string | null;
  }[];
}

/** GET /packs/{name}/install-preview. */
export interface PackInstallPreview {
  name: string;
  version: string;
  installed: boolean;
  added: string[];
  updated: string[];
  unchanged: string[];
  unassessable?: string[];
  counts: {
    added: number;
    updated: number;
    unchanged: number;
    unassessable?: number;
  };
}

/** GET /packs/{name}/coverage */
export interface PackCoverage {
  name: string;
  version: string;
  application: string | null;
  connected: boolean;
  counts: {
    monitored: number;
    not_assessable: number;
    total: number;
  };
  policies: {
    slug: string;
    title: string;
    profile: string;
    requires: string[];
    status: "monitored" | "not_assessable";
    reason: string | null;
  }[];
}

export interface PolicyDetail extends PolicySummary {
  description: string | null;
  source_text: string | null;
  remediation: string | null;
  compliance_mappings: Record<string, string[]>;
}

/** GET/PUT /policies/{id}/fixtures — pack (disk) or custom (JSONB) Workbench fixtures. */
export interface PolicyFixturesResponse {
  available: boolean;
  source: "pack" | "custom" | "none";
  pack_name: string | null;
  slug: string;
  fixtures: {
    rows?: unknown[];
    expected_match_subject_ids?: string[];
    [key: string]: unknown;
  } | null;
  relative_path: string | null;
}

/** POST /policies/{id}/fixtures/from-matches | /policies/fixtures/from-matches. */
export interface PolicyFixtureCaptureResult {
  fixtures: {
    rows: unknown[];
    expected_match_subject_ids: string[];
    [key: string]: unknown;
  };
  row_count: number;
  truncated: boolean;
  max_rows: number;
  resource_type: string;
  persisted: boolean;
  policy_id: string | null;
}

/** GET /policies/{id}/evaluations. */
export interface PolicyEvaluationSummary {
  id: string;
  status: string;
  matched_object_count: number;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
  policy_version_id: string;
  policy_version: number;
  connector_run_id: string | null;
  connector_run_path: string | null;
  findings_list_path: string | null;
}

export interface PolicyEvaluationsResponse {
  items: PolicyEvaluationSummary[];
  limit: number;
  count: number;
}

/** GET /policies/{id}/findings — open findings strip. */
export interface PolicyOpenFindingItem {
  id: string;
  title: string;
  severity: string;
  subject_type: string;
  subject_id: string;
  subject_label: string | null;
  last_seen_at: string;
  detail_path: string;
}

export interface PolicyOpenFindingsResponse {
  policy_id: string;
  policy_slug: string;
  /** False when no PolicyEvaluation rows exist for this policy. */
  ever_evaluated: boolean;
  open_finding_count: number;
  open_by_severity: Record<string, number>;
  open_findings: PolicyOpenFindingItem[];
  open_findings_truncated: boolean;
  limit: number;
  findings_list_path: string;
}

/** GET /policies/{id}/versions — immutable version history. */
export interface PolicyVersionSummary {
  id: string;
  version: number;
  created_at: string | null;
  severity: string;
  is_enabled: boolean;
  is_current: boolean;
  source_preview: string;
  source_hash: string;
  created_by: string | null;
}

export interface PolicyVersionsResponse {
  policy_id: string;
  policy_slug: string;
  source: string;
  current_version_id: string | null;
  /** False for pack/system — UI must not offer Activate. */
  can_activate: boolean;
  items: PolicyVersionSummary[];
  count: number;
}

export interface PolicyValidateError {
  message: string;
  line?: number | null;
  column?: number | null;
}

export interface PolicyValidateResult {
  valid: boolean;
  errors: PolicyValidateError[];
  slug: string | null;
  severity: string | null;
  description: string | null;
}

/** POST /policies/generate — AI or offline scaffold draft (never auto-enabled). */
export interface PolicyGenerateValidation {
  valid: boolean;
  errors: string[];
  slug: string | null;
}

export interface PolicyGenerateFixtureTest {
  passed: boolean;
  expected: string[];
  actual: string[];
  missing?: string[];
  unexpected?: string[];
  error?: string | null;
  /** The scaffold was written for another intent: informational only. */
  advisory?: boolean;
}

/** policy()/evidence() over edge-case rows; only crashes count. */
export interface PolicyGenerateProbeTest {
  passed: boolean;
  probed: number;
  errors: string[];
}

export interface PolicyGenerateResult {
  source_text: string;
  provider: string;
  model: string;
  message?: string | null;
  error?: string | null;
  validation: PolicyGenerateValidation;
  /** Present when include_fixtures=true — never persisted by generate. */
  fixtures: {
    rows: unknown[];
    expected_match_subject_ids: string[];
  } | null;
  fixture_test?: PolicyGenerateFixtureTest | null;
  probe_test?: PolicyGenerateProbeTest | null;
}

export interface PolicyGenerateIntentChip {
  label: string;
  intent: string;
  connector_hint?: string;
  resource_type?: string;
}

export interface PolicyGenerateCatalog {
  connector: string | null;
  intent_chips: PolicyGenerateIntentChip[];
  template_names: string[];
  fields: {
    resource_types: string[];
    schemas: Record<string, string>;
    okta?: {
      privileged_roles: string[];
      tenant_setting_keys: string[];
      event_actions: string[];
      identity_fields: string[];
      prompt_catalog: string;
    };
  };
  samples: unknown[];
}

export interface PolicyFixtureTestResult {
  passed: boolean;
  expected: string[];
  actual: string[];
}

/** POST /policies/{id}/evaluate — mutate reconcile. */
export interface PolicyEvaluateResult {
  id: string;
  status: string;
  matched_object_count: number;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
  policy_id: string;
  policy_slug: string;
  policy_version_id: string;
  policy_version: number;
  is_enabled: boolean;
}

/** POST /policies/{id}/dry-run | /policies/dry-run-draft. */
export interface PolicyDryRunMatch {
  subject_type: string;
  subject_id: string | null;
  label: string | null;
  detail_path: string | null;
  secondary: string | null;
  findings_list_path: string;
  evidence: Record<string, unknown>;
  match_status: "new" | "existing" | "would_resolve" | string;
  existing_finding_id: string | null;
  existing_finding_path: string | null;
}

export interface PolicyDryRunResult {
  as_of: string;
  dry_run: boolean;
  persisted: boolean;
  policy_id: string | null;
  policy_slug: string | null;
  policy_version_id: string | null;
  severity: string | null;
  evaluated_row_count: number;
  match_count: number;
  truncated: boolean;
  match_limit: number;
  new_match_count: number;
  existing_match_count: number;
  would_resolve_count: number;
  duration_ms: number;
  matches: PolicyDryRunMatch[];
  would_resolve: PolicyDryRunMatch[];
}

export interface Operator {
  id: string;
  email: string;
  display_name: string | null;
  role: "read_only" | "analyst" | "admin";
  is_active: boolean;
  last_login_at: string | null;
  ui_preferences?: Record<string, unknown>;
  /** Whether the operator has two-factor authentication on. */
  mfa_enabled?: boolean;
  /** GET /auth/me only: this session is limited to MFA setup. */
  mfa_enrollment_required?: boolean;
}

/** GET /auth/mfa: the caller's two-factor authentication. */
export interface MfaStatus {
  enabled: boolean;
  enabled_at: string | null;
  recovery_codes_remaining: number;
  required_by_org: boolean;
}

/** POST /auth/mfa/setup: a pending secret to add to an authenticator app. */
export interface MfaSetup {
  secret: string;
  otpauth_uri: string;
}

/** GET/PATCH /org/security. */
export interface OrgSecurity {
  require_mfa: boolean;
  active_operators_without_mfa: number;
}

/** Per-operator notification prefs — distinct from finding mute. */
export interface OperatorNotificationPreferences {
  id: string;
  operator_id: string;
  email_enabled: boolean;
  in_app_enabled: boolean;
  findings_enabled: boolean;
  webhook_failures_enabled: boolean;
  min_severity: "low" | "medium" | "high" | "critical" | string;
  muted_events: string[];
  /** Per organization: a mail server is set up (Settings → Email or the server
   * environment), so the email channel actually sends. */
  email_configured: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface WebhookDeliveryCounts {
  pending: number;
  success: number;
  failed: number;
}

export interface WebhookEndpoint {
  id: string;
  name: string;
  url: string;
  description: string | null;
  events: string[];
  is_enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
  signing_secret?: string;
  /** Present on list/detail. */
  delivery_counts?: WebhookDeliveryCounts;
}

/** Org LLM settings for policy AI drafts. API key never returned. */
export interface AiSettings {
  configured: boolean;
  provider: string | null;
  model: string | null;
  base_url: string | null;
  is_enabled: boolean;
  api_key_configured: boolean;
  defaults: {
    providers: string[];
    models: Record<string, string>;
    base_urls: Record<string, string>;
  };
}

export type EmailSecurity = "starttls" | "ssl" | "none";

/** The org's saved mail server, enabled or not. Password never returned. */
export interface OrgEmailSettings {
  host: string;
  port: number;
  security: EmailSecurity;
  username: string | null;
  password_configured: boolean;
  from_address: string;
  is_enabled: boolean;
  updated_at: string | null;
}

/** GET/PUT /settings/email: the mail server in force. An enabled org row
 * overrides the server's KESTREL_SMTP_* environment; `source` null means
 * no email is sent. Password never returned. */
export interface EmailSettings {
  source: "org" | "environment" | null;
  configured: boolean;
  host: string | null;
  port: number | null;
  security: EmailSecurity | null;
  username: string | null;
  password_configured: boolean;
  from_address: string | null;
  is_enabled: boolean;
  updated_at: string | null;
  /** The saved org row regardless of `is_enabled`, so a disabled one can be edited. */
  org: OrgEmailSettings | null;
}

/** POST /settings/email/test: a test message to the signed-in admin. */
export interface EmailTestResult {
  ok: boolean;
  source: EmailSettings["source"];
  to: string | null;
  detail: string | null;
}

/** Org ticket tracker integration. Tokens never returned. */
export interface TicketIntegration {
  id: string;
  name: string;
  provider: string;
  description: string | null;
  config: Record<string, unknown>;
  is_enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
}

export interface WebhookDelivery {
  id: string;
  webhook_endpoint_id: string;
  finding_id: string | null;
  event_type: string;
  status: "pending" | "success" | "failed";
  attempt_count: number;
  http_status: number | null;
  error_message: string | null;
  /** Wall-clock ms enqueue→success; null when not yet delivered. */
  latency_ms: number | null;
  created_at: string | null;
  delivered_at: string | null;
  can_retry: boolean;
}

/** Envelope returned by cursor-paginated list endpoints.
 * `next_cursor` is null on the last page; pass it back as `?cursor=` to
 * fetch the next one. Treat the value as opaque. */
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

/** Per-operator saved findings list filter presets. */
export interface FindingFilterPreset {
  id: string;
  name: string;
  filters: Record<string, unknown>;
  is_favorite: boolean;
  last_used_at: string;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface FindingFilterPresets {
  favorites: FindingFilterPreset[];
  recent: FindingFilterPreset[];
}

/** In-app notification inbox. */
export interface InAppNotification {
  id: string;
  operator_id: string;
  kind: string;
  event_type: string;
  title: string;
  body: string | null;
  finding_id: string | null;
  severity: string | null;
  payload: Record<string, unknown>;
  read_at: string | null;
  is_read: boolean;
  detail_path: string | null;
  created_at: string | null;
  updated_at?: string | null;
}

/** `GET /notifications`: a cursor page plus the caller's total unread count. */
export interface InAppNotificationList {
  items: InAppNotification[];
  next_cursor: string | null;
  unread_count: number;
}

/** Org-wide ⌘K search. */
export interface OrgSearchItem {
  id: string;
  label: string;
  subtitle: string | null;
  href: string;
}

export interface OrgSearchGroup {
  type: "identity" | "finding" | "application" | "policy" | "access_review" | string;
  items: OrgSearchItem[];
}

export interface OrgSearchResponse {
  query: string;
  groups: OrgSearchGroup[];
}




/** Change feed. Classification is derived at read time. */
export type ChangeSignificance = "high" | "medium" | "low";

export interface ClassifiedChange {
  event_id: string;
  change_class: string;
  significance: ChangeSignificance;
  entity_type: string;
  entity_id: string;
  label: string | null;
  summary: string;
  before: unknown;
  after: unknown;
  detected_at: string | null;
  detail_path: string | null;
  change_type: string;
  field_changes: { field?: string; old?: unknown; new?: unknown }[];
  connector_instance_id: string | null;
  application_display_name: string | null;
  /** Who caused the change, from a matching provider audit row.
   *  Null whenever the connector collects no audit log or nothing matched —
   *  snapshot-diff alone cannot know an actor. */
  actor_email: string | null;
  actor_provider_id: string | null;
  actor_action: string | null;
  actor_occurred_at: string | null;
}

export interface ChangeFeed {
  since: string;
  limit: number;
  offset: number;
  total: number;
  scan_saturated: boolean;
  summary: {
    by_class: Record<string, number>;
    by_significance: Record<ChangeSignificance, number>;
  };
  changes: ClassifiedChange[];
  filters: {
    change_classes: string[] | null;
    min_significance: ChangeSignificance | null;
    connector_instance_id: string | null;
    search: string | null;
  };
}

/** Result of testing unsaved connector credentials from the wizard. */
export interface ConnectorProbeResult {
  ok: boolean;
  healthy: boolean;
  message: string;
  sync_mode: string;
  auth_method: string;
  checked_permissions: Record<string, boolean>;
}
