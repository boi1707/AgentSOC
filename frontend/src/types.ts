export interface Actor {
  username: string;
  role: "viewer" | "analyst" | "approver" | "admin";
  csrf: string;
}
export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
  severity_counts?: Record<string, number>;
}
export interface Evidence {
  id: string;
  level: number;
  rule: string;
  kind: string;
  description: string;
  hostname?: string;
  src_ip?: string;
  dst_ip?: string;
  host_ip?: string;
  severity: string;
  event_type: string;
  [key: string]: unknown;
}
export interface Normalized {
  schema_version: number;
  source: string;
  external_id: string;
  source_timestamp: string | null;
  entities: string[];
  evidence: Evidence;
  severity: string;
  event_type: string;
}
export interface Alert {
  provenance: string;
  id: string;
  received: number;
  case_id: string | null;
  source: string;
  severity: string;
  event_type: string;
  correlation_status: string;
  synthetic: number;
  normalized: Normalized;
  raw_event?: unknown;
}
export interface Verdict {
  verdict?: string;
  confidence?: number;
  grounded?: number;
  evidence_ids?: string[];
  reason?: string;
  block_ip?: string | null;
  mode?: string;
  review_reason?: string | null;
  supporting_evidence?: string[];
  contradicting_evidence?: string[];
  missing_data?: string[];
  mitre?: string[];
}
export interface Incident {
  response_mode: string;
  provenance: string;
  severity: string;
  id: string;
  created: number;
  status: string;
  workflow_status: string;
  latest_run_id: string | null;
  synthetic: number;
  incident: {
    ips: string[];
    entities?: string[];
    alerts: Evidence[];
    raw_ids: string[];
    dropped_rows: number;
  };
  verdict: Verdict;
  can_approve: boolean;
  target: string | null;
}
export interface Job {
  id: string;
  run_id: string;
  status: string;
  attempts: number;
  max_attempts: number;
  error: string | null;
  available: number;
}
export interface Action {
  id: number;
  ts: number;
  action: string;
  ip: string | null;
  mode: string;
  result: string;
  actor: string | null;
  requested_by: string | null;
  verification_status: string;
}
export interface Run {
  id: string;
  case_id: string;
  created: number;
  finished: number | null;
  status: string;
  replay: number;
  parent_run_id: string | null;
  provider: string | null;
  model: string | null;
  mode: string;
  error: string | null;
  prompt_version: string;
  steps?: Step[];
  planned_steps?: {
    id: string;
    role: string;
    status: string;
    attempt: number;
  }[];
  verdict?: Verdict;
  evidence?: unknown;
  cutoff?: number;
}
export interface Step {
  model_source: string | null;
  id: number;
  ts: number;
  case_id: string;
  run_id: string | null;
  step_id: string | null;
  agent: string;
  mode: string;
  provider: string | null;
  model: string | null;
  prompt_version: string | null;
  tool_name: string | null;
  prompt: unknown;
  response: unknown;
  evidence: string[];
  usage: Record<string, number>;
  duration_ms: number;
  error: string | null;
  status: string;
  attempt: number | null;
}
export interface IncidentDetail extends Incident {
  evidence: {
    id: string;
    normalized: Normalized;
    received: number;
    synthetic: number;
    reason: string;
  }[];
  runs: Run[];
  notes: { id: number; actor: string; created: number; body: string }[];
  actions: Action[];
  jobs: Job[];
}
export interface Metrics {
  alerts_received: number;
  incidents: number;
  unprocessed_alerts: number;
  llm_calls: number;
  blocked_egress: number;
  llm_errors: number;
  average_analysis_ms: number | null;
  last_alert_at: number | null;
}
export interface Health {
  database: string;
  worker_fresh: boolean;
  workers: { id: string; last_seen: number; current_job: string | null }[];
  backlog: number;
  oldest_job_age_seconds: number | null;
  dead_letters: number;
  last_alert_at: number | null;
  wazuh_connection: string;
  source: string | null;
  demo: boolean;
  response_mode: string;
  provider: {
    mode: string;
    name: string;
    model: string | null;
    configured: boolean;
    reachable: boolean | null;
    last_call: {
      ts: number;
      error: string | null;
      mode: string;
      provider: string | null;
      model: string | null;
    } | null;
  };
}
export interface Overview {
  metrics: Metrics;
  severity: Record<string, number>;
  workflow: Record<string, number>;
  series: { ts: number; count: number }[];
  recent: Incident[];
  system: Health;
  synthetic_alerts: number;
  review_pending: number;
}
export interface Audit {
  id: number;
  ts: number;
  actor: string;
  action: string;
  target: string | null;
  result: string;
}
