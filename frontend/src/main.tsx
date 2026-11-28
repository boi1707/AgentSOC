import { t, useLanguage, LanguageSwitcher } from "./i18n";
import { AssistantPanel } from "./AssistantPanel";
import React, {
  useEffect,
  useRef,
  useState,
  createContext,
  useContext,
  type FormEvent,
  type ReactNode,
} from "react";
import { createRoot } from "react-dom/client";
import {
  BrowserRouter,
  NavLink,
  Link,
  Route,
  Routes,
  useLocation,
  useParams,
} from "react-router-dom";
import {
  Activity,
  ArrowUpRight,
  Bell,
  BookOpen,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Clock,
  Database,
  FileText,
  Filter,
  LayoutDashboard,
  LogOut,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  X,
  ExternalLink,
  Network,
  Check,
  Play,
  Layers,
  UserRound,
} from "lucide-react";
import { api, setCsrf, useData } from "./api";
import type {
  Actor,
  Page,
  Alert,
  Incident,
  IncidentDetail,
  Step,
  Health,
  Overview,
  Audit,
  Run,
} from "./types";
import "./style.css";

const Session = createContext<Actor | null>(null);
const stamp = (value: number | null | undefined) =>
  value
    ? new Date(value * 1000).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }) +
      " (" +
      t("local") +
      ")"
    : t("No data");
const relative = (value: number | null | undefined) =>
  !value
    ? t("No data")
    : `${Math.max(0, Math.floor(Date.now() / 1000 - value)) < 60 ? t("Just now") : Math.floor((Date.now() / 1000 - value) / 60) + t("m ago")}`;
const short = (id: string) => (id.length > 16 ? id.slice(0, 12) : id);
function Badge({ value }: { value: string | undefined }) {
  return (
    <span className={"badge " + (value ?? "unknown")}>
      {t(value ?? "No data")}
    </span>
  );
}
function Provenance({
  synthetic,
  mode,
  provenance,
}: {
  synthetic?: number;
  mode?: string;
  provenance?: string;
}) {
  return (
    <>
      {!!synthetic && <Badge value="synthetic" />}
      {mode && <Badge value={mode} />}
      {provenance === "legacy_unknown" && (
        <span title={t("Historical data has no recorded provenance")}>
          <Badge value="legacy" />
        </span>
      )}
    </>
  );
}
function Json({ value }: { value: unknown }) {
  return (
    <pre className="json">
      {value === null || value === undefined
        ? t("No data")
        : typeof value === "string"
          ? value
          : JSON.stringify(value, null, 2)}
    </pre>
  );
}
function State({
  loading,
  error,
  empty,
  children,
}: {
  loading?: boolean;
  error?: string;
  empty?: boolean;
  children: ReactNode;
}) {
  if (loading)
    return (
      <div className="empty" role="status">
        <RefreshCw size={22} className="spin" />
        <h3>{t("Loading operational data")}</h3>
        <p>{t("Reading from AgentSOC.")}</p>
      </div>
    );
  if (error)
    return (
      <div className="empty error" role="alert">
        <TriangleAlert />
        <h3>{t("Unable to load data")}</h3>
        <p>{t(error)}</p>
        <p>
          {t(
            "Check the API connection and sign in again if your session expired.",
          )}
        </p>
      </div>
    );
  if (empty)
    return (
      <div className="empty">
        <Layers size={30} />
        <h3>{t("No records to display")}</h3>
        <p>
          {t(
            "Connect Wazuh or adjust the filters. This console does not seed data.",
          )}
        </p>
      </div>
    );
  return <>{children}</>;
}
function PageTitle({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-title">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="actions">{children}</div>
    </div>
  );
}
function Pager({
  total,
  offset,
  change,
}: {
  total: number;
  offset: number;
  change: (offset: number) => void;
}) {
  return (
    <div className="pager">
      <span>
        {total
          ? `${offset + 1}–${Math.min(offset + 25, total)} of ${total}`
          : t("0 records")}{" "}
        {t("· server paginated")}
      </span>
      <div>
        <button
          aria-label={t("Previous page")}
          disabled={!offset}
          onClick={() => change(Math.max(0, offset - 25))}
        >
          <ChevronLeft size={16} />
        </button>
        <button
          aria-label={t("Next page")}
          disabled={offset + 25 >= total}
          onClick={() => change(offset + 25)}
        >
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}
function Updated({ value, error }: { value?: number; error?: string }) {
  return (
    <span className={t("updated ") + (error ? "warn" : "")}>
      <span className="dot" />
      {error
        ? t("Disconnected · showing stale data")
        : value
          ? t("Updated ") + new Date(value).toLocaleTimeString()
          : t("Waiting for API")}
    </span>
  );
}
function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
  }, []);
  return (
    <dialog ref={ref} onCancel={onClose}>
      <div className="modal-title">
        <h2>{title}</h2>
        <button aria-label={t("Close detail")} onClick={onClose}>
          <X size={18} />
        </button>
      </div>
      {children}
    </dialog>
  );
}
function IncidentTable({ items }: { items: Incident[] }) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>{t("Incident / evidence")}</th>
            <th>{t("Priority")}</th>
            <th>{t("Workflow")}</th>
            <th>{t("AI verdict")}</th>
            <th>{t("Created")}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {items.map((c) => {
            const sev = c.severity;
            return (
              <tr key={c.id}>
                <td>
                  <Link
                    className="row-link mono"
                    to={"/console/incidents/" + c.id}
                  >
                    INC-{short(c.id)}
                  </Link>
                  <span className="sub">
                    {c.incident.raw_ids.length} {t("alerts ·")}
                    {c.incident.ips.length} {t("IP entities")}{" "}
                    <Provenance
                      provenance={c.provenance}
                      synthetic={c.synthetic}
                    />
                  </span>
                </td>
                <td>
                  <Badge value={sev} />
                </td>
                <td>
                  <Badge value={c.workflow_status} />
                </td>
                <td>
                  <Badge value={c.verdict.verdict ?? t("not analyzed")} />
                  <span className="sub">
                    {c.verdict.confidence === undefined
                      ? t("Not measured")
                      : Math.round(c.verdict.confidence * 100) +
                        t("% confidence")}{" "}
                    <Provenance mode={c.verdict.mode} />
                  </span>
                </td>
                <td className="muted small">{stamp(c.created)}</td>
                <td>
                  <Link
                    aria-label={t("Open incident ") + c.id}
                    to={"/console/incidents/" + c.id}
                  >
                    <ArrowUpRight size={16} />
                  </Link>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
function OverviewPage() {
  const query = useData<Overview>("/overview");
  const d = query.data;
  return (
    <>
      <PageTitle
        eyebrow={t("COMMAND CENTER")}
        title={t("Security overview")}
        description={t(
          "Your alert pipeline, investigation workload, and operational signals.",
        )}
      >
        <Updated value={query.updated} error={query.error} />
        <button onClick={query.refresh}>
          <RefreshCw size={15} />
          {t("Refresh")}
        </button>
      </PageTitle>
      <State loading={!d && query.loading} error={!d ? query.error : undefined}>
        {d && (
          <>
            {query.error && (
              <div className="notice warn">
                {t("Connection lost. Values below are stale.")}
              </div>
            )}
            {d.system.demo && (
              <div className="notice">
                {t(
                  "Synthetic demo database · mock analysis · no notifications or real response.",
                )}
              </div>
            )}
            <div className="kpis">
              {[
                [
                  "Alerts received",
                  d.metrics.alerts_received,
                  "Durable Wazuh inbox",
                  <Bell size={18} />,
                ],
                [
                  "Incidents",
                  d.metrics.incidents,
                  "Correlated evidence groups",
                  <Layers size={18} />,
                ],
                [
                  "Awaiting review",
                  d.review_pending,
                  "Human decision required",
                  <ShieldCheck size={18} />,
                ],
                [
                  "Job backlog",
                  d.system.backlog,
                  d.system.worker_fresh
                    ? "Worker heartbeat fresh"
                    : "Worker heartbeat stale",
                  <Activity size={18} />,
                ],
              ].map(([label, value, note, icon], i) => (
                <section className="kpi" key={i}>
                  <div className="kpi-label">
                    {label}
                    {icon}
                  </div>
                  <div className="kpi-number">{value}</div>
                  <div className="sub">{note}</div>
                </section>
              ))}
            </div>
            <div className="overview-grid">
              <section className="panel chart">
                <div className="panel-heading">
                  <div>
                    <h2>{t("Alert activity")}</h2>
                    <p>{t("Received events per hour · last 24 hours")}</p>
                  </div>
                  <span className="tag">{t("UTC buckets")}</span>
                </div>
                <ActivityChart values={d.series} />
                <div className="chart-axis">
                  <span>{t("24 hours ago")}</span>
                  <span>{t("12 hours ago")}</span>
                  <span>{t("Now")}</span>
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>{t("Severity distribution")}</h2>
                    <p>{t("All received alerts")}</p>
                  </div>
                  <Filter size={16} />
                </div>
                <div className="severity-list">
                  {["critical", "high", "medium", "low", "info"].map((s) => (
                    <div key={s}>
                      <div className="severity-line">
                        <Badge value={s} />
                        <strong>{d.severity[s] ?? 0}</strong>
                      </div>
                      <div className="bar-track">
                        <div
                          className={"bar " + s}
                          style={{
                            width:
                              (d.metrics.alerts_received
                                ? ((d.severity[s] ?? 0) /
                                    d.metrics.alerts_received) *
                                  100
                                : 0) + "%",
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            </div>
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>{t("Recent incidents")}</h2>
                  <p>{t("Latest investigations and human review decisions")}</p>
                </div>
                <Link className="text-link" to="/console/incidents">
                  {t("View queue")}
                  <ArrowUpRight size={14} />
                </Link>
              </div>
              <State empty={!d.recent.length}>
                <IncidentTable items={d.recent} />
              </State>
            </section>
            <div className="pipeline-strip">
              <div>
                <span
                  className={"dot " + (!d.system.worker_fresh ? "amber" : "")}
                />
                <strong>
                  {d.system.worker_fresh
                    ? t("Worker active")
                    : t("Worker unavailable")}
                </strong>
                <span>
                  {d.system.backlog} {t("jobs pending")}
                </span>
              </div>
              <div>
                <Database size={15} />
                <span>{t("SQLite ready")}</span>
              </div>
              <div>
                <Clock size={15} />
                <span>
                  {t("Last alert:")}
                  {relative(d.system.last_alert_at)}
                </span>
              </div>
              <Link to="/console/system">
                {t("System health")}
                <ChevronRight size={14} />
              </Link>
            </div>
          </>
        )}
      </State>
    </>
  );
}
function ActivityChart({
  values,
}: {
  values: { ts: number; count: number }[];
}) {
  const max = Math.max(1, ...values.map((v) => v.count));
  const points = values
    .map((v, i) => `${(i * 960) / 23},${155 - (v.count / max) * 125}`)
    .join(" ");
  return (
    <div className="chart-wrap">
      <svg
        viewBox="0 0 960 180"
        role="img"
        aria-label={t("Hourly alert counts")}
      >
        <g stroke="#263041" strokeDasharray="3 5">
          {[30, 70, 110, 155].map((y) => (
            <line x1="0" x2="960" y1={y} y2={y} key={y} />
          ))}
        </g>
        <polygon
          points={"0,155 " + points + " 960,155"}
          fill="#2991ff"
          fillOpacity=".08"
        />
        <polyline
          points={points}
          fill="none"
          stroke="#4b9cff"
          strokeWidth="2"
          vectorEffect="non-scaling-stroke"
        />
        {values
          .filter((v) => v.count > 0)
          .map((v) => (
            <text
              key={v.ts}
              x={(values.indexOf(v) * 960) / 23}
              y={145 - (v.count / max) * 125}
              fill="#9aaabd"
              fontSize="13"
            >
              {v.count}
            </text>
          ))}
      </svg>
      {!values.some((v) => v.count > 0) && (
        <span className="chart-empty">
          {t("No alerts received in this time window")}
        </span>
      )}
    </div>
  );
}
type Scope = { source: string; entity: string; since: string; until: string };
const emptyScope: Scope = { source: "", entity: "", since: "", until: "" };
function scoped(params: URLSearchParams, scope: Scope) {
  for (const key of ["source", "entity"] as const)
    if (scope[key]) params.set(key, scope[key]);
  for (const key of ["since", "until"] as const)
    if (scope[key])
      params.set(key, String(new Date(scope[key]).getTime() / 1000));
  return params;
}
function ScopeFilters({
  value,
  change,
}: {
  value: Scope;
  change: (v: Scope) => void;
}) {
  return (
    <details className="scope-filters">
      <summary>
        <Filter size={13} />
        {t("Entity, source and time filters")}
      </summary>
      <div className="filter-bar">
        <label>
          {t("Source ID")}
          <input
            aria-label={t("Source ID")}
            maxLength={64}
            value={value.source}
            onChange={(e) => change({ ...value, source: e.target.value })}
            placeholder={t("Any source")}
          />
        </label>
        <label>
          {t("Entity")}
          <input
            aria-label={t("Entity key")}
            maxLength={300}
            value={value.entity}
            onChange={(e) => change({ ...value, entity: e.target.value })}
            placeholder={t("ip:? or host:?")}
          />
        </label>
        <label>
          {t("From (local)")}
          <input
            aria-label={t("From time")}
            type="datetime-local"
            value={value.since}
            onChange={(e) => change({ ...value, since: e.target.value })}
          />
        </label>
        <label>
          {t("Until (local)")}
          <input
            aria-label={t("Until time")}
            type="datetime-local"
            value={value.until}
            onChange={(e) => change({ ...value, until: e.target.value })}
          />
        </label>
        <button onClick={() => change(emptyScope)}>{t("Clear scope")}</button>
      </div>
    </details>
  );
}
function AlertsPage() {
  const [scope, setScope] = useState<Scope>(emptyScope);
  const [offset, setOffset] = useState(0),
    [severity, setSeverity] = useState(""),
    [status, setStatus] = useState(""),
    [q, setQ] = useState("");
  const params = new URLSearchParams({
    limit: "25",
    offset: String(offset),
    severity,
    status,
    q,
  });
  const query = useData<Page<Alert>>("/alerts?" + scoped(params, scope));
  const d = query.data;
  function filter(fn: () => void) {
    fn();
    setOffset(0);
  }
  return (
    <>
      <PageTitle
        eyebrow={t("TELEMETRY")}
        title={t("Alert inbox")}
        description={t(
          "Original Wazuh alerts, normalized fields, and correlation provenance.",
        )}
      >
        <Updated value={query.updated} error={query.error} />
        <span className="tag">{t("Wazuh adapter v1")}</span>
      </PageTitle>
      <div className="filter-bar">
        <label className="search">
          <Search size={16} />
          <input
            aria-label={t("Search alerts")}
            placeholder={t("Search alert ID, host or evidence…")}
            value={q}
            onChange={(e) => filter(() => setQ(e.target.value))}
          />
        </label>
        <select
          aria-label={t("Severity filter")}
          value={severity}
          onChange={(e) => filter(() => setSeverity(e.target.value))}
        >
          <option value="">{t("All severities")}</option>
          {["critical", "high", "medium", "low", "info"].map((v) => (
            <option key={v} value={v}>
              {t(v)}
            </option>
          ))}
        </select>
        <select
          aria-label={t("Correlation filter")}
          value={status}
          onChange={(e) => filter(() => setStatus(e.target.value))}
        >
          <option value="">{t("All correlation states")}</option>
          <option value="pending">{t("pending")}</option>
          <option value="correlated">{t("correlated")}</option>
          <option value="uncorrelated">{t("uncorrelated")}</option>
        </select>
        <button onClick={query.refresh}>
          <RefreshCw size={15} />
          {t("Refresh")}
        </button>
      </div>
      <ScopeFilters
        value={scope}
        change={(v) => {
          setScope(v);
          setOffset(0);
        }}
      />
      <section className="panel">
        <div className="panel-heading">
          <h2>
            {t("Received alerts")}
            <span className="count">{d?.total ?? "—"}</span>
          </h2>
          <span className="muted small">
            {t("Sorted by received time · newest first")}
          </span>
        </div>
        <State
          loading={!d && query.loading}
          error={!d ? query.error : undefined}
          empty={d?.total === 0}
        >
          {d && (
            <>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>{t("Alert")}</th>
                      <th>{t("Severity")}</th>
                      <th>{t("Event type / host")}</th>
                      <th>{t("Network evidence")}</th>
                      <th>{t("Correlation")}</th>
                      <th>{t("Received")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.items.map((a) => (
                      <tr key={a.id}>
                        <td>
                          <Link
                            className="row-link mono"
                            to={"/console/alerts/" + encodeURIComponent(a.id)}
                          >
                            {short(a.id)}
                          </Link>
                          <span className="sub truncate">
                            {a.normalized.evidence.description ||
                              t("No description")}{" "}
                            <Provenance
                              provenance={a.provenance}
                              synthetic={a.synthetic}
                            />
                          </span>
                        </td>
                        <td>
                          <Badge value={a.severity} />
                        </td>
                        <td>
                          {t(a.event_type)}
                          <span className="sub mono">
                            {a.normalized.evidence.hostname ||
                              t("No host identity")}
                          </span>
                        </td>
                        <td className="mono small">
                          {a.normalized.evidence.src_ip || "—"}
                          <span className="sub">
                            → {a.normalized.evidence.dst_ip || "—"}
                          </span>
                        </td>
                        <td>
                          <Badge value={a.correlation_status} />
                          {a.case_id && (
                            <Link
                              className="sub text-link"
                              to={"/console/incidents/" + a.case_id}
                            >
                              INC-{short(a.case_id)}
                            </Link>
                          )}
                        </td>
                        <td className="small muted">{stamp(a.received)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager total={d.total} offset={offset} change={setOffset} />
            </>
          )}
        </State>
      </section>
    </>
  );
}
function AlertPage() {
  const { id } = useParams();
  const query = useData<Alert>("/alerts/" + encodeURIComponent(id ?? ""));
  const d = query.data;
  return (
    <>
      <Link className="back" to="/console/alerts">
        <ChevronLeft size={15} />
        {t("Alert inbox")}
      </Link>
      <PageTitle
        eyebrow={t("SOURCE EVIDENCE")}
        title={d ? t("Alert ") + short(d.id) : t("Alert detail")}
        description={t(
          "Preserved source payload and the normalized envelope used for correlation.",
        )}
      />
      <State loading={!d && query.loading} error={query.error}>
        {d && (
          <>
            <div className="detail-meta">
              <Badge value={d.severity} />
              <Badge value={d.correlation_status} />
              <Provenance provenance={d.provenance} synthetic={d.synthetic} />
              <span>
                {t("Source:")}
                {d.source}
              </span>
              <span>
                {t("Received:")}
                {stamp(d.received)}
              </span>
              {d.case_id && (
                <Link to={"/console/incidents/" + d.case_id}>
                  {t("Open incident")}
                  <ExternalLink size={13} />
                </Link>
              )}
            </div>
            <div className="two-columns">
              <section className="panel">
                <div className="panel-heading">
                  <h2>{t("Normalized envelope")}</h2>
                  <span className="tag">
                    {t("schema v")}
                    {d.normalized.schema_version}
                  </span>
                </div>
                <Json value={d.normalized} />
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>{t("Original JSON")}</h2>
                  <span className="tag">{t("Local evidence")}</span>
                </div>
                <Json value={d.raw_event} />
              </section>
            </div>
          </>
        )}
      </State>
    </>
  );
}
function IncidentsPage() {
  const [scope, setScope] = useState<Scope>(emptyScope);
  const [offset, setOffset] = useState(0),
    [status, setStatus] = useState(""),
    [severity, setSeverity] = useState("");
  const query = useData<Page<Incident>>(
    "/incidents?" +
      scoped(
        new URLSearchParams({
          limit: "25",
          offset: String(offset),
          status,
          severity,
        }),
        scope,
      ),
  );
  const d = query.data;
  return (
    <>
      <PageTitle
        eyebrow={t("INVESTIGATION")}
        title={t("Incident queue")}
        description={t(
          "Correlated alerts, independent workflow state, and evidence-backed AI verdicts.",
        )}
      >
        <Updated value={query.updated} error={query.error} />
      </PageTitle>
      <div className="filter-bar">
        <Filter size={16} />
        <select
          aria-label={t("Workflow filter")}
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">{t("All workflow states")}</option>
          {["open", "investigating", "review", "closed"].map((v) => (
            <option key={v} value={v}>
              {t(v)}
            </option>
          ))}
        </select>
        <select
          aria-label={t("Incident severity filter")}
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">{t("All severities")}</option>
          {["critical", "high", "medium", "low", "info"].map((v) => (
            <option key={v} value={v}>
              {t(v)}
            </option>
          ))}
        </select>
        <span className="filter-spacer" />
        <button onClick={query.refresh}>
          <RefreshCw size={15} />
          {t("Refresh")}
        </button>
      </div>
      <ScopeFilters
        value={scope}
        change={(v) => {
          setScope(v);
          setOffset(0);
        }}
      />
      <section className="panel">
        <div className="panel-heading">
          <h2>
            {t("Investigations")}
            <span className="count">{d?.total ?? "—"}</span>
          </h2>
          <span className="small muted">
            {t("Workflow ≠ AI verdict ≠ response status")}
          </span>
        </div>
        <State
          loading={!d && query.loading}
          error={!d ? query.error : undefined}
          empty={d?.total === 0}
        >
          {d && (
            <>
              <IncidentTable items={d.items} />
              <Pager total={d.total} offset={offset} change={setOffset} />
            </>
          )}
        </State>
      </section>
    </>
  );
}
function IncidentPage() {
  const { id } = useParams();
  const actor = useContext(Session)!;
  const query = useData<IncidentDetail>("/incidents/" + id);
  const d = query.data;
  const [note, setNote] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [selectedRun, setSelectedRun] = useState<Run>();
  const analyst = actor.role !== "viewer";
  const approver = ["admin", "approver"].includes(actor.role);
  async function write(path: string, body: unknown, method = "POST") {
    setBusy(true);
    setError("");
    try {
      await api(path, { method, body: JSON.stringify(body) });
      query.refresh();
      setNote("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Link className="back" to="/console/incidents">
        <ChevronLeft size={15} />
        {t("Incident queue")}
      </Link>
      <PageTitle
        eyebrow={t("INCIDENT WORKSPACE")}
        title={d ? "INC-" + short(d.id) : t("Investigation")}
        description={
          d
            ? t("Created ") + stamp(d.created)
            : t("Loading evidence and investigation history")
        }
      >
        <button onClick={query.refresh}>
          <RefreshCw size={15} />
          {t("Refresh")}
        </button>
      </PageTitle>
      <State loading={!d && query.loading} error={!d ? query.error : undefined}>
        {d && (
          <>
            <div className="detail-meta">
              <Badge value={d.workflow_status} />
              <Badge value={d.verdict.verdict ?? t("not analyzed")} />
              <Provenance
                provenance={d.provenance}
                synthetic={d.synthetic}
                mode={d.verdict.mode}
              />
              <span className="mono">{d.id}</span>
            </div>
            {error && (
              <div role="alert" className="notice warn">
                {t(error)}
              </div>
            )}
            <div className="investigation-layout">
              <div className="evidence-column">
                <section className="panel verdict">
                  <div className="panel-heading">
                    <h2>
                      <Shield size={17} />
                      {t("Decision summary")}
                    </h2>
                    <Badge value={d.verdict.verdict ?? "queued"} />
                  </div>
                  <p className="summary-text">
                    {d.verdict.reason ||
                      "No AI verdict yet. Check the job state below."}
                  </p>
                  <div className="verdict-facts">
                    <div>
                      <small>{t("Confidence")}</small>
                      <strong>
                        {d.verdict.confidence === undefined
                          ? t("Not measured")
                          : Math.round(d.verdict.confidence * 100) + "%"}
                      </strong>
                    </div>
                    <div>
                      <small>{t("Citation groundedness")}</small>
                      <strong>
                        {d.verdict.grounded === undefined
                          ? t("No data")
                          : Math.round(d.verdict.grounded * 100) + "%"}
                      </strong>
                    </div>
                    <div>
                      <small>{t("Evidence in context")}</small>
                      <strong>
                        {d.incident.alerts.length} / {d.evidence.length}{" "}
                        {t("alerts")}
                      </strong>
                    </div>
                  </div>
                  {d.incident.dropped_rows > 0 && (
                    <div className="notice">
                      {d.incident.dropped_rows}{" "}
                      {t(
                        "deduplicated rows omitted from model context. Original evidence remains below.",
                      )}
                    </div>
                  )}
                  {d.verdict.review_reason && (
                    <p className="review-reason">
                      <TriangleAlert size={14} />
                      {d.verdict.review_reason}
                    </p>
                  )}
                  <div className="citations">
                    {d.verdict.evidence_ids?.map((e) => (
                      <Link
                        to={"/console/alerts/" + encodeURIComponent(e)}
                        key={e}
                      >
                        [{short(e)}] <ExternalLink size={11} />
                      </Link>
                    ))}
                  </div>
                  {(d.verdict.missing_data?.length ?? 0) > 0 && (
                    <Json
                      value={{
                        missing_data: d.verdict.missing_data,
                        supporting: d.verdict.supporting_evidence,
                        contradicting: d.verdict.contradicting_evidence,
                      }}
                    />
                  )}
                </section>
                {d.latest_run_id && <AgentFindings runId={d.latest_run_id} />}
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Evidence inventory")}</h2>
                    <span className="tag">
                      {d.evidence.length} {t("original alerts")}
                    </span>
                  </div>
                  {!d.evidence.length ? (
                    <div className="empty compact">
                      {t("Legacy evidence links unavailable.")}
                    </div>
                  ) : (
                    <div className="evidence-list">
                      {d.evidence.map((a) => (
                        <div className="evidence-row" key={a.id}>
                          <div className="evidence-icon">
                            {a.normalized.evidence.kind === "net" ? (
                              <Network size={17} />
                            ) : (
                              <Terminal size={17} />
                            )}
                          </div>
                          <div>
                            <Link
                              className="row-link"
                              to={"/console/alerts/" + encodeURIComponent(a.id)}
                            >
                              {a.normalized.evidence.description ||
                                a.normalized.event_type}
                            </Link>
                            <div className="sub mono">
                              {a.id} ·{" "}
                              {a.normalized.evidence.hostname ||
                                a.normalized.evidence.src_ip ||
                                t("No host identity")}
                            </div>
                            <div className="sub">
                              {t("Grouped:")}
                              {a.reason} · {stamp(a.received)}
                            </div>
                          </div>
                          <Badge value={a.normalized.severity} />
                        </div>
                      ))}
                    </div>
                  )}
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Investigation runs")}</h2>
                    <span className="tag">
                      {t("Immutable evidence snapshots")}
                    </span>
                  </div>
                  {!d.runs.length ? (
                    <div className="empty compact">
                      {t("No run metadata exists for this legacy case.")}
                    </div>
                  ) : (
                    d.runs.map((r) => (
                      <div className="run-row" key={r.id}>
                        <button
                          className="row-link"
                          onClick={() => setSelectedRun(r)}
                        >
                          <BookOpen size={16} />
                          <span className="mono">{short(r.id)}</span>
                          <ArrowUpRight size={13} />
                        </button>
                        <Badge value={r.status} />
                        <Badge value={r.replay ? "replay" : r.mode} />
                        <span className="small muted">
                          {r.model || r.provider || t("No provider data")}
                        </span>
                        {analyst && (
                          <button
                            disabled={
                              busy ||
                              r.status === "running" ||
                              r.status === "queued"
                            }
                            onClick={() => {
                              if (
                                confirm(
                                  t(
                                    "Call the configured model again with this frozen evidence snapshot? Replay cannot execute a response.",
                                  ),
                                )
                              )
                                void write("/incidents/" + id + "/replay", {
                                  parent_run_id: r.id,
                                });
                            }}
                          >
                            <Play size={13} />
                            {t("Replay")}
                          </button>
                        )}
                      </div>
                    ))
                  )}
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Analyst notes")}</h2>
                    <span className="tag">{t("Audited writes")}</span>
                  </div>
                  <div className="notes">
                    {d.notes.length ? (
                      d.notes.map((n) => (
                        <article key={n.id}>
                          <div>
                            <strong>{n.actor}</strong>
                            <small>{stamp(n.created)}</small>
                          </div>
                          <p>{n.body}</p>
                        </article>
                      ))
                    ) : (
                      <p className="muted">{t("No notes have been added.")}</p>
                    )}
                    {analyst && (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          void write("/incidents/" + id + "/notes", {
                            body: note,
                          });
                        }}
                      >
                        <label htmlFor="note">
                          {t("Add operational context")}
                        </label>
                        <textarea
                          id="note"
                          maxLength={8000}
                          required
                          value={note}
                          onChange={(e) => setNote(e.target.value)}
                          placeholder={t(
                            "Record observations, decisions, or follow-up work…",
                          )}
                        />
                        <button disabled={busy} className="primary">
                          {t("Add note")}
                        </button>
                      </form>
                    )}
                  </div>
                </section>
              </div>
              <aside className="investigation-side">
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Response review")}</h2>
                    <ShieldCheck size={17} />
                  </div>
                  <div className="side-content">
                    <label>{t("Proposed target")}</label>
                    <div className="target mono">
                      {d.target ?? t("No eligible target")}
                    </div>
                    <label>{t("Action")}</label>
                    <p>{t("Block cited network source")}</p>
                    <label>{t("Response mode")}</label>
                    <p>
                      <Badge value={d.response_mode} />
                    </p>
                    <label>{t("Current result")}</label>
                    <p>
                      <Badge value={d.status} />
                    </p>
                    <label>{t("Proposal expires")}</label>
                    <p>{stamp(d.proposal.expires)}</p>
                    <p className="mono small">{d.proposal.id}</p>
                    {d.status === "pending" &&
                      d.proposal.ineligibility_reason && (
                        <p className="small muted">
                          {t(d.proposal.ineligibility_reason)}
                        </p>
                      )}
                    <p className="muted small">
                      {t(
                        "Target and eligibility are validated again on the server. SSH requires a live verdict and human approval.",
                      )}
                    </p>
                    {approver && d.status === "pending" && (
                      <div className="response-buttons">
                        <button
                          className="primary"
                          disabled={!d.can_approve || busy}
                          onClick={() => {
                            if (
                              confirm(
                                t(
                                  "Approve this response under the configured mode?",
                                ),
                              )
                            )
                              void write("/incidents/" + id + "/response", {
                                decision: "approve",
                                run_id: d.latest_run_id,
                              });
                          }}
                        >
                          <Check size={15} />
                          {t("Approve response")}
                        </button>
                        <button
                          disabled={busy}
                          onClick={() =>
                            void write("/incidents/" + id + "/response", {
                              decision: "reject",
                              run_id: d.latest_run_id,
                            })
                          }
                        >
                          {t("Reject")}
                        </button>
                      </div>
                    )}
                    {!approver && (
                      <p className="small muted">
                        {t("Approver permission is required to decide.")}
                      </p>
                    )}
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Entities")}</h2>
                  </div>
                  <div className="side-content entities">
                    {(d.incident.entities ?? d.incident.ips).map((e) => (
                      <span className="mono" key={e}>
                        {e}
                      </span>
                    ))}
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Case integrations")}</h2>
                  </div>
                  <div className="side-content">
                    <label>{t("TheHive")}</label>
                    <p>
                      {d.integrations?.thehive ? (
                        <>
                          <Badge value={d.integrations.thehive.state} />{" "}
                          <span className="mono">
                            {d.integrations.thehive.remote_id ??
                              t("No remote ID yet")}
                          </span>
                        </>
                      ) : (
                        "Not queued"
                      )}
                    </p>
                    {d.integrations?.thehive?.error && (
                      <p className="warn">{d.integrations.thehive.error}</p>
                    )}
                    <label>{t("VirusTotal · public IP reputation")}</label>
                    {d.integrations?.virustotal.length ? (
                      d.integrations.virustotal.map((v) => (
                        <div className="job" key={v.ip}>
                          <span className="mono">{v.ip}</span>{" "}
                          <Badge value={v.status} />
                          {v.report?.stats && (
                            <p>
                              {t("Malicious:")}
                              {v.report.stats.malicious ?? 0}{" "}
                              {t("· Suspicious:")}
                              {v.report.stats.suspicious ?? 0}
                            </p>
                          )}
                          {v.report && (
                            <small>
                              {v.report.status} · {stamp(v.report.queried_at)}
                            </small>
                          )}
                          {v.error && <p className="warn">{v.error}</p>}
                        </div>
                      ))
                    ) : (
                      <p className="muted small">
                        {t("No public IP lookup queued.")}
                      </p>
                    )}
                    {!!d.integrations?.virustotal_hashes?.length && (
                      <>
                        <label>{t("File reputation (SHA256)")}</label>
                        {d.integrations.virustotal_hashes.map((item) => (
                          <div className="job" key={item.sha256}>
                            <code className="json">{item.sha256}</code>{" "}
                            <Badge value={item.status} />
                            {item.report && (
                              <p>
                                {item.report.status} ·{" "}
                                {stamp(item.report.queried_at)}
                              </p>
                            )}
                            {item.report?.stats && (
                              <p>
                                {t("Malicious:")}{" "}
                                {item.report.stats.malicious ?? 0}
                              </p>
                            )}
                            {item.error && <p className="warn">{item.error}</p>}
                            <small>
                              {t("Missing reputation does not mean safe.")}
                            </small>
                          </div>
                        ))}
                      </>
                    )}
                    <label>{t("Shuffle response notifications")}</label>
                    {d.integrations?.shuffle.length ? (
                      d.integrations.shuffle.map((event) => (
                        <div className="job" key={event.id}>
                          <Badge value={event.status} />{" "}
                          <span>
                            {t("Attempts:")}
                            {event.attempts}
                          </span>
                          {event.error && <p className="warn">{event.error}</p>}
                        </div>
                      ))
                    ) : (
                      <p className="muted small">
                        {t("No approved response event queued.")}
                      </p>
                    )}
                    <p className="muted small">
                      {t(
                        "Delivery status does not authorize or verify blocking. See Response history for the action result.",
                      )}
                    </p>
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Job state")}</h2>
                  </div>
                  <div className="side-content">
                    {d.jobs.map((j) => (
                      <div className="job" key={j.id}>
                        <Badge value={j.status} />
                        <span>
                          {t("Attempt")}
                          {j.attempts}/{j.max_attempts}
                        </span>
                        {j.error && <p className="warn">{j.error}</p>}
                      </div>
                    ))}
                    {!d.jobs.length && <p>{t("No job metadata")}</p>}
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>{t("Response history")}</h2>
                  </div>
                  <div className="side-content">
                    {d.actions.length ? (
                      d.actions.map((a) => (
                        <div className="job" key={a.id}>
                          <Badge value={a.result} />
                          <p>
                            {a.actor || t("Actor unavailable")} · {t(a.mode)}
                          </p>
                          <small>{stamp(a.ts)}</small>
                          <p className="muted small">
                            {t("Verification:")}
                            {t(a.verification_status)}
                          </p>
                          {a.managed_expires_at && (
                            <p className="muted small">
                              {t("Managed expiry")} ·{" "}
                              {stamp(a.managed_expires_at)}
                            </p>
                          )}
                          {a.managed_error && (
                            <p className="warn small">{t(a.managed_error)}</p>
                          )}
                        </div>
                      ))
                    ) : (
                      <p className="muted small">
                        {t("No response executed.")}
                      </p>
                    )}
                  </div>
                </section>
                {analyst && (
                  <section className="panel">
                    <div className="panel-heading">
                      <h2>{t("Workflow")}</h2>
                    </div>
                    <div className="side-content">
                      <select
                        aria-label={t("Update workflow")}
                        value={d.workflow_status}
                        disabled={busy}
                        onChange={(e) =>
                          void write(
                            "/incidents/" + id + "/workflow",
                            { status: e.target.value },
                            "PATCH",
                          )
                        }
                      >
                        {["open", "investigating", "review", "closed"].map(
                          (s) => (
                            <option key={s} value={s}>
                              {t(s)}
                            </option>
                          ),
                        )}
                      </select>
                    </div>
                  </section>
                )}
              </aside>
            </div>
            {selectedRun && (
              <RunModal
                run={selectedRun}
                close={() => setSelectedRun(undefined)}
              />
            )}
          </>
        )}
      </State>
    </>
  );
}
function AgentFindings({ runId }: { runId: string }) {
  const query = useData<Run>("/runs/" + runId);
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>{t("Net · Host · Judge")}</h2>
        <span className="tag">{t("Recorded role outcomes")}</span>
      </div>
      <div className="role-findings">
        {(
          [
            ["net", "Network evidence"],
            ["host", "Host & generic evidence"],
            ["judge", "Correlated decision"],
          ] as const
        ).map(([role, label]) => {
          const step = query.data?.steps
            ?.filter((s) => s.agent === role)
            .at(-1);
          const planned = query.data?.planned_steps
            ?.filter((s) => s.role === role)
            .at(-1);
          const output = step?.response;
          const value =
            output && typeof output === "object"
              ? (output as Record<string, unknown>)
              : undefined;
          const text = step?.error
            ? t("Analysis unavailable: ") + step.error
            : value
              ? String(
                  value.finding ??
                    value.reason ??
                    t("No decision summary returned"),
                )
              : query.error
                ? t("Data unavailable")
                : "No recorded output yet";
          return (
            <article key={role}>
              <div>
                <h3>{role.toUpperCase()}</h3>
                <Badge value={step?.status ?? planned?.status} />
              </div>
              <small>{label}</small>
              <p>{text}</p>
              <div className="sub">
                {step ? (
                  <>
                    <Badge value={step.mode} /> · {step.duration_ms.toFixed(0)}{" "}
                    {t("ms ·")}
                    {step.provider ?? t("Provider not recorded")}
                  </>
                ) : (
                  "Waiting for recorded step metadata"
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
function RunModal({ run, close }: { run: Run; close: () => void }) {
  const query = useData<Run>("/runs/" + run.id);
  return (
    <Modal title={t("Investigation ") + short(run.id)} onClose={close}>
      <State loading={query.loading && !query.data} error={query.error}>
        {query.data && (
          <>
            {!!run.replay && (
              <div className="notice">
                {t(
                  "Replay uses a frozen snapshot and cannot execute a response. Model output may differ.",
                )}
              </div>
            )}
            <div className="detail-meta">
              <Badge value={query.data.status} />
              <Badge value={query.data.mode} />
              <span>
                {t("Cutoff:")}
                {stamp(query.data.cutoff)}
              </span>
            </div>
            <div className="detail-meta">
              {query.data.planned_steps?.map((s) => (
                <span key={s.id}>
                  {s.role.toUpperCase()} <Badge value={s.status} />{" "}
                  {t("? attempt")} {s.attempt}
                </span>
              ))}
            </div>
            <StepList items={query.data.steps ?? []} />
            <h3>{t("Final structured verdict")}</h3>
            <Json value={query.data.verdict} />
          </>
        )}
      </State>
    </Modal>
  );
}
function StepList({ items }: { items: Step[] }) {
  return (
    <div className="timeline">
      {items.map((s) => (
        <details key={s.id}>
          <summary>
            <span className="timeline-dot" />
            <strong>{s.tool_name ?? s.agent.toUpperCase()}</strong>
            <Badge value={s.status} />
            <span className="mono small">
              {s.duration_ms.toFixed(0)} {t("ms")}
            </span>
            <ChevronDown size={14} />
          </summary>
          <div className="step-content">
            <div className="detail-meta">
              <Badge value={s.mode} />
              <span>
                {t("Provider:")}
                {s.provider ?? t("No data")}
              </span>
              <span>
                {t("Model:")}
                {s.model ?? t("No data")}
              </span>
              <span>
                {t("Attempt:")}
                {s.attempt ?? t("No data")}
              </span>
            </div>
            <h4>{t("Guarded input")}</h4>
            <Json value={s.prompt} />
            <h4>{t("Structured output")}</h4>
            <Json value={s.response} />
            <h4>{t("Usage / error")}</h4>
            <Json
              value={{
                usage: Object.keys(s.usage).length ? s.usage : null,
                model_attribution: s.model_source,
                error: s.error,
                prompt_version: s.prompt_version,
              }}
            />
          </div>
        </details>
      ))}
    </div>
  );
}
function LedgerPage() {
  const [offset, setOffset] = useState(0),
    [role, setRole] = useState(""),
    [selected, setSelected] = useState<Step>();
  const query = useData<Page<Step>>(
    "/ledger?" +
      new URLSearchParams({ limit: "25", offset: String(offset), role }),
  );
  const d = query.data;
  return (
    <>
      <PageTitle
        eyebrow={t("ACCOUNTABILITY")}
        title={t("Investigation ledger")}
        description={t(
          "Guarded model inputs, bounded read-only tools, citations, and recorded outcomes.",
        )}
      >
        <Updated value={query.updated} error={query.error} />
      </PageTitle>
      <div className="filter-bar">
        <select
          aria-label={t("Agent role filter")}
          value={role}
          onChange={(e) => {
            setRole(e.target.value);
            setOffset(0);
          }}
        >
          <option value="">{t("All roles and tools")}</option>
          {["net", "host", "judge", "tool"].map((v) => (
            <option key={v} value={v}>
              {t(v)}
            </option>
          ))}
        </select>
        <span className="muted small">
          {t("Missing legacy metadata is shown as no data.")}
        </span>
      </div>
      <section className="panel">
        <State
          loading={!d && query.loading}
          error={!d ? query.error : undefined}
          empty={d?.total === 0}
        >
          {d && (
            <>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>{t("Step / incident")}</th>
                      <th>{t("Agent or tool")}</th>
                      <th>{t("Provider / model")}</th>
                      <th>{t("Mode")}</th>
                      <th>{t("Duration")}</th>
                      <th>{t("Result")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.items.map((s) => (
                      <tr key={s.id}>
                        <td>
                          <button
                            className="row-link mono"
                            onClick={() => setSelected(s)}
                          >
                            STEP-{s.id} <ArrowUpRight size={12} />
                          </button>
                          <Link
                            className="sub mono"
                            to={"/console/incidents/" + s.case_id}
                          >
                            {short(s.case_id)}
                          </Link>
                        </td>
                        <td>
                          {s.tool_name ?? s.agent.toUpperCase()}
                          <span className="sub">
                            {s.prompt_version ?? t("No version metadata")}
                          </span>
                        </td>
                        <td>
                          {s.provider ?? t("No data")}
                          <span className="sub mono">
                            {s.model ?? t("No model data")}
                          </span>
                        </td>
                        <td>
                          <Badge value={s.mode} />
                        </td>
                        <td className="mono">
                          {s.duration_ms.toFixed(0)} {t("ms")}
                        </td>
                        <td>
                          <Badge value={s.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager total={d.total} offset={offset} change={setOffset} />
            </>
          )}
        </State>
      </section>
      {selected && (
        <Modal
          title={t("Ledger step ") + selected.id}
          onClose={() => setSelected(undefined)}
        >
          <StepList items={[selected]} />
          <p className="muted small">
            {t("Recorded")}
            {stamp(selected.ts)} {t("· run")}{" "}
            {selected.run_id ?? t("No run metadata")}
          </p>
        </Modal>
      )}
    </>
  );
}
function ResponsesPage() {
  const [offset, setOffset] = useState(0);
  const query = useData<Page<Incident>>(
    "/incidents?status=review&response_status=pending&limit=25&offset=" +
      offset,
  );
  const d = query.data;
  return (
    <>
      <PageTitle
        eyebrow={t("HUMAN IN THE LOOP")}
        title={t("Response review")}
        description={t(
          "Review evidence and policy eligibility before deciding. No automatic execution.",
        )}
      >
        <span className="tag">
          <ShieldCheck size={14} />
          {t("Human approval required")}
        </span>
      </PageTitle>
      <section className="panel">
        <div className="panel-heading">
          <h2>{t("Review queue")}</h2>
          <Link to="/console/incidents" className="text-link">
            {t("Full paginated queue")}
            <ArrowUpRight size={14} />
          </Link>
        </div>
        <State
          loading={!d && query.loading}
          error={!d ? query.error : undefined}
          empty={d?.total === 0}
        >
          {d && (
            <>
              <IncidentTable items={d.items} />
              <Pager total={d.total} offset={offset} change={setOffset} />
            </>
          )}
        </State>
      </section>
    </>
  );
}
function SystemPage() {
  const query = useData<Health>("/system");
  const d = query.data;
  const actor = useContext(Session)!;
  const [notice, setNotice] = useState("");
  async function user(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget,
      values = new FormData(form);
    try {
      await api("/users", {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(values)),
      });
      setNotice("User created.");
      form.reset();
    } catch (e) {
      setNotice((e as Error).message);
    }
  }
  return (
    <>
      <PageTitle
        eyebrow={t("OPERATIONS")}
        title={t("System health")}
        description={t(
          "Measured backend and worker state. Configuration does not imply connectivity.",
        )}
      >
        <Updated value={query.updated} error={query.error} />
        <button onClick={query.refresh}>
          <RefreshCw size={15} />
          {t("Refresh")}
        </button>
      </PageTitle>
      <State loading={!d && query.loading} error={!d ? query.error : undefined}>
        {d && (
          <>
            <div className="health-grid">
              <section className="panel health-card">
                <Database />
                <h2>{t("Database")}</h2>
                <Badge value={d.database} />
                <p>{t("SQLite · durable local storage")}</p>
              </section>
              <section className="panel health-card">
                <Activity />
                <h2>{t("Background worker")}</h2>
                <Badge value={d.worker_fresh ? "active" : "stale"} />
                <p>
                  {d.backlog} {t("queued/running jobs ·")}
                  {d.dead_letters} {t("dead letters")}
                </p>
              </section>
              <section className="panel health-card">
                <Network />
                <h2>{t("Wazuh source")}</h2>
                <Badge value="not probed" />
                <p>
                  {t("Last alert:")}
                  {stamp(d.last_alert_at)}
                </p>
              </section>
            </div>
            <div className="two-columns">
              <section className="panel">
                <div className="panel-heading">
                  <h2>{t("LLM provider")}</h2>
                  <Badge value={d.provider.mode} />
                </div>
                <dl>
                  <dt>{t("Provider")}</dt>
                  <dd>{d.provider.name}</dd>
                  <dt>{t("Configured")}</dt>
                  <dd>
                    {d.provider.configured
                      ? t("Yes")
                      : t("No hosted configuration")}
                  </dd>
                  <dt>{t("Model")}</dt>
                  <dd className="mono">
                    {d.provider.model ?? t("No model attribution (mock)")}
                  </dd>
                  <dt>{t("Reachability")}</dt>
                  <dd>{t("Not actively probed")}</dd>
                  <dt>{t("Last call")}</dt>
                  <dd>{stamp(d.provider.last_call?.ts)}</dd>
                  <dt>{t("Last error")}</dt>
                  <dd>
                    {d.provider.last_call?.error ?? t("No recorded error")}
                  </dd>
                  <dt>{t("Response mode")}</dt>
                  <dd>
                    <Badge value={d.response_mode} />
                  </dd>
                  <dt>{t("Demo isolation")}</dt>
                  <dd>
                    {d.demo
                      ? t("Synthetic demo database")
                      : t("Production database")}
                  </dd>
                </dl>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>{t("External integrations")}</h2>
                </div>
                <div className="side-content">
                  {Object.entries(d.integrations ?? {}).map(
                    ([name, integration]) => (
                      <div className="job" key={name}>
                        <strong>
                          {name === "virustotal"
                            ? t("VirusTotal")
                            : name === "thehive"
                              ? t("TheHive")
                              : t("Shuffle")}
                        </strong>
                        <p>
                          {integration.active
                            ? t("Enabled")
                            : integration.configured
                              ? t("Disabled in demo")
                              : t("Not configured")}
                        </p>
                        <p className="muted small">
                          {Object.entries(integration.states)
                            .map(([state, count]) => state + ": " + count)
                            .join(" · ") || t("No queued work")}
                        </p>
                        {integration.errors > 0 && (
                          <p className="warn">
                            {integration.errors}{" "}
                            {t("entries need retry or review")}
                          </p>
                        )}
                      </div>
                    ),
                  )}
                  <p className="muted small">
                    {t(
                      "Configuration and queue state only; external reachability is not actively probed.",
                    )}
                  </p>
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>{t("Worker heartbeats")}</h2>
                  <span className="tag">{t("UTC storage")}</span>
                </div>
                <div className="side-content">
                  {d.workers.length ? (
                    d.workers.map((w) => (
                      <div className="worker" key={w.id}>
                        <span className="mono">{short(w.id)}</span>
                        <span>{stamp(w.last_seen)}</span>
                        <span className="muted">
                          {w.current_job
                            ? t("Processing ") + short(w.current_job)
                            : t("Idle at last heartbeat")}
                        </span>
                      </div>
                    ))
                  ) : (
                    <div className="empty compact">
                      {t("No heartbeat received. Start python -m src.worker.")}
                    </div>
                  )}
                  <p className="muted small">
                    {t("Oldest active job:")}{" "}
                    {d.oldest_job_age_seconds === null
                      ? t("No jobs")
                      : Math.floor(d.oldest_job_age_seconds) + t(" seconds")}
                  </p>
                </div>
              </section>
            </div>
            {actor.role === "admin" && (
              <section className="panel">
                <div className="panel-heading">
                  <h2>{t("Create operator account")}</h2>
                  <UserRound size={16} />
                </div>
                <form className="user-form" onSubmit={user}>
                  <label>
                    {t("Username")}
                    <input
                      name="username"
                      required
                      maxLength={80}
                      autoComplete="off"
                    />
                  </label>
                  <label>
                    {t("Password")}
                    <input
                      name="password"
                      type="password"
                      required
                      minLength={16}
                      autoComplete="new-password"
                    />
                  </label>
                  <label>
                    {t("Role")}
                    <select name="role">
                      {["viewer", "analyst", "approver", "admin"].map((r) => (
                        <option key={r} value={r}>
                          {t(r)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button className="primary">{t("Create user")}</button>
                  {notice && <p role="status">{t(notice)}</p>}
                </form>
              </section>
            )}
          </>
        )}
      </State>
    </>
  );
}
function AuditPage() {
  const [offset, setOffset] = useState(0);
  const query = useData<Page<Audit>>("/audit?offset=" + offset);
  const d = query.data;
  return (
    <>
      <PageTitle
        eyebrow={t("GOVERNANCE")}
        title={t("Audit log")}
        description={t(
          "Who changed what, when, and with which recorded result.",
        )}
      >
        <Updated value={query.updated} error={query.error} />
      </PageTitle>
      <section className="panel">
        <State
          loading={!d && query.loading}
          error={!d ? query.error : undefined}
          empty={d?.total === 0}
        >
          {d && (
            <>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>{t("Timestamp")}</th>
                      <th>{t("Actor")}</th>
                      <th>{t("Operation")}</th>
                      <th>{t("Target")}</th>
                      <th>{t("Result")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.items.map((a) => (
                      <tr key={a.id}>
                        <td className="small muted">{stamp(a.ts)}</td>
                        <td>
                          <span className="actor">
                            <UserRound size={14} />
                            {a.actor}
                          </span>
                        </td>
                        <td>{a.action}</td>
                        <td className="mono small">
                          {a.target ? short(a.target) : "—"}
                        </td>
                        <td>
                          <Badge value={a.result} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager total={d.total} offset={offset} change={setOffset} />
            </>
          )}
        </State>
      </section>
    </>
  );
}
const navigation = [
  ["Overview", "/console", LayoutDashboard],
  ["Alerts", "/console/alerts", Bell],
  ["Incidents", "/console/incidents", Layers],
  ["Investigation ledger", "/console/ledger", BookOpen],
  ["Response review", "/console/responses", ShieldCheck],
  ["System health", "/console/system", Server],
  ["Audit log", "/console/audit", FileText],
] as const;
function Shell({ actor, logout }: { actor: Actor; logout: () => void }) {
  const location = useLocation();
  const query = useData<Health>("/system");
  const current =
    navigation.find((n) => n[1] === location.pathname)?.[0] ??
    "Investigation workspace";
  return (
    <Session.Provider value={actor}>
      <div className="shell">
        <aside className="sidebar">
          <Link
            to="/console"
            className="brand"
            aria-label={t("AgentSOC overview")}
          >
            <div className="brand-icon">
              <Shield size={22} />
            </div>
            <span>
              Agent<span className="brand-accent">SOC</span>
              <small>{t("SECURITY OPERATIONS")}</small>
            </span>
          </Link>
          <div className="workspace">
            <span className="workspace-icon">
              <Layers size={16} />
            </span>
            <div>
              {t("Operations workspace")}
              <small>{t("Self-hosted console")}</small>
            </div>
            <ChevronDown size={13} />
          </div>
          <div className="nav-label">{t("WORKSPACE")}</div>
          <nav aria-label={t("Primary navigation")}>
            {navigation.map(([label, to, Icon]) => (
              <NavLink
                end={to === "/console"}
                to={to}
                key={to}
                aria-label={t(label)}
              >
                <Icon size={17} />
                <span>{t(label)}</span>
                {label === "Response review" && <span className="nav-dot" />}
              </NavLink>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <div className="environment">
              <span
                className={"dot " + (!query.data?.worker_fresh ? "amber" : "")}
              />
              <div>
                {query.data?.demo
                  ? t("Synthetic demo")
                  : query.data?.worker_fresh
                    ? t("Worker active")
                    : t("Worker not verified")}
                <small>
                  {t(query.data?.response_mode ?? "Awaiting system state")}
                </small>
              </div>
            </div>
            <button className="profile" onClick={logout}>
              <span className="avatar">
                {actor.username.slice(0, 2).toUpperCase()}
              </span>
              <span>
                {actor.username}
                <small>{t(actor.role)}</small>
              </span>
              <LogOut size={15} />
            </button>
          </div>
        </aside>
        <div className="content">
          <header className="topbar">
            <div>
              <span className="muted">{t("Workspace")}</span>
              <ChevronRight size={14} />
              <span>{t(current)}</span>
            </div>
            <div>
              <LanguageSwitcher />
              <span className="timezone">
                <Clock size={13} />
                {Intl.DateTimeFormat().resolvedOptions().timeZone}
              </span>
              <span className="top-divider" />
              <span className="small muted">{t("AgentSOC / v0.2")}</span>
            </div>
            <button
              className="mobile-logout"
              aria-label={t("Sign out")}
              onClick={logout}
            >
              <LogOut size={16} />
            </button>
          </header>
          <main>
            <Routes>
              <Route path="/console" element={<OverviewPage />} />
              <Route path="/console/alerts" element={<AlertsPage />} />
              <Route path="/console/alerts/:id" element={<AlertPage />} />
              <Route path="/console/incidents" element={<IncidentsPage />} />
              <Route path="/console/incidents/:id" element={<IncidentPage />} />
              <Route path="/console/ledger" element={<LedgerPage />} />
              <Route path="/console/responses" element={<ResponsesPage />} />
              <Route path="/console/system" element={<SystemPage />} />
              <Route path="/console/audit" element={<AuditPage />} />
              <Route
                path="*"
                element={
                  <div className="empty">
                    <h1>{t("Page not found")}</h1>
                    <Link to="/console">{t("Return to overview")}</Link>
                  </div>
                }
              />
            </Routes>
            <footer>
              {t("AgentSOC · Evidence before action")}
              <span>
                {t("All timestamps displayed in your local timezone")}
              </span>
            </footer>
          </main>
        </div>
        <AssistantPanel
          key={actor.username}
          username={actor.username}
          role={actor.role}
        />
      </div>
    </Session.Provider>
  );
}
function App() {
  useLanguage();
  const [actor, setActor] = useState<Actor | null>(),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    const expired = () => {
      setActor(null);
      setCsrf("");
    };
    window.addEventListener("agentsoc:unauthorized", expired);
    return () => window.removeEventListener("agentsoc:unauthorized", expired);
  }, []);
  useEffect(() => {
    api<Actor>("/auth/me")
      .then((a) => {
        setActor(a);
        setCsrf(a.csrf);
      })
      .catch(() => setActor(null));
  }, []);
  async function login(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const values = Object.fromEntries(new FormData(e.currentTarget));
      const a = await api<Actor>("/auth/login", {
        method: "POST",
        body: JSON.stringify(values),
      });
      setCsrf(a.csrf);
      setActor(a);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function logout() {
    try {
      await api("/auth/logout", { method: "POST" });
      setCsrf("");
      setActor(null);
    } catch (e) {
      alert((e as Error).message);
    }
  }
  if (actor === undefined)
    return (
      <div className="login">
        <State loading>
          <span />
        </State>
      </div>
    );
  if (!actor)
    return (
      <div className="login">
        <LanguageSwitcher />
        <div className="login-brand">
          <Shield size={30} />
          <span>AgentSOC</span>
        </div>
        <section className="login-card">
          <span className="eyebrow">{t("SECURITY OPERATIONS WORKSPACE")}</span>
          <h1>{t("Welcome back.")}</h1>
          <p>
            {t("Sign in to investigate alerts and review response decisions.")}
          </p>
          <form onSubmit={login}>
            <label htmlFor="username">{t("Username")}</label>
            <input
              id="username"
              name="username"
              required
              autoComplete="username"
              placeholder={t("Your operator account")}
            />
            <label htmlFor="password">{t("Password")}</label>
            <input
              id="password"
              name="password"
              type="password"
              required
              autoComplete="current-password"
            />
            {error && (
              <p role="alert" className="warn">
                {t(error)}
              </p>
            )}
            <button className="primary" disabled={busy}>
              {busy ? t("Signing in…") : t("Sign in to workspace")}
              <ArrowUpRight size={16} />
            </button>
          </form>
          <div className="login-note">
            <ShieldCheck size={15} />
            <span>
              {t("Self-hosted · server-side session · human-approved response")}
            </span>
          </div>
        </section>
        <p className="login-foot">
          {t("Evidence-driven operations. Every decision accountable.")}
        </p>
      </div>
    );
  return <Shell actor={actor} logout={() => void logout()} />;
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
