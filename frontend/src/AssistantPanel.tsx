import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { Link, useLocation } from "react-router-dom";
import { api } from "./api";
import { t, useLanguage } from "./i18n";

type Fact = {
  incident_id: string;
  status: string;
  priority: string;
  wazuh_level: number;
  missing_evidence: boolean;
  verdict: string | null;
  confidence: number | null;
  grounded: number | null;
  source_ips: string[];
  destination_ips: string[];
  policy_explanation: string;
  rules: { evidence_id: string; rule_id: string; level: number | null }[];
  proposal: {
    id: string;
    eligible: boolean;
    source_ip: string | null;
    expires: number;
  };
};
type Citation = {
  id: string;
  source: string;
  incident_id: string;
  normalized: unknown;
};
type Answer = {
  language: string;
  summary: string;
  notice: string;
  interpretation: string | null;
  model_status: string;
  fallback?: {
    origin: "stored_analysis";
    label: string;
    text: string;
    truncated: boolean;
  } | null;
  facts: Fact[];
  citations: Citation[];
  analysis: unknown[];
  related?: { incident_id: string; run_id: string; status: string }[];
  truncated: boolean;
};
type Thread = {
  id: string;
  title: string;
  incident_id: string | null;
  archived: number;
};
type ResponseIntent = {
  id: string;
  case_id: string;
  run_id: string;
  target: string;
  approval_policy: string;
  status: string;
  mode: string;
  expires: number;
  ttl: number;
  justification: string;
  evidence_ids: string[];
  evidence_gaps: string[];
  original_judge_verdict: string;
};
type Message = {
  id: string;
  request_key: string;
  question: string;
  status: string;
  incident_id: string | null;
  answer?: Answer;
  error?: string;
};
type History = {
  thread: Thread;
  messages: Message[];
  actions: ResponseIntent[];
  before: number | null;
};
type Outbound = {
  request_key: string;
  message: string;
  incident_id: string | null;
  language: string;
};
const path = "/assistant/threads";

function Markdown({ text }: { text: string }) {
  return (
    <div className="assistant-interpretation">
      {text.split("\n").map((line, i) => (
        <div key={i}>
          {line
            .split(/(\*\*[^*]+\*\*|`[^`]+`)/)
            .map((part, j) =>
              part.startsWith("**") && part.endsWith("**") ? (
                <strong key={j}>{part.slice(2, -2)}</strong>
              ) : part.startsWith("`") && part.endsWith("`") ? (
                <code key={j}>{part.slice(1, -1)}</code>
              ) : (
                <span key={j}>{part}</span>
              ),
            )}
        </div>
      ))}
    </div>
  );
}

export function AssistantPanel({
  username,
  role,
}: {
  username: string;
  role: string;
}) {
  const [language] = useLanguage();
  const label = (en: string, vi: string) => (language === "vi" ? vi : en);
  const [open, setOpen] = useState(false);
  const [wide, setWide] = useState(false);
  const [threads, setThreads] = useState<Thread[]>([]);
  const [offset, setOffset] = useState(30);
  const [more, setMore] = useState(false);
  const [selected, select] = useState(
    () => localStorage.getItem("agentsoc-copilot:" + username) ?? "",
  );
  const [details, setDetails] = useState<Record<string, History>>({});
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [pending, setPending] = useState<Record<string, Outbound>>({});
  const sending = useRef(new Set<string>());
  const [busyIds, setBusyIds] = useState<string[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [link, setLink] = useState<{ thread: string; code: string }>();
  const [policy, setPolicy] = useState("standard");
  const [justification, setJustification] = useState("");
  const [actionBusy, setActionBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const canDecide = role === "approver" || role === "admin";
  const location = useLocation();
  const incidentId = location.pathname.match(
    /^\/console\/incidents\/([^/]+)$/,
  )?.[1];
  const current = details[selected];
  const text = drafts[selected] ?? "";
  const messages = current?.messages ?? [];
  const busy = busyIds.includes(selected);
  const version = useRef<Record<string, number>>({});
  const setError = (id: string, error: string) =>
    setErrors((previous) => ({ ...previous, [id]: error }));
  const reload = useCallback(async (id: string, before?: number) => {
    const serial = (version.current[id] ?? 0) + 1;
    version.current[id] = serial;
    const next = await api<History>(
      path + "/" + id + (before ? "?before=" + before : ""),
    );
    if (version.current[id] !== serial) return;
    setDetails((previous) => ({
      ...previous,
      [id]: before
        ? { ...next, messages: [...next.messages, ...previous[id].messages] }
        : next,
    }));
  }, []);
  const listing = useCallback(async () => {
    const result = await api<{ items: Thread[]; more: boolean }>(path);
    setThreads(result.items);
    setMore(result.more);
    setOffset(result.items.length);
    select(
      (previous) =>
        previous || result.items.find((thread) => !thread.archived)?.id || "",
    );
  }, []);
  useEffect(() => {
    if (!open) return;
    void listing().catch((error: Error) =>
      setErrors((previous) => ({ ...previous, "": error.message })),
    );
  }, [open, listing]);
  useEffect(() => {
    if (!open || !selected) return;
    localStorage.setItem("agentsoc-copilot:" + username, selected);
    const load = () =>
      void reload(selected).catch((error: Error) =>
        setErrors((previous) => ({ ...previous, [selected]: error.message })),
      );
    load();
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, [open, selected, reload, username]);
  async function createThread() {
    setCreating(true);
    try {
      const thread = await api<Thread>(path, {
        method: "POST",
        body: JSON.stringify({ incident_id: incidentId }),
      });
      setThreads((previous) => [thread, ...previous]);
      select(thread.id);
      return thread.id;
    } finally {
      setCreating(false);
    }
  }
  async function ask(question: string, retry?: Outbound) {
    if (busy || !question.trim()) return;
    const reserved = selected;
    if (sending.current.has(reserved)) return;
    sending.current.add(reserved);
    let id = selected;
    try {
      if (!id) id = await createThread();
      const context =
        retry?.incident_id ?? incidentId ?? current?.thread.incident_id ?? null;
      const payload = retry ?? {
        message: question,
        language,
        incident_id: context,
        request_key: Array.from(
          crypto.getRandomValues(new Uint8Array(16)),
          (n) => n.toString(16).padStart(2, "0"),
        ).join(""),
      };
      setBusyIds((previous) => [...previous, id]);
      setError(id, "");
      setPending((previous) => ({ ...previous, [id]: payload }));
      await api<Message>(path + "/" + id + "/messages", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setDrafts((previous) =>
        previous[reserved] === question
          ? { ...previous, [reserved]: "" }
          : previous,
      );
      await reload(id);
      setPending((previous) => {
        const next = { ...previous };
        delete next[id];
        return next;
      });
    } catch (error) {
      setError(
        id,
        error instanceof Error
          ? error.message
          : t("Assistant unavailable. Try again."),
      );
    } finally {
      sending.current.delete(reserved);
      setBusyIds((previous) => previous.filter((value) => value !== id));
    }
  }
  async function update(body: object) {
    await api(path + "/" + selected, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
    await Promise.all([listing(), reload(selected)]);
  }
  async function action(id?: string, decision?: "approve" | "reject") {
    if (actionBusy) return;
    const ownerThread = selected;
    setActionBusy(true);
    setError(ownerThread, "");
    try {
      await api(path + "/" + ownerThread + "/actions" + (id ? "/" + id : ""), {
        method: "POST",
        body: JSON.stringify(
          id
            ? { decision }
            : {
                policy,
                justification,
                incident_id: incidentId ?? current?.thread.incident_id,
              },
        ),
      });
      await reload(ownerThread);
    } catch (error) {
      setError(
        ownerThread,
        error instanceof Error
          ? error.message
          : t("Assistant unavailable. Try again."),
      );
    } finally {
      setActionBusy(false);
    }
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    void ask(text);
  }
  return (
    <div className="assistant">
      <button
        className="assistant-entry primary"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
      >
        {t("AI Assistant")}
      </button>
      {open && (
        <section
          className={"assistant-panel panel" + (wide ? " assistant-wide" : "")}
          aria-label={t("AI Assistant")}
        >
          <div className="panel-heading">
            <h2>{t("AI Assistant")}</h2>
            <button onClick={() => setWide(!wide)}>
              {wide ? label("Compact", "Thu gọn") : label("Expand", "Mở rộng")}
            </button>
            <button
              aria-label={t("Close assistant")}
              onClick={() => setOpen(false)}
            >
              ×
            </button>
          </div>
          <div className="assistant-threads">
            <select
              aria-label={label("Conversation history", "Lịch sử hội thoại")}
              value={selected}
              onChange={(event) => {
                select(event.target.value);
                setJustification("");
              }}
            >
              <option value="">
                {label("Select conversation", "Chọn hội thoại")}
              </option>
              {threads.map((thread) => (
                <option key={thread.id} value={thread.id}>
                  {thread.title}
                  {thread.archived
                    ? " · " + label("Archived", "Đã lưu trữ")
                    : ""}
                </option>
              ))}
            </select>
            <button
              disabled={creating}
              onClick={() =>
                void createThread().catch((error) =>
                  setError(selected, error.message),
                )
              }
            >
              {label("New Chat", "Hội thoại mới")}
            </button>
            {more && (
              <button
                onClick={() =>
                  void api<{ items: Thread[]; more: boolean }>(
                    path + "?offset=" + offset,
                  )
                    .then((result) => {
                      setThreads((previous) => [
                        ...previous,
                        ...result.items.filter(
                          (thread) =>
                            !previous.some((item) => item.id === thread.id),
                        ),
                      ]);
                      setOffset((value) => value + result.items.length);
                      setMore(result.more);
                    })
                    .catch((error) => setError(selected, error.message))
                }
              >
                {label("More", "Xem thêm")}
              </button>
            )}
          </div>
          {selected && (
            <div className="assistant-threads">
              <button
                onClick={() => {
                  const title = window.prompt(
                    label("Conversation title", "Tên hội thoại"),
                    current?.thread.title,
                  );
                  if (title?.trim())
                    void update({ title }).catch((error) =>
                      setError(selected, error.message),
                    );
                }}
              >
                {label("Rename", "Đổi tên")}
              </button>
              <button
                onClick={() =>
                  void update({ archived: !current?.thread.archived }).catch(
                    (error) => setError(selected, error.message),
                  )
                }
              >
                {current?.thread.archived
                  ? label("Restore", "Khôi phục")
                  : label("Archive", "Lưu trữ")}
              </button>
              <button
                disabled={!!current?.thread.archived}
                onClick={() =>
                  void api<{ code: string }>(
                    path + "/" + selected + "/telegram-link",
                    { method: "POST" },
                  )
                    .then((result) =>
                      setLink({ thread: selected, code: result.code }),
                    )
                    .catch((error) => setError(selected, error.message))
                }
              >
                {label("Link Telegram", "Liên kết Telegram")}
              </button>
            </div>
          )}
          {link?.thread === selected && (
            <p className="mono">
              {label(
                "Send in a private bot chat within 5 minutes",
                "Gửi trong chat riêng với bot trong 5 phút",
              )}
              : /link {link.code}
            </p>
          )}
          {(incidentId || current?.thread.incident_id) && (
            <p className="mono">
              {label("Incident context", "Ngữ cảnh sự cố")}:{" "}
              {incidentId ?? current?.thread.incident_id}
            </p>
          )}
          <div className="assistant-suggestions">
            {[
              "Review the last 24 hours",
              "Are any proposals pending approval?",
              "Why was this action recommended?",
            ].map((key) => (
              <button
                key={key}
                disabled={creating || busy || !!current?.thread.archived}
                onClick={() => void ask(t(key))}
              >
                {t(key)}
              </button>
            ))}
          </div>
          <div className="assistant-messages" role="log" aria-live="polite">
            {current?.before && (
              <button
                onClick={() =>
                  void reload(selected, current.before ?? undefined).catch(
                    (error) => setError(selected, error.message),
                  )
                }
              >
                {label("Older messages", "Tin nhắn cũ hơn")}
              </button>
            )}
            {!messages.length && (
              <p>
                {t(
                  "Ask about stored incidents or open an incident for context.",
                )}
              </p>
            )}
            {messages.map((message) => (
              <article key={message.id}>
                <strong>{message.question}</strong>
                {message.error && <p role="alert">{message.error}</p>}
                {!message.answer && (
                  <p>
                    {message.status === "failed"
                      ? label(
                          "Request failed. Resend to retry.",
                          "Yêu cầu lỗi. Gửi lại để thử tiếp.",
                        )
                      : label("Processing", "Đang xử lý")}
                  </p>
                )}
                {message.answer && (
                  <>
                    <p>{message.answer.summary}</p>
                    <p className="small muted">{message.answer.notice}</p>
                    {message.answer.model_status === "unavailable" && (
                      <p>{t("Model unavailable; evidence is still shown.")}</p>
                    )}
                    {message.answer.fallback && (
                      <section aria-label={message.answer.fallback.label}>
                        <h3>{message.answer.fallback.label}</h3>
                        <Markdown text={message.answer.fallback.text} />
                      </section>
                    )}
                    {message.answer.truncated && (
                      <p>
                        {t(
                          "Results limited. Use the incident queue for all records.",
                        )}
                      </p>
                    )}
                    <h3>{t("Evidence-based facts")}</h3>
                    {message.answer.facts.map((fact) => (
                      <p key={fact.incident_id}>
                        <Link
                          to={
                            "/console/incidents/" +
                            encodeURIComponent(fact.incident_id)
                          }
                        >
                          {fact.incident_id}
                        </Link>
                        {" · "}
                        {t(fact.status)}
                        {" · "}
                        {t(fact.priority)}
                        {" · Wazuh "}
                        {fact.wazuh_level}
                        {fact.proposal.source_ip && (
                          <span className="mono">
                            {" · "}
                            {fact.proposal.source_ip}
                          </span>
                        )}
                        <br />
                        {t("Stored verdict")}:{" "}
                        {fact.verdict ?? t("Data unavailable")}
                        {" · "}
                        {t("Confidence")}:{" "}
                        {fact.confidence ?? t("Data unavailable")}
                        {" · grounded="}
                        {fact.grounded ?? "?"}
                        {!!(
                          fact.source_ips.length || fact.destination_ips.length
                        ) && (
                          <span className="mono">
                            <br />
                            {fact.source_ips.join(", ") || "?"} →{" "}
                            {fact.destination_ips.join(", ") || "?"}
                          </span>
                        )}
                        {fact.rules.map((rule) => (
                          <span key={rule.evidence_id}>
                            <br />
                            Wazuh {rule.rule_id || "?"} · level{" "}
                            {rule.level ?? "?"} · [{rule.evidence_id}]
                          </span>
                        ))}
                        <br />
                        {fact.policy_explanation}
                        {fact.missing_evidence && (
                          <span>
                            {" · "}
                            {t("Missing evidence")}
                          </span>
                        )}
                        <br />
                        <Link
                          to={
                            "/console/incidents/" +
                            encodeURIComponent(fact.incident_id)
                          }
                        >
                          {t("Open evidence and review proposal")}
                        </Link>
                      </p>
                    ))}
                    <details>
                      <summary>{t("Evidence citations")}</summary>
                      {message.answer.citations.map((citation) => (
                        <div key={citation.incident_id + citation.id}>
                          <Link
                            to={
                              "/console/alerts/" +
                              encodeURIComponent(citation.id)
                            }
                          >
                            [{citation.source}:{citation.id}]
                          </Link>
                        </div>
                      ))}
                    </details>
                    {message.answer.related && (
                      <details>
                        <summary>
                          {label(
                            "Related investigations (historical)",
                            "Điều tra liên quan (lịch sử)",
                          )}
                        </summary>
                        {message.answer.related.map((item) => (
                          <p key={item.run_id}>
                            <Link
                              to={
                                "/console/incidents/" +
                                encodeURIComponent(item.incident_id)
                              }
                            >
                              {item.incident_id}
                            </Link>{" "}
                            · {item.status}
                          </p>
                        ))}
                      </details>
                    )}
                    <details>
                      <summary>{t("Stored AI analysis")}</summary>
                      <pre className="json">
                        {JSON.stringify(message.answer.analysis, null, 2)}
                      </pre>
                    </details>
                    {message.answer.interpretation && (
                      <>
                        <h3>{t("AI interpretation")}</h3>
                        <Markdown text={message.answer.interpretation} />
                      </>
                    )}
                  </>
                )}
              </article>
            ))}
            {current?.actions.map((item) => (
              <article key={item.id} className="assistant-action">
                <h3>{label("Response preview", "Xem trước phản ứng")}</h3>
                <p className="mono">
                  {item.case_id} / {item.run_id}
                </p>
                <p>
                  {label("Source", "Nguồn")} {item.target} ·{" "}
                  {item.original_judge_verdict} · {item.approval_policy}
                </p>
                <p>
                  {t("Evidence citations")} {item.evidence_ids.join(", ")}
                </p>
                <p>{item.evidence_gaps.join(" · ")}</p>
                {item.justification && <p>{item.justification}</p>}
                <p>
                  {item.mode} · {item.status} · {item.ttl / 3600}h ·{" "}
                  {new Date(item.expires * 1000).toLocaleString(language)}
                </p>
                {canDecide &&
                  item.status === "prepared" &&
                  !current.thread.archived && (
                    <>
                      <button
                        disabled={actionBusy}
                        onClick={() => void action(item.id, "approve")}
                      >
                        {t("Approve")}
                      </button>
                      <button
                        disabled={actionBusy}
                        onClick={() => void action(item.id, "reject")}
                      >
                        {t("Reject")}
                      </button>
                    </>
                  )}
              </article>
            ))}
            {busy && <p role="status">{t("Reading evidence…")}</p>}
          </div>
          {(errors[selected] || errors[""]) && (
            <p role="alert">
              {errors[selected] || errors[""]}{" "}
              {pending[selected] && (
                <button
                  onClick={() =>
                    void ask(pending[selected].message, pending[selected])
                  }
                >
                  {label("Retry", "Thử lại")}
                </button>
              )}
            </p>
          )}
          {canDecide &&
            selected &&
            !current?.thread.archived &&
            (incidentId || current?.thread.incident_id) && (
              <details className="assistant-action">
                <summary>
                  {label("Prepare response", "Chuẩn bị phản ứng")}
                </summary>
                <select
                  aria-label={label("Approval policy", "Chính sách duyệt")}
                  value={policy}
                  onChange={(event) => setPolicy(event.target.value)}
                >
                  <option value="standard">
                    {label("Standard", "Tiêu chuẩn")}
                  </option>
                  <option value="manual_analyst">
                    {label("Manual analyst", "Chuyên viên xác nhận")}
                  </option>
                </select>
                {policy === "manual_analyst" && (
                  <textarea
                    aria-label={label("Justification", "Lý do")}
                    maxLength={1000}
                    value={justification}
                    onChange={(event) => setJustification(event.target.value)}
                  />
                )}
                <button
                  disabled={
                    actionBusy ||
                    (policy === "manual_analyst" &&
                      justification.trim().length < 8)
                  }
                  onClick={() => void action()}
                >
                  {label("Preview", "Xem trước")}
                </button>
              </details>
            )}
          <form onSubmit={submit}>
            <label className="sr-only" htmlFor="assistant-question">
              {t("Ask the assistant")}
            </label>
            <textarea
              id="assistant-question"
              value={text}
              disabled={creating}
              maxLength={2000}
              required
              placeholder={t("Ask the assistant")}
              onChange={(event) =>
                setDrafts((previous) => ({
                  ...previous,
                  [selected]: event.target.value,
                }))
              }
            />
            <button
              disabled={
                creating || busy || !text.trim() || !!current?.thread.archived
              }
            >
              {t("Send")}
            </button>
          </form>
        </section>
      )}
    </div>
  );
}
