import { useEffect, useRef, useState, type FormEvent } from "react";
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
  facts: Fact[];
  citations: Citation[];
  analysis: unknown[];
  truncated: boolean;
};
type Message = { question: string; answer?: Answer; error?: string };

export function AssistantPanel() {
  const [language] = useLanguage();
  const [open, setOpen] = useState(false),
    [text, setText] = useState("");
  const [messages, setMessages] = useState<Message[]>([]),
    [busy, setBusy] = useState(false);
  const location = useLocation();
  const incidentId = location.pathname.match(
    /^\/console\/incidents\/([^/]+)$/,
  )?.[1];
  const controller = useRef<AbortController | null>(null);
  const context = useRef(incidentId);
  useEffect(() => {
    controller.current?.abort();
    context.current = incidentId;
    setMessages([]);
    setBusy(false);
  }, [incidentId]);
  useEffect(() => () => controller.current?.abort(), []);
  async function ask(question: string) {
    if (busy || !question.trim()) return;
    setBusy(true);
    setText("");
    const active = new AbortController();
    controller.current = active;
    const selected = incidentId;
    const timer = setTimeout(() => active.abort(), 20000);
    const index = messages.length;
    setMessages((previous) => [...previous.slice(-19), { question }]);
    try {
      const answer = await api<Answer>("/assistant/query", {
        method: "POST",
        signal: active.signal,
        body: JSON.stringify({
          message: question,
          language,
          incident_id: selected,
          history: messages.slice(-4).map((message) => message.question),
        }),
      });
      if (context.current !== selected) return;
      setMessages((previous) =>
        previous.map((message, i) =>
          i === Math.min(index, 19) ? { ...message, answer } : message,
        ),
      );
    } catch (error) {
      if (context.current !== selected) return;
      const detail =
        error instanceof Error && error.name === "AbortError"
          ? t("Assistant timed out. Try again.")
          : t("Assistant unavailable. Try again.");
      setMessages((previous) =>
        previous.map((message, i) =>
          i === Math.min(index, 19) ? { ...message, error: detail } : message,
        ),
      );
    } finally {
      clearTimeout(timer);
      if (controller.current === active) setBusy(false);
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
          className="assistant-panel panel"
          aria-label={t("AI Assistant")}
        >
          <div className="panel-heading">
            <h2>{t("AI Assistant")}</h2>
            <button
              aria-label={t("Close assistant")}
              onClick={() => setOpen(false)}
            >
              ×
            </button>
          </div>
          <p className="muted small">
            {t("Read-only. Decisions use the incident review workflow.")}
          </p>
          {incidentId && <p className="mono">{incidentId}</p>}
          <div className="assistant-suggestions">
            {[
              "Review the last 24 hours",
              "Are any proposals pending approval?",
              "Why was this action recommended?",
            ].map((key) => (
              <button
                key={key}
                disabled={busy}
                onClick={() => void ask(t(key))}
              >
                {t(key)}
              </button>
            ))}
          </div>
          <div className="assistant-messages" role="log" aria-live="polite">
            {!messages.length && (
              <p>
                {t(
                  "Ask about stored incidents or open an incident for context.",
                )}
              </p>
            )}
            {messages.map((message, i) => (
              <article key={i}>
                <strong>{message.question}</strong>
                {message.error && <p role="alert">{message.error}</p>}
                {message.answer && (
                  <>
                    <p>{message.answer.summary}</p>
                    <p className="small muted">{message.answer.notice}</p>
                    {message.answer.model_status === "unavailable" && (
                      <p>{t("Model unavailable; evidence is still shown.")}</p>
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
                          <pre className="json">
                            {JSON.stringify(citation.normalized, null, 2)}
                          </pre>
                        </div>
                      ))}
                    </details>
                    <details>
                      <summary>{t("Stored AI analysis")}</summary>
                      <pre className="json">
                        {JSON.stringify(message.answer.analysis, null, 2)}
                      </pre>
                    </details>
                    {message.answer.interpretation && (
                      <>
                        <h3>{t("AI interpretation")}</h3>
                        <p className="assistant-interpretation">
                          {message.answer.interpretation}
                        </p>
                      </>
                    )}
                  </>
                )}
              </article>
            ))}
            {busy && <p role="status">{t("Reading evidence…")}</p>}
          </div>
          <form onSubmit={submit}>
            <label className="sr-only" htmlFor="assistant-question">
              {t("Ask the assistant")}
            </label>
            <textarea
              id="assistant-question"
              value={text}
              maxLength={2000}
              required
              placeholder={t("Ask the assistant")}
              onChange={(event) => setText(event.target.value)}
            />
            <button disabled={busy || !text.trim()}>{t("Send")}</button>
          </form>
        </section>
      )}
    </div>
  );
}
