"""One bounded notification envelope, shared by completion and legacy notify paths."""

from .anon import Anon
from .approvals import proposal


def proposal_event(store, settings, case, *, run=None):
    from .api.v1 import scrub

    p = proposal(store, settings, case, run=run)
    alerts = case["incident"].get("alerts", [])
    level = max((int(a.get("level", 0)) for a in alerts), default=0)
    severity = next(
        label
        for minimum, label in ((15, "critical"), (12, "high"), (8, "medium"), (4, "low"), (0, "info"))
        if level >= minimum
    )
    anon = Anon(settings.hosts)
    anon.rev = case["restore"]
    return scrub(
        {
            "event_id": "proposal:" + p["id"],
            "event": "proposal.created",
            "case_id": case["id"],
            "proposal": p,
            "verdict": case["verdict"].get("verdict"),
            "priority": level,
            "severity": severity,
            "explanation": anon.restore(str(case["verdict"].get("reason", "")))[:1800],
            "evidence_summary": [
                {key: a.get(key) for key in ("id", "rule", "level", "src_ip", "dst_ip")}
                for a in alerts
                if a.get("id") in p["evidence_ids"]
            ][:10],
            "notification_recipients": list(settings.telegram_notify_chats),
        },
        settings,
    )
