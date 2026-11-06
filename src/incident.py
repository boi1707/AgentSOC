import json
import time
from hashlib import sha256

from .adapters.wazuh import normalize


def norm(alert, host_ips=None):
    value = normalize(alert, host_ips)
    return value["evidence"], set(value["ips"])


class Grouper:
    def __init__(self, gap=600, quiet=30, hi=12, cap=40, host_ips=None):
        self.gap, self.quiet, self.hi, self.cap = gap, quiet, hi, cap
        self.host_ips = {"10.8.0.3": "192.168.10.20"} if host_ips is None else host_ips
        self.inc = []

    def add(self, alert, now=None, normalized=None):
        now = time.time() if now is None else now
        value = normalized if normalized is not None else normalize(alert, self.host_ips)
        row, ips, entities = value["evidence"], set(value["ips"]), set(value["entities"])
        if not entities:
            raise ValueError("Alert has no safe correlation entity")
        matches = [i for i in self.inc if i["entities"] & entities and now - i["last"] <= self.gap]
        if matches:
            incident = matches[0]
            for other in matches[1:]:
                incident["ips"] |= other["ips"]
                incident["entities"] |= other["entities"]
                incident["raw_ids"].extend(other["raw_ids"])
                incident["hi"] |= other["hi"]
                for key, value in other["rows"].items():
                    if key in incident["rows"]:
                        incident["rows"][key]["count"] += value["count"]
                    else:
                        incident["rows"][key] = value
                self.inc.remove(other)
        else:
            incident = {"ips": set(), "entities": set(), "rows": {}, "raw_ids": [], "last": now, "hi": False}
            self.inc.append(incident)
        incident["ips"] |= ips
        incident["entities"] |= entities
        incident["last"] = now
        incident["hi"] |= row["level"] >= self.hi
        incident["raw_ids"].append(row["id"])
        fingerprint = {k: v for k, v in row.items() if k not in {"id", "timestamp"}}
        key = sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()
        incident["rows"].setdefault(key, {**row, "count": 0})["count"] += 1

    def ready(self, now=None):
        now = time.time() if now is None else now
        out = []
        for incident in list(self.inc):
            if incident["hi"] or now - incident["last"] >= self.quiet:
                self.inc.remove(incident)
                rows = sorted(incident["rows"].values(), key=lambda r: -r["level"])
                out.append(
                    {
                        "ips": sorted(incident["ips"]),
                        "entities": sorted(incident["entities"]),
                        "alerts": rows[: self.cap],
                        "raw_ids": incident["raw_ids"],
                        "dropped_rows": max(0, len(rows) - self.cap),
                    }
                )
        return out
