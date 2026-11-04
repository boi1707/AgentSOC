import ipaddress
import json
import time
from hashlib import sha256

KEEP = (
    "image",
    "commandLine",
    "parentImage",
    "originalFileName",
    "user",
    "destinationIp",
    "destinationPort",
    "sourceIp",
)


def norm(alert, host_ips=None):
    data, rule = alert.get("data", {}), alert.get("rule", {})
    event = data.get("win", {}).get("eventdata", {})
    agent = alert.get("agent", {})
    net = any(k in data for k in ("src_addr", "srcip"))
    src = data.get("src_addr", data.get("srcip")) if net else event.get("sourceIp")
    dst = data.get("dst_addr", data.get("dstip")) if net else event.get("destinationIp")
    # A network sensor's management IP must not merge all unrelated flows.
    host = None if net else (host_ips or {}).get(agent.get("ip"), agent.get("ip"))
    ips = set()
    for candidate in (src, dst, host):
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except (ValueError, TypeError):
            pass
    row = {
        "id": str(alert["id"]),
        "level": int(rule.get("level", 0)),
        "rule": str(rule.get("id", "")),
        "kind": "net" if net else "host",
        "description": rule.get("description", ""),
        "timestamp": alert.get("timestamp"),
        "hostname": agent.get("name", ""),
        "src_ip": src,
        "dst_ip": dst,
        "host_ip": host,
    }
    row.update({k: event[k] for k in KEEP if k in event})
    if net:
        row.update(msg=data.get("msg", ""), dst_port=data.get("dst_port"), proto=data.get("proto"))
    return row, ips


class Grouper:
    def __init__(self, gap=600, quiet=30, hi=12, cap=40, host_ips=None):
        self.gap, self.quiet, self.hi, self.cap = gap, quiet, hi, cap
        self.host_ips = {"10.8.0.3": "192.168.10.20"} if host_ips is None else host_ips
        self.inc = []

    def add(self, alert, now=None):
        now = time.time() if now is None else now
        row, ips = norm(alert, self.host_ips)
        if not ips:
            raise ValueError("Alert has no valid correlation IP")
        matches = [i for i in self.inc if i["ips"] & ips and now - i["last"] <= self.gap]
        if matches:
            incident = matches[0]
            for other in matches[1:]:
                incident["ips"] |= other["ips"]
                incident["raw_ids"].extend(other["raw_ids"])
                incident["hi"] |= other["hi"]
                for key, value in other["rows"].items():
                    if key in incident["rows"]:
                        incident["rows"][key]["count"] += value["count"]
                    else:
                        incident["rows"][key] = value
                self.inc.remove(other)
        else:
            incident = {"ips": set(), "rows": {}, "raw_ids": [], "last": now, "hi": False}
            self.inc.append(incident)
        incident["ips"] |= ips
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
                        "alerts": rows[: self.cap],
                        "raw_ids": incident["raw_ids"],
                        "dropped_rows": max(0, len(rows) - self.cap),
                    }
                )
        return out
