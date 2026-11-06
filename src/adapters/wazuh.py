import ipaddress
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WazuhAlert(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str = Field(min_length=1, max_length=200)
    rule: dict
    agent: dict = Field(default_factory=dict)
    data: dict = Field(default_factory=dict)
    timestamp: str | None = None

    @field_validator("rule")
    @classmethod
    def valid_rule(cls, value):
        level = value.get("level", 0)
        if isinstance(level, bool) or str(level) not in {str(n) for n in range(16)}:
            raise ValueError("Wazuh level must be an integer from 0 to 15")
        if "groups" in value and (
            not isinstance(value["groups"], list) or any(not isinstance(g, str) for g in value["groups"])
        ):
            raise ValueError("Wazuh rule.groups must be an array of strings")
        return value

    @field_validator("agent")
    @classmethod
    def valid_agent(cls, value):
        if any(
            value.get(key) is not None and not isinstance(value[key], str) for key in ("name", "ip", "id")
        ):
            raise ValueError("Wazuh agent identifiers must be strings")
        return value

    @field_validator("data")
    @classmethod
    def valid_data(cls, value):
        if any(
            value.get(key) is not None and not isinstance(value[key], str)
            for key in ("src_addr", "dst_addr", "srcip", "dstip")
        ):
            raise ValueError("Decoded network addresses must be strings")
        if "win" in value:
            if not isinstance(value["win"], dict):
                raise ValueError("Windows evidence must be an object")
            win = value["win"]
            if any(key in win and not isinstance(win[key], dict) for key in ("eventdata", "system")):
                raise ValueError("Windows eventdata/system must be objects")
            if win.get("system", {}).get("computer") is not None and not isinstance(
                win["system"]["computer"], str
            ):
                raise ValueError("Windows computer identity must be a string")
            event = win.get("eventdata", {})
            if any(
                event.get(key) is not None and not isinstance(event[key], str)
                for key in (
                    "image",
                    "commandLine",
                    "parentImage",
                    "originalFileName",
                    "user",
                    "sourceIp",
                    "destinationIp",
                )
            ):
                raise ValueError("Known Windows evidence fields must be strings")
        return value


def normalize(alert, host_ips=None):
    host_ips = {"10.8.0.3": "192.168.10.20"} if host_ips is None else host_ips
    alert = WazuhAlert.model_validate(alert).model_dump()
    data, rule, agent = alert["data"], alert["rule"], alert["agent"]
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    event = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    network = (
        "src_addr" in data or any(g in {"snort", "network", "firewall"} for g in rule.get("groups", []))
    ) and not win
    kind = "net" if network else "host" if win else "generic"
    src = data.get("src_addr", data.get("srcip")) if network else event.get("sourceIp", data.get("srcip"))
    dst = (
        data.get("dst_addr", data.get("dstip")) if network else event.get("destinationIp", data.get("dstip"))
    )
    host = None if network else (host_ips or {}).get(agent.get("ip"), agent.get("ip"))
    ips = []
    for value in (src, dst, host):
        try:
            value = str(ipaddress.ip_address(value))
            if value not in ips:
                ips.append(value)
        except (ValueError, TypeError):
            pass
    hostname = agent.get("name") or win.get("system", {}).get("computer", "")
    entities = [
        "ip:" + ip
        for ip in ips
        if not (
            ipaddress.ip_address(ip).is_unspecified
            or ipaddress.ip_address(ip).is_multicast
            or ipaddress.ip_address(ip).is_loopback
        )
    ]
    # Network sensors' management identities must never join unrelated flows.
    if not network and hostname and str(hostname).strip().lower() not in {"unknown", "n/a", "-", "none"}:
        entities.append("host:" + str(hostname).lower())
    level = int(rule.get("level", 0))
    timestamp, quality = None, "not_provided"
    if alert.get("timestamp"):
        try:
            parsed = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
            timestamp = parsed.astimezone(UTC).isoformat() if parsed.tzinfo else None
            quality = "valid" if timestamp else "missing_timezone"
        except ValueError:
            quality = "invalid"
    severity = next(
        label
        for floor, label in ((15, "critical"), (12, "high"), (8, "medium"), (4, "low"), (0, "info"))
        if level >= floor
    )
    event_type = (
        "network"
        if network
        else "sysmon"
        if win
        else "file_integrity"
        if "syscheck" in alert
        else "authentication"
        if any("auth" in str(g) or "sshd" in str(g) for g in rule.get("groups", []))
        else "generic"
    )
    row = {
        "id": alert["id"],
        "level": level,
        "rule": str(rule.get("id", "")),
        "kind": kind,
        "description": str(rule.get("description", "")),
        "timestamp": alert.get("timestamp"),
        "hostname": hostname,
        "src_ip": src,
        "dst_ip": dst,
        "host_ip": host,
        "severity": severity,
        "event_type": event_type,
    }
    row.update(
        {
            k: event[k]
            for k in (
                "image",
                "commandLine",
                "parentImage",
                "originalFileName",
                "user",
                "destinationIp",
                "destinationPort",
                "sourceIp",
            )
            if k in event
        }
    )
    if network:
        row.update(msg=data.get("msg", ""), dst_port=data.get("dst_port"), proto=data.get("proto"))
    if kind == "generic":
        row["user"] = data.get("dstuser", data.get("srcuser"))
        if isinstance(alert.get("syscheck"), dict):
            row["file"] = alert["syscheck"].get("path")
    return {
        "schema_version": 1,
        "source": "wazuh",
        "external_id": alert["id"],
        "source_timestamp": timestamp,
        "source_time_quality": quality,
        "severity": severity,
        "event_type": event_type,
        "entities": entities,
        "ips": ips,
        "evidence": row,
        "correlation_status": "pending" if entities else "uncorrelated",
    }
