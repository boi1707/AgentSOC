"""Bounded, deterministic Sysmon lineage lookup. The model cannot call this client."""

import asyncio
import base64
import ipaddress
import json
import re
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .adapters.wazuh import EVENT_FIELDS, SYSTEM_FIELDS, normalize

INDEX = "wazuh-alerts-*"
PROMPT_VERSION = "net-host-judge-v4"
MAX_REQUEST = 4096
MAX_RESPONSE = 512 * 1024
MAX_CONTEXT = 48 * 1024
PROVIDER = "Microsoft-Windows-Sysmon"
ALERT_ID = re.compile(r"[0-9]{1,20}\.[0-9]{1,24}")
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
GUID = re.compile(r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}")
INDEX_NAME = re.compile(r"wazuh-alerts-[a-z0-9][a-z0-9._-]{0,120}")
FIELDS = [
    "id",
    "timestamp",
    "manager.name",
    "agent.id",
    "agent.name",
    "agent.ip",
    "rule.id",
    "rule.level",
    "rule.description",
    *("data.win.system." + field for field in (*SYSTEM_FIELDS, "computer")),
    *("data.win.eventdata." + field for field in EVENT_FIELDS),
]


class RetrievalError(Exception):
    pass


def validate_config(settings):
    try:
        url = urlsplit(settings.wazuh_indexer_url)
        valid_url = (
            url.scheme == "https"
            and NAME.fullmatch(url.hostname or "")
            and (url.port is None or 1 <= url.port <= 65535)
            and not url.username
            and not url.password
            and url.path in ("", "/")
            and not url.query
            and not url.fragment
            and re.fullmatch(r"https://[A-Za-z0-9_.-]+(?::[0-9]{1,5})?/?", settings.wazuh_indexer_url)
        )
        if valid_url:
            try:
                ipaddress.ip_address(url.hostname)
            except ValueError:
                pass
            else:
                valid_url = False
    except ValueError:
        valid_url = False
    if not (
        valid_url
        and NAME.fullmatch(settings.wazuh_indexer_username)
        and settings.wazuh_indexer_password_file
        and settings.wazuh_indexer_ca_file
        and settings.wazuh_indexer_index_pattern == INDEX
        and 0.05 <= settings.wazuh_retrieval_timeout <= 3
        and type(settings.wazuh_retrieval_window) is int
        and 1 <= settings.wazuh_retrieval_window <= 120
        and type(settings.wazuh_retrieval_max_alerts) is int
        and 1 <= settings.wazuh_retrieval_max_alerts <= 20
        and type(settings.wazuh_retrieval_max_queries) is int
        and 1 <= settings.wazuh_retrieval_max_queries <= 3
    ):
        raise ValueError("Invalid Wazuh retrieval configuration")


def _connection(settings):
    validate_config(settings)
    try:
        path = Path(settings.wazuh_indexer_password_file)
        if not path.is_file():
            raise ValueError
        with path.open("rb") as file:
            encoded = file.read(4097)
        if len(encoded) > 4096:
            raise ValueError
        password = encoded.decode("utf-8").rstrip("\r\n")
        if not password or any(ord(c) < 32 or ord(c) == 127 for c in password):
            raise ValueError
    except (OSError, ValueError):
        raise RetrievalError("secret_unavailable") from None
    try:
        if not Path(settings.wazuh_indexer_ca_file).is_file():
            raise ValueError
        tls = ssl.create_default_context(cafile=settings.wazuh_indexer_ca_file)
    except (OSError, ValueError):
        raise RetrievalError("invalid_ca") from None
    return password, tls


def _obj(value):
    return value if isinstance(value, dict) else {}


def _stamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return stamp.astimezone(UTC) if stamp.tzinfo else None
    except (ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class Event:
    alert_id: str
    endpoint: tuple
    timestamp: datetime
    guid: str
    parent: str | None
    event_id: str
    system_time: datetime | None

    @classmethod
    def parse(cls, raw):
        agent, manager = _obj(raw.get("agent")), _obj(raw.get("manager"))
        windows = _obj(_obj(raw.get("data")).get("win"))
        system, event = _obj(windows.get("system")), _obj(windows.get("eventdata"))
        agent_id, hostname = agent.get("id"), agent.get("name")
        computer, manager_name = system.get("computer"), manager.get("name")
        agent_ip = agent.get("ip")
        if agent_ip is not None:
            if not isinstance(agent_ip, str) or len(agent_ip) > 64:
                return None
            try:
                ipaddress.ip_address(agent_ip)
            except ValueError:
                return None
        alert_id, stamp = raw.get("id"), _stamp(raw.get("timestamp"))
        system_time = _stamp(system.get("systemTime"))
        guid, parent = event.get("processGuid"), event.get("parentProcessGuid")
        event_id = system.get("eventID")
        if not (
            isinstance(alert_id, str)
            and ALERT_ID.fullmatch(alert_id)
            and isinstance(agent_id, str)
            and re.fullmatch(r"[0-9]{1,12}", agent_id)
            and all(isinstance(name, str) and NAME.fullmatch(name) for name in (hostname, manager_name))
            and (computer is None or isinstance(computer, str) and NAME.fullmatch(computer))
            and (computer or agent_ip)
            and system.get("providerName") == PROVIDER
            and stamp
            and (system.get("systemTime") is None or system_time)
            and isinstance(guid, str)
            and GUID.fullmatch(guid)
            and (type(event_id) is int or isinstance(event_id, str))
            and re.fullmatch(r"[0-9]{1,5}", str(event_id))
        ):
            return None
        return cls(
            alert_id,
            (manager_name, agent_id, hostname, agent_ip, computer),
            stamp,
            guid,
            parent if isinstance(parent, str) and GUID.fullmatch(parent) else None,
            str(event_id),
            system_time,
        )


def _body(anchor, guid, start, end, limit, remaining):
    manager, agent_id, hostname, ip, computer = anchor.endpoint
    fields = {
        "manager.name": manager,
        "agent.id": agent_id,
        "agent.name": hostname,
        "agent.ip": ip,
        "data.win.system.computer": computer,
        "data.win.system.providerName": PROVIDER,
        "data.win.system.eventID": "1",
    }
    filters = [{"term": {key: value}} for key, value in fields.items() if value is not None]
    filters.extend(
        (
            {"terms": {"data.win.eventdata.processGuid": sorted({guid, guid.lower(), guid.upper()})}},
            {"range": {"timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
        )
    )
    return json.dumps(
        {
            "_source": FIELDS,
            "size": limit,
            "track_total_hits": False,
            "sort": [{"timestamp": "desc"}, {"id": "asc"}],
            "timeout": f"{max(1, int(remaining * 1000))}ms",
            "query": {"bool": {"filter": filters}},
        },
        separators=(",", ":"),
    ).encode()


async def _search(client, url, body, remaining, limit):
    if len(body) > MAX_REQUEST:
        raise RetrievalError("request_limit")
    chunks = bytearray()
    async with client.stream(
        "POST", url, params={"allow_partial_search_results": "false"}, content=body, timeout=remaining
    ) as response:
        if response.status_code != 200:
            code = response.status_code
            category = {401: "unauthorized", 403: "forbidden", 429: "rate_limited"}.get(code)
            raise RetrievalError(category or ("server_error" if code >= 500 else "http_error"))
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise RetrievalError("unsupported_encoding")
        length = response.headers.get("content-length")
        if length is not None and (
            not length.isascii() or not length.isdigit() or len(length) > 10 or int(length) > MAX_RESPONSE
        ):
            raise RetrievalError("response_limit")
        if response.is_stream_consumed:  # In-memory test transports may prebuffer the response.
            if len(response.content) > MAX_RESPONSE:
                raise RetrievalError("response_limit")
            chunks.extend(response.content)
        else:
            async for chunk in response.aiter_raw(chunk_size=16384):
                if len(chunks) + len(chunk) > MAX_RESPONSE:
                    raise RetrievalError("response_limit")
                chunks.extend(chunk)
    try:
        payload = json.loads(chunks)
        hits = payload["hits"]["hits"]
        if payload.get("timed_out") is True:
            raise TimeoutError
        terminated = payload.get("terminated_early", False)
        if (
            not isinstance(hits, list)
            or payload.get("timed_out") is not False
            or type(terminated) is not bool
        ):
            raise ValueError
        shards = _obj(payload.get("_shards"))
        counts = [shards[name] for name in ("total", "successful", "skipped", "failed")]
        if any(type(count) is not int or count < 0 for count in counts):
            raise ValueError
        total, successful, skipped, failed = counts
        # OpenSearch counts skipped shards within successful shards.
        if skipped > successful or successful + failed > total:
            raise ValueError
        if failed or terminated or successful != total:
            raise RetrievalError("partial_response")
    except (ValueError, KeyError, TypeError, RecursionError):
        raise RetrievalError("malformed_response") from None
    if len(hits) > limit:
        raise RetrievalError("result_limit")
    return hits


def _matches(event, anchor, guid, start, end, system_end):
    return (
        event is not None
        and event.event_id == "1"
        and event.endpoint == anchor.endpoint
        and event.guid.lower() == guid.lower()
        and start <= event.timestamp <= end
        and (event.system_time is None or start <= event.system_time <= system_end)
    )


def _normalize_context(raw, host_ips):
    rule = _obj(raw.get("rule"))
    description = rule.get("description", "")
    rule_id = rule.get("id")
    if (
        not isinstance(description, str)
        or len(description) > 1024
        or not isinstance(rule_id, (str, int))
        or not re.fullmatch(r"[0-9]{1,16}", str(rule_id))
        or "level" not in rule
    ):
        raise ValueError("Invalid contextual rule")
    windows = raw["data"]["win"]
    row = normalize(
        {
            "id": raw["id"],
            "timestamp": raw["timestamp"],
            "agent": {key: raw["agent"][key] for key in ("id", "name", "ip") if key in raw["agent"]},
            "rule": {"id": rule_id, "level": rule["level"], "description": description},
            "data": {
                "win": {
                    "system": {
                        key: windows["system"][key] for key in SYSTEM_FIELDS if key in windows["system"]
                    },
                    "eventdata": {
                        key: windows["eventdata"][key] for key in EVENT_FIELDS if key in windows["eventdata"]
                    },
                }
            },
        },
        host_ips,
    )["evidence"]
    # The enrolled agent name and Windows computer name can differ. Register
    # both as typed identities so pseudonymization also covers command text.
    if computer := windows["system"].get("computer"):
        row["computer"] = computer
    return row


async def _collect(settings, transport, anchor, cutoff, primary, reserved_ids, budget, stats, deadline):
    password, tls = _connection(settings)
    url = settings.wazuh_indexer_url.rstrip("/") + "/" + INDEX + "/_search"
    private = tuple(
        value
        for value in (
            password,
            settings.wazuh_indexer_url.rstrip("/"),
            urlsplit(url).hostname,
            settings.wazuh_indexer_username,
            settings.wazuh_indexer_password_file,
            settings.wazuh_indexer_ca_file,
            base64.b64encode(f"{settings.wazuh_indexer_username}:{password}".encode()).decode(),
        )
        if value
    )
    lower = anchor.timestamp - timedelta(seconds=settings.wazuh_retrieval_window)
    cutoff_time = datetime.fromtimestamp(cutoff, UTC)
    upper = min(anchor.timestamp, cutoff_time)
    system_end = min(anchor.system_time or anchor.timestamp, cutoff_time)
    seen, rows, provenance = set(primary), [], {}
    reserved_ids = set(reserved_ids)
    source = settings.wazuh_source
    added_bytes = 0
    guid, reason = anchor.guid, "same_process_guid"
    if anchor.event_id == "1" and anchor.parent and anchor.parent.lower() != anchor.guid.lower():
        guid, reason = anchor.parent, "parent_process_guid"

    async with httpx.AsyncClient(
        transport=transport,
        verify=tls,
        auth=(settings.wazuh_indexer_username, password),
        follow_redirects=False,
        trust_env=False,
        headers={"Accept-Encoding": "identity", "Content-Type": "application/json"},
    ) as client:
        async with asyncio.timeout_at(deadline):
            for _ in range(min(2, settings.wazuh_retrieval_max_queries)):
                limit = budget - stats["retrieved"]
                if limit <= 0:
                    break
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError
                stats["queries"] += 1
                hits = await _search(
                    client, url, _body(anchor, guid, lower, upper, limit, remaining), remaining, limit
                )
                stats["retrieved"] += len(hits)
                parent_candidates = {}
                for hit in hits:
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError
                    index, raw = _obj(hit).get("_index"), _obj(_obj(hit).get("_source"))
                    event = Event.parse(raw)
                    if not (
                        isinstance(index, str)
                        and INDEX_NAME.fullmatch(index)
                        and _matches(event, anchor, guid, lower, upper, system_end)
                    ):
                        continue
                    identity = (source, event.alert_id)
                    citation = f"indexer:{source}:{event.alert_id}"
                    if identity in seen or citation in reserved_ids:
                        continue
                    try:
                        row = _normalize_context(raw, settings.host_ips)
                        row.update(id=citation, evidence_class="contextual", correlation_reason=reason)
                        encoded = json.dumps(row, ensure_ascii=False)
                        # These exact deployment values never become stored contextual evidence.
                        inspected = encoded + json.dumps((index, event.endpoint), ensure_ascii=False)
                        if any(
                            value in inspected or json.dumps(value)[1:-1] in inspected for value in private
                        ):
                            continue
                        row_bytes = len(encoded.encode())
                        if added_bytes + row_bytes > MAX_CONTEXT:
                            continue
                    except (ValueError, TypeError, RecursionError, OverflowError):
                        continue
                    if (
                        reason == "same_process_guid"
                        and event.parent
                        and event.parent.lower() != guid.lower()
                    ):
                        key = event.parent.lower()
                        if key not in parent_candidates or event.timestamp < parent_candidates[key].timestamp:
                            parent_candidates[key] = event
                    seen.add(identity)
                    added_bytes += row_bytes
                    rows.append(row)
                    manager, agent, hostname, ip, computer = event.endpoint
                    provenance[citation] = {
                        "alert_id": event.alert_id,
                        "source": source,
                        "index": index,
                        "endpoint": {
                            "manager": manager,
                            "agent_id": agent,
                            "hostname": hostname,
                            "ip": ip,
                            "computer": computer,
                        },
                        "event_timestamp": event.timestamp.isoformat(),
                        "retrieved_at": time.time(),
                        "correlation_reason": reason,
                        "evidence_class": "contextual",
                    }
                if len(parent_candidates) != 1:
                    break
                next_parent = next(iter(parent_candidates.values()))
                guid, reason = next_parent.parent, "parent_process_guid"
                upper = min(upper, next_parent.timestamp)
                system_end = min(system_end, next_parent.system_time or next_parent.timestamp)
    if asyncio.get_running_loop().time() >= deadline:
        raise TimeoutError
    return rows, provenance


def retrieve(settings, candidates, primary, cutoff, slots, *, transport=None, reserved_ids=()):
    """Return sanitized metadata and normalized evidence, even when Indexer is unavailable."""
    start = time.monotonic()
    stats = {"status": "no_eligible_anchor", "queries": 0, "retrieved": 0, "accepted": 0, "rejected": 0}
    rows, provenance = [], {}
    if not settings.wazuh_retrieval_enabled or settings.demo:
        return rows, provenance, {**stats, "status": "disabled", "duration_ms": 0, "correlation_reasons": []}
    try:
        validate_config(settings)
        if not slots:
            stats["status"] = "no_capacity"
        elif anchor := next(
            (
                e
                for raw in candidates
                if (e := Event.parse(raw))
                and e.timestamp.timestamp() <= cutoff
                and (e.system_time is None or e.system_time.timestamp() <= cutoff)
            ),
            None,
        ):

            async def collect():
                deadline = asyncio.get_running_loop().time() + max(
                    0, settings.wazuh_retrieval_timeout - (time.monotonic() - start)
                )
                return await _collect(
                    settings,
                    transport,
                    anchor,
                    cutoff,
                    primary,
                    reserved_ids,
                    min(slots, settings.wazuh_retrieval_max_alerts),
                    stats,
                    deadline,
                )

            # asyncio.run waits for the default executor during shutdown. A DNS
            # resolver that outlives cancellation must not extend this job's budget.
            loop = asyncio.new_event_loop()
            try:
                rows, provenance = loop.run_until_complete(collect())
            finally:
                loop.close()
            stats["status"] = "matched" if rows else "no_match"
    except (TimeoutError, httpx.TimeoutException):
        stats.update(status="timeout", error="deadline_or_transport_timeout")
    except httpx.ConnectError as exc:
        cause = exc
        while cause is not None and not isinstance(cause, ssl.SSLError):
            cause = cause.__cause__
        stats.update(status="failed", error="tls" if cause is not None else "connection")
    except httpx.TransportError:
        stats.update(status="failed", error="transport")
    except RetrievalError as exc:
        stats.update(status="failed", error=str(exc))
    except (ValueError, OverflowError):
        stats.update(status="failed", error="configuration_or_input")
    stats.update(
        accepted=len(rows),
        rejected=stats["retrieved"] - len(rows),
        duration_ms=round((time.monotonic() - start) * 1000, 2),
        correlation_reasons=sorted({row["correlation_reason"] for row in rows}),
    )
    return rows, provenance, stats
