"""Response adapters and read-only pfREST verification."""

import ipaddress
import json
import logging
import math
import re
import ssl
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

import httpx

PFSENSE_ALIAS = "AGENTSOC_BLOCKLIST"
PFSENSE_MAX_TTL = 86400
PFSENSE_LAB_TARGET = ipaddress.IPv4Network("10.100.27.10/32")
PFSENSE_PROTECTED = ("10.8.0.0/24", "172.22.50.0/24", "192.168.119.0/24", "10.100.27.254/32")


@dataclass(frozen=True)
class BlockPlan:
    proposal_id: str
    source_ip: str
    expires_at: float
    protected_networks: tuple[str, ...]


class ResponseAdapter(Protocol):
    def block(self, plan: BlockPlan) -> str: ...
    def remove(self, plan: BlockPlan) -> str: ...


@dataclass(frozen=True)
class ManagedObservation:
    """One coherent transport observation. An unmarked entry belongs to an external operator."""

    revision: int
    configured: bool = False
    applied: bool = True
    runtime_member: bool = False
    configured_owner: str | None = None
    runtime_owner: str | None = None
    pending_owner: str | None = None
    alias_identity: str = PFSENSE_ALIAS
    unexpected_changes: bool = False


class ManagedTransport(Protocol):
    """The mocked lifecycle requires conditional writes and enforced operation deadlines."""

    identity: str

    def observe(self, ip: str) -> ManagedObservation: ...

    def configure(self, ip: str, *, revision: int, owner: str | None, deadline: float) -> None: ...

    def apply(self, ip: str, *, revision: int, deadline: float) -> None: ...


class RetryableMutation(Exception):
    """A retry is permitted after another observation."""


class PermanentMutation(Exception):
    """The worker must suspend this operation."""


class UnknownMutation(Exception):
    """Reconcile state before considering another operation."""


class DryRunAdapter:
    def block(self, plan: BlockPlan) -> str:
        return "dry_run"

    def remove(self, plan: BlockPlan) -> str:
        return "dry_run"


class PfSenseReadError(RuntimeError):
    """Sanitized failure suitable for operator diagnostics."""


@contextmanager
def private_http_logs():
    """Suppress wire traces for this synchronous request thread, including response headers."""
    thread = threading.get_ident()

    def other_thread(record):
        return record.thread != thread

    loggers = [
        logging.getLogger(name)
        for name in (
            "httpx",
            "httpcore.connection",
            "httpcore.http11",
            "httpcore.http2",
            "httpcore.proxy",
            "httpcore.socks",
        )
    ]
    for logger in loggers:
        logger.addFilter(other_thread)
    try:
        yield
    finally:
        for logger in loggers:
            logger.removeFilter(other_thread)


@dataclass(frozen=True)
class PfSenseObservation:
    alias_id: int
    configured: bool
    runtime_member: bool
    configuration_applied: bool


class PfSenseAdapter:
    """Read the configured alias and its runtime PF table. Writes remain disabled."""

    def __init__(self, settings=None, *, transport=None):
        self.settings = settings
        self._transport = transport

    @staticmethod
    def validate_settings(settings):
        if settings.pfsense_alias != PFSENSE_ALIAS:
            raise ValueError("PFSENSE_ALIAS must identify the dedicated managed alias")
        if not 1 <= settings.pfsense_block_ttl <= PFSENSE_MAX_TTL:
            raise ValueError("PFSENSE_BLOCK_TTL_SECONDS must be 1..86400")
        if not math.isfinite(settings.pfsense_timeout) or not 0 < settings.pfsense_timeout <= 15:
            raise ValueError("PFSENSE_TIMEOUT must be greater than zero and at most 15 seconds")
        for value in settings.pfsense_allowed_networks:
            network = ipaddress.IPv4Network(value)
            if not network.subnet_of(PFSENSE_LAB_TARGET):
                raise ValueError("PFSENSE_ALLOWED_NETWORKS exceeds the initial authorized lab scope")
        options = (
            settings.pfsense_url,
            settings.pfsense_hostname,
            settings.pfsense_ca_file,
            settings.pfsense_api_key_file,
        )
        if not any(options):
            return
        try:
            endpoint = urlsplit(settings.pfsense_url)
            if (
                not all(options)
                or endpoint.scheme != "https"
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.hostname != settings.pfsense_hostname.lower()
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]", settings.pfsense_hostname)
                or not any(c.isalpha() for c in settings.pfsense_hostname)
                or endpoint.path not in {"", "/"}
                or endpoint.query
                or endpoint.fragment
                or endpoint.port == 0
                or not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/?", settings.pfsense_url)
            ):
                raise ValueError
        except ValueError:
            raise ValueError(
                "Configure a valid pfSense HTTPS origin, expected hostname, CA file and key file"
            ) from None

    def validate_plan(self, plan: BlockPlan, now: float):
        ip = ipaddress.IPv4Address(plan.source_ip)
        ttl = self.settings.pfsense_block_ttl if self.settings else PFSENSE_MAX_TTL
        if not 0 < plan.expires_at - now <= ttl:
            raise ValueError("Block expiration must be within 24 hours")
        self.validate_target(ip, plan.protected_networks)

    def validate_target(self, source_ip, protected_networks=()):
        ip = ipaddress.IPv4Address(source_ip)
        allowed = self.settings.pfsense_allowed_networks if self.settings else (str(PFSENSE_LAB_TARGET),)
        protected = (*PFSENSE_PROTECTED, *protected_networks)
        if self.settings:
            protected += (*self.settings.protected, self.settings.gateway + "/32")
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
            or any(ip in ipaddress.ip_network(n) for n in protected)
        ):
            raise ValueError("Protected or invalid source IP")
        if ip not in PFSENSE_LAB_TARGET or not any(ip in ipaddress.IPv4Network(n) for n in allowed):
            raise ValueError("Source IP is outside the authorized pfSense lab scope")
        return ip

    def observe(self, source_ip: str) -> PfSenseObservation:
        """Read configuration and runtime state; this does not verify a traffic flow."""
        settings = self.settings
        if settings is None or not settings.pfsense_url:
            raise PfSenseReadError("pfSense read-only access is not configured")
        self.validate_settings(settings)
        target = self.validate_target(source_ip)
        try:
            ca = ssl.create_default_context(cafile=settings.pfsense_ca_file)
        except (OSError, ValueError):
            raise PfSenseReadError("pfSense CA could not be loaded") from None
        try:
            path = Path(settings.pfsense_api_key_file)
            if not path.is_file():
                raise ValueError
            with path.open("rb") as key_file:
                key = key_file.read(4097)
            if len(key) > 4096:
                raise ValueError
            key = key.decode("ascii").strip()
            if not re.fullmatch(r"[!-~]+", key):
                raise ValueError
        except (OSError, ValueError):
            raise PfSenseReadError("pfSense API key file is missing or invalid") from None
        if key in (
            settings.ingest_key,
            settings.approve_key,
            settings.llm_key,
            settings.admin_password,
            settings.tg_token,
            *settings.integration_secrets,
        ):
            raise PfSenseReadError("pfSense API access requires a dedicated key")

        with (
            private_http_logs(),
            httpx.Client(
                base_url=settings.pfsense_url,
                verify=ca,
                trust_env=False,
                follow_redirects=False,
                timeout=settings.pfsense_timeout,
                headers={"X-API-Key": key, "Accept": "application/json", "Accept-Encoding": "identity"},
                transport=self._transport,
            ) as client,
        ):
            aliases = self._get(client, "/api/v2/firewall/aliases", name=PFSENSE_ALIAS)
            if not isinstance(aliases, list) or len(aliases) != 1:
                raise PfSenseReadError("pfSense managed alias missing or ambiguous")
            alias = aliases[0]
            if (
                not isinstance(alias, dict)
                or alias.get("name") != PFSENSE_ALIAS
                or alias.get("type") != "host"
                or type(alias.get("id")) is not int
                or alias["id"] < 0
            ):
                raise PfSenseReadError("pfSense managed alias has an unexpected identity")
            addresses = self._strings(alias.get("address"))
            apply = self._get(client, "/api/v2/firewall/apply")
            if not isinstance(apply, dict) or type(apply.get("applied")) is not bool:
                raise PfSenseReadError("Invalid pfSense apply status")
            pending = self._strings(apply.get("pending_subsystems"))
            if apply["applied"] == bool(pending):
                raise PfSenseReadError("Inconsistent pfSense apply status")
            table = self._get(client, "/api/v2/diagnostics/table", id=PFSENSE_ALIAS)
            if (
                not isinstance(table, dict)
                or table.get("name") != PFSENSE_ALIAS
                or table.get("id") != PFSENSE_ALIAS
            ):
                raise PfSenseReadError("pfSense runtime table identity mismatch")
            runtime_member = False
            for entry in self._strings(table.get("entries")):
                try:
                    network = ipaddress.ip_network(entry, strict=True)
                except ValueError:
                    raise PfSenseReadError("Invalid pfSense runtime table entry") from None
                if target in network:
                    runtime_member = True
            return PfSenseObservation(alias["id"], str(target) in addresses, runtime_member, apply["applied"])

    @staticmethod
    def _strings(value):
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise PfSenseReadError("Invalid pfSense response fields")
        return value

    @staticmethod
    def _get(client, endpoint, **params):
        try:
            with client.stream("GET", endpoint, params=params) as result:
                if result.status_code != 200:
                    raise PfSenseReadError(f"pfSense read failed (HTTP {result.status_code})")
                if result.headers.get("content-encoding", "identity") != "identity":
                    raise PfSenseReadError("pfSense response used unexpected compression")
                body = bytearray()
                for chunk in result.iter_bytes(chunk_size=8192):
                    body.extend(chunk)
                    if len(body) > 1024 * 1024:
                        raise PfSenseReadError("pfSense response exceeded the read limit")
            payload = json.loads(body)
        except httpx.TimeoutException:
            raise PfSenseReadError("pfSense read timed out") from None
        except httpx.HTTPError:
            raise PfSenseReadError("pfSense TLS or HTTP transport failed") from None
        except ValueError:
            raise PfSenseReadError("Invalid pfSense response format") from None
        if not isinstance(payload, dict) or payload.get("code") != 200 or "data" not in payload:
            raise PfSenseReadError("Invalid pfSense response envelope")
        return payload["data"]

    def block(self, plan: BlockPlan) -> str:
        raise RuntimeError("Live pfSense mitigation is disabled pending separate authorization")

    def remove(self, plan: BlockPlan) -> str:
        raise RuntimeError("Live pfSense mitigation is disabled pending separate authorization")
