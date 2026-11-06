import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from dotenv import load_dotenv


@dataclass
class Settings:
    db: str = "data/agentsoc.db"
    ingest_key: str = ""
    approve_key: str = ""
    llm_mode: str = "mock"
    llm_url: str = ""
    llm_key: str = ""
    llm_model: str = ""
    response_mode: str = "dry-run"
    confidence: float = 0.85
    quiet: float = 30
    gap: float = 600
    poll: float = 2
    hi_level: int = 12
    cap: int = 40
    log_level: str = "INFO"
    log_component: str = ""
    host_ips: dict = field(default_factory=lambda: {"10.8.0.3": "192.168.10.20"})
    hosts: tuple = ("win-victim", "gateway", "kali")
    protected: tuple = ("10.8.0.0/24", "192.168.10.0/24", "127.0.0.0/8", "169.254.0.0/16")
    gateway: str = "10.8.0.2"
    ssh_key: str = "data/block_key"
    known_hosts: str = "data/known_hosts"
    tg_token: str = ""
    tg_chat: str = ""
    embedded_worker: bool = False
    demo: bool = False
    admin_username: str = "admin"
    admin_password: str = ""
    secure_cookie: bool = False
    lease_seconds: float = 120
    wazuh_source: str = "wazuh"

    @classmethod
    def from_env(cls):
        load_dotenv()
        return cls(
            db=os.getenv("DEMO_DB", "data/demo/agentsoc.db")
            if os.getenv("DEMO_MODE", "0") == "1"
            else os.getenv("DB", "data/agentsoc.db"),
            ingest_key=os.getenv("INGEST_KEY", ""),
            approve_key=os.getenv("APPROVE_KEY", ""),
            llm_mode=os.getenv("LLM_MODE", "mock"),
            llm_url=os.getenv("LLM_URL", ""),
            llm_key=os.getenv("LLM_API_KEY", ""),
            llm_model=os.getenv("LLM_MODEL", ""),
            response_mode=os.getenv("RESPONSE_MODE", "dry-run"),
            confidence=float(os.getenv("MIN_CONFIDENCE", "0.85")),
            quiet=float(os.getenv("QUIET_SECONDS", "30")),
            gap=float(os.getenv("GAP_SECONDS", "600")),
            poll=float(os.getenv("POLL_SECONDS", "2")),
            hi_level=int(os.getenv("HI_LEVEL", "12")),
            cap=int(os.getenv("CAP", "40")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_component=os.getenv("LOG_COMPONENT", ""),
            host_ips=json.loads(os.getenv("HOST_IPS", '{"10.8.0.3":"192.168.10.20"}')),
            hosts=tuple(os.getenv("HOST_NAMES", "win-victim,gateway,kali").split(",")),
            gateway=os.getenv("GATEWAY", "10.8.0.2"),
            ssh_key=os.getenv("SSH_KEY", "data/block_key"),
            known_hosts=os.getenv("KNOWN_HOSTS", "data/known_hosts"),
            tg_token=os.getenv("TG_TOKEN", ""),
            tg_chat=os.getenv("TG_CHAT", ""),
            embedded_worker=os.getenv("EMBEDDED_WORKER", "0") == "1",
            demo=os.getenv("DEMO_MODE", "0") == "1",
            admin_username=os.getenv("ADMIN_USERNAME", "admin"),
            admin_password=os.getenv("ADMIN_PASSWORD", ""),
            secure_cookie=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
            lease_seconds=float(os.getenv("JOB_LEASE_SECONDS", "120")),
            wazuh_source=os.getenv("WAZUH_SOURCE_ID", "wazuh"),
        )

    def validate(self):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.wazuh_source):
            raise ValueError("WAZUH_SOURCE_ID must be 1..64 letters, digits, underscore or hyphen")
        if len(self.ingest_key) < 24 or len(self.approve_key) < 24:
            raise ValueError("Set separate INGEST_KEY and APPROVE_KEY of at least 24 characters")
        if self.ingest_key == self.approve_key:
            raise ValueError("INGEST_KEY and APPROVE_KEY must be different")
        if self.llm_mode not in {"mock", "live"} or self.response_mode not in {"dry-run", "ssh"}:
            raise ValueError("Invalid LLM_MODE or RESPONSE_MODE")
        if self.llm_mode == "live":
            url = urlsplit(self.llm_url)
            if not all((url.scheme == "https", url.hostname, self.llm_key.strip(), self.llm_model.strip())):
                raise ValueError("Live mode requires HTTPS LLM_URL, LLM_API_KEY and LLM_MODEL")
            if url.username or url.password or url.query or url.fragment:
                raise ValueError("LLM_URL must not contain credentials, query or fragment")
        if self.response_mode == "ssh":
            ipaddress.IPv4Address(self.gateway)
            if self.llm_mode != "live":
                raise ValueError("Mock verdicts cannot execute SSH blocking")
        timings = (self.quiet, self.gap, self.poll)
        if not 0 <= self.confidence <= 1 or not all(math.isfinite(v) and v > 0 for v in timings):
            raise ValueError("Invalid confidence or timing configuration")
        if not 0 <= self.hi_level <= 15 or not 1 <= self.cap <= 40:
            raise ValueError("HI_LEVEL must be 0..15; CAP must be 1..40")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("Invalid LOG_LEVEL")
        if self.log_component not in {"", "api", "worker"}:
            raise ValueError("Invalid LOG_COMPONENT")
        if bool(self.tg_token) != bool(self.tg_chat):
            raise ValueError("TG_TOKEN and TG_CHAT must both be configured or both empty")
        if self.demo and (self.llm_mode != "mock" or self.response_mode != "dry-run" or self.tg_token):
            raise ValueError("Demo requires mock, dry-run and no Telegram credentials")
        if not math.isfinite(self.lease_seconds) or self.lease_seconds < 5:
            raise ValueError("JOB_LEASE_SECONDS must be finite and at least 5")
        if self.admin_password and len(self.admin_password) < 24:
            raise ValueError("ADMIN_PASSWORD must contain at least 24 characters")
        if not isinstance(self.host_ips, dict):
            raise ValueError("HOST_IPS must be a JSON object mapping IP addresses")
        for source, target in self.host_ips.items():
            ipaddress.ip_address(source)
            ipaddress.ip_address(target)
