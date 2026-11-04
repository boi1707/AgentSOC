import ipaddress
import json
import math
import os
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
    host_ips: dict = field(default_factory=lambda: {"10.8.0.3": "192.168.10.20"})
    hosts: tuple = ("win-victim", "gateway", "kali")
    protected: tuple = ("10.8.0.0/24", "192.168.10.0/24", "127.0.0.0/8", "169.254.0.0/16")
    gateway: str = "10.8.0.2"
    ssh_key: str = "data/block_key"
    known_hosts: str = "data/known_hosts"
    tg_token: str = ""
    tg_chat: str = ""

    @classmethod
    def from_env(cls):
        load_dotenv()
        return cls(
            db=os.getenv("DB", "data/agentsoc.db"),
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
            host_ips=json.loads(os.getenv("HOST_IPS", '{"10.8.0.3":"192.168.10.20"}')),
            hosts=tuple(os.getenv("HOST_NAMES", "win-victim,gateway,kali").split(",")),
            gateway=os.getenv("GATEWAY", "10.8.0.2"),
            ssh_key=os.getenv("SSH_KEY", "data/block_key"),
            known_hosts=os.getenv("KNOWN_HOSTS", "data/known_hosts"),
            tg_token=os.getenv("TG_TOKEN", ""),
            tg_chat=os.getenv("TG_CHAT", ""),
        )

    def validate(self):
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
        if bool(self.tg_token) != bool(self.tg_chat):
            raise ValueError("TG_TOKEN and TG_CHAT must both be configured or both empty")
        if not isinstance(self.host_ips, dict):
            raise ValueError("HOST_IPS must be a JSON object mapping IP addresses")
        for source, target in self.host_ips.items():
            ipaddress.ip_address(source)
            ipaddress.ip_address(target)
