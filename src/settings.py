import ipaddress
import json
import os
from dataclasses import dataclass, field

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
        if self.llm_mode == "live" and not all(
            (self.llm_url.startswith("https://"), self.llm_key, self.llm_model)
        ):
            raise ValueError("Live mode requires HTTPS LLM_URL, LLM_API_KEY and LLM_MODEL")
        if self.response_mode == "ssh":
            ipaddress.IPv4Address(self.gateway)
            if self.llm_mode != "live":
                raise ValueError("Mock verdicts cannot execute SSH blocking")
        if not 0 <= self.confidence <= 1 or min(self.quiet, self.gap, self.poll) <= 0:
            raise ValueError("Invalid confidence or timing configuration")
        for source, target in self.host_ips.items():
            ipaddress.ip_address(source)
            ipaddress.ip_address(target)
