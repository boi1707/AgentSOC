"""Response adapter contracts. pfSense intentionally has no execution transport."""

import ipaddress
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class BlockPlan:
    proposal_id: str
    source_ip: str
    expires_at: float
    protected_networks: tuple[str, ...]


class ResponseAdapter(Protocol):
    def block(self, plan: BlockPlan) -> str: ...
    def remove(self, plan: BlockPlan) -> str: ...


class DryRunAdapter:
    def block(self, plan: BlockPlan) -> str:
        return "dry_run"

    def remove(self, plan: BlockPlan) -> str:
        return "dry_run"


class PfSenseAdapter:
    """Plan validation only; cannot call a firewall even if constructed directly."""

    def validate_plan(self, plan: BlockPlan, now: float):
        ip = ipaddress.IPv4Address(plan.source_ip)
        if not 0 < plan.expires_at - now <= 86400:
            raise ValueError("Block expiration must be within 24 hours")
        if (
            ip.is_loopback
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
            or any(ip in ipaddress.ip_network(n) for n in plan.protected_networks)
        ):
            raise ValueError("Protected or invalid source IP")

    def block(self, plan: BlockPlan) -> str:
        raise RuntimeError("Live pfSense mitigation is disabled pending separate authorization")

    def remove(self, plan: BlockPlan) -> str:
        raise RuntimeError("Live pfSense mitigation is disabled pending separate authorization")
