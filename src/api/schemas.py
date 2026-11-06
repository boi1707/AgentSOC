"""Versioned read contracts. Raw vendor payloads stay flexible; operational envelopes are typed."""

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)
    severity_counts: dict[str, int] | None = None


class Normalized(BaseModel):
    model_config = ConfigDict(extra="allow")
    schema_version: int
    source: str | None = None
    external_id: str | None = None
    source_timestamp: str | None = None
    source_time_quality: str | None = None
    received_at: float | None = None
    severity: str
    event_type: str
    entities: list[str]
    evidence: dict[str, Any]


class AlertSummary(BaseModel):
    provenance: str
    id: str
    received: float
    case_id: str | None
    source: str
    external_id: str | None
    normalized: Normalized
    severity: str | None
    event_type: str | None
    synthetic: int
    correlation_status: str


class AlertDetail(AlertSummary):
    raw_event: dict[str, Any]


class IncidentSummary(BaseModel):
    response_mode: str
    provenance: str
    id: str
    created: float
    status: str
    workflow_status: str
    latest_run_id: str | None
    synthetic: int
    severity: str
    incident: dict[str, Any]
    verdict: dict[str, Any]
    can_approve: bool
    target: str | None


class IncidentDetail(IncidentSummary):
    evidence: list[dict[str, Any]]
    runs: list[dict[str, Any]]
    notes: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    jobs: list[dict[str, Any]]


class LedgerStep(BaseModel):
    parameters: dict[str, Any] | None
    id: int
    ts: float
    case_id: str
    agent: str
    mode: str
    prompt: Any
    response: Any
    evidence: Any
    usage: dict[str, Any]
    duration_ms: float
    error: str | None
    run_id: str | None
    step_id: str | None
    provider: str | None
    model: str | None
    model_source: str | None
    prompt_version: str | None
    attempt: int | None
    tool_name: str | None
    status: str


class AuditEvent(BaseModel):
    id: int
    ts: float
    actor: str
    action: str
    target: str | None
    result: str
