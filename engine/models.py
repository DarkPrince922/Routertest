"""Core data models shared across the engine.

Plain dataclasses + enums; no framework coupling so the same types can be reused
from a future web panel.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class JobStatus(str, enum.Enum):
    """Lifecycle of a scan job."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    DONE = "DONE"
    REJECTED = "REJECTED"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"  # stopped by the user mid-scan
    SKIPPED = "SKIPPED"      # target is not a router — deeper stages skipped


class ScanProfile(str, enum.Enum):
    """Which stages a scan runs.

    ``FIRMWARE`` is reserved for a future binwalk/EMBA branch and is NOT
    implemented in v1 — it exists so the enum and extension points are stable.
    """

    QUICK = "QUICK"        # nmap only
    STANDARD = "STANDARD"  # nmap + nuclei
    FULL = "FULL"          # nmap + nuclei + routersploit
    FIRMWARE = "FIRMWARE"  # reserved (binwalk/EMBA) — not implemented in v1


class Severity(str, enum.Enum):
    """Finding severity. Ordering helper via :func:`severity_rank`."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(sev: Severity) -> int:
    """Numeric rank for sorting/aggregation (higher == more severe)."""
    return _SEVERITY_ORDER.get(sev, 0)


def normalize_severity(raw: str | None) -> Severity:
    """Best-effort map an external severity string to :class:`Severity`."""
    if not raw:
        return Severity.INFO
    try:
        return Severity(raw.strip().lower())
    except ValueError:
        return Severity.INFO


@dataclass(slots=True)
class Finding:
    """A single result produced by a stage."""

    stage: str
    severity: Severity
    title: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
        }


@dataclass(slots=True)
class ScanJob:
    """A queued/running/finished scan."""

    id: int
    target: str
    profile: ScanProfile
    status: JobStatus
    engagement_id: str
    created_at: datetime
    finished_at: datetime | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target": self.target,
            "profile": self.profile.value,
            "status": self.status.value,
            "engagement_id": self.engagement_id,
            "created_at": self.created_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "error": self.error,
        }


@dataclass(slots=True)
class ScopeDecision:
    """Result of a :class:`~engine.scope.ScopeGate` check."""

    target: str
    resolved_ip: str | None
    allowed: bool
    reason: str


def utcnow() -> datetime:
    """Timezone-aware UTC now (single source so timestamps are consistent)."""
    return datetime.now(timezone.utc)
