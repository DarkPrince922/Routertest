"""Core models and the Detector interface for the cve_detect module."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class Status:
    """Detection verdict for a Finding."""

    VULNERABLE = "vulnerable"        # confirmed by a non-destructive active check
    LIKELY = "likely"               # fingerprint (model+firmware) strongly matches
    NOT_VULNERABLE = "not_vulnerable"
    UNKNOWN = "unknown"             # not enough signal to decide


# Confidence anchors used by detectors so the numbers stay comparable.
CONF_CONFIRMED = 0.95   # active non-destructive check succeeded
CONF_LIKELY = 0.7       # model + vulnerable firmware match
CONF_WEAK = 0.4         # model matches, firmware unknown
CONF_NONE = 0.0


@dataclass(slots=True)
class DeviceInfo:
    """Everything the fingerprint stage learned about one host."""

    ip: str
    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None
    open_ports: list[int] = field(default_factory=list)
    http_signatures: dict = field(default_factory=dict)  # server, title, favicon, endpoints
    raw_banners: dict = field(default_factory=dict)

    def blob(self) -> str:
        """Lowercased text of all signals, for cheap substring matching."""
        parts = [self.vendor or "", self.model or "", self.firmware or ""]
        parts += [str(v) for v in self.http_signatures.values()]
        parts += [str(v) for v in self.raw_banners.values()]
        return " ".join(parts).lower()

    def has_port(self, *ports: int) -> bool:
        return any(p in self.open_ports for p in ports)


@dataclass(slots=True)
class Finding:
    """A single detection result (detection-only; no exploitation)."""

    cve: str
    title: str
    severity: str                    # critical/high/medium
    status: str                      # Status.*
    confidence: float                # 0..1
    affected_component: str
    evidence: str                    # sanitized: what pointed at the vuln
    remediation: str
    references: list[str] = field(default_factory=list)
    eol: bool = False                # device is end-of-life ("replace" in summary)
    host: str = ""                   # filled in by the runner for reporting

    def to_dict(self) -> dict:
        return {
            "cve": self.cve, "title": self.title, "severity": self.severity,
            "status": self.status, "confidence": round(self.confidence, 2),
            "affected_component": self.affected_component, "evidence": self.evidence,
            "remediation": self.remediation, "references": list(self.references),
            "eol": self.eol, "host": self.host,
        }


class Detector(ABC):
    """One CVE (or tightly-related family). Stateless; safe to share.

    ``applicable`` is a cheap fingerprint gate so we don't run TP-Link checks
    against a D-Link (registry uses it to dispatch). ``check`` does the actual
    (non-destructive) detection and returns zero or more findings.
    """

    #: Human name and the CVE ids this detector reasons about.
    name: str = "detector"
    cves: tuple[str, ...] = ()

    @abstractmethod
    def applicable(self, device: DeviceInfo) -> bool:
        """True if this detector's vendor/model/ports match ``device``."""

    @abstractmethod
    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        """Return findings. ``active`` gates non-destructive active probes.

        In safe mode (``active is False``) a detector may only fingerprint and
        probe endpoint presence (GET/HEAD, no payload). It must never send a
        command marker or mutate device state.
        """
