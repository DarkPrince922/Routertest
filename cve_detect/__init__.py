"""cve_detect — detection-only router CVE identification.

This package *identifies* known router vulnerabilities on authorized targets so
they can be remediated (patch / disable service / WAN-filter). It NEVER exploits,
runs commands, or changes device state. Every active probe is non-destructive and
gated behind an explicit ``active`` flag; scope is enforced before any request.

Public surface:
    DeviceInfo, Finding, Detector      — models + detector interface (base)
    SafeHTTP, ScopeDenied              — scope/rate/timeout-gated transport (http)
    run_detectors, applicable_detectors — dispatch (registry)
    build_markdown, build_json          — remediation report (report)
"""
from .base import DeviceInfo, Detector, Finding, Status
from .http import SafeHTTP, ScopeDenied
from .registry import applicable_detectors, run_detectors
from .report import build_json, build_markdown

__all__ = [
    "DeviceInfo", "Detector", "Finding", "Status",
    "SafeHTTP", "ScopeDenied",
    "applicable_detectors", "run_detectors",
    "build_json", "build_markdown",
]
