"""Detector registry + dispatch.

``applicable_detectors`` filters by fingerprint so we never run a vendor's checks
against another vendor's device. ``run_detectors`` executes the applicable ones
and flattens their findings.
"""
from __future__ import annotations

import logging

from .base import DeviceInfo, Detector, Finding
from .detectors import ALL_DETECTORS

log = logging.getLogger(__name__)


def applicable_detectors(device: DeviceInfo,
                         detectors: list[Detector] | None = None) -> list[Detector]:
    pool = detectors if detectors is not None else ALL_DETECTORS
    out: list[Detector] = []
    for det in pool:
        try:
            if det.applicable(device):
                out.append(det)
        except Exception:  # noqa: BLE001 - a bad applicable() must not break dispatch
            log.exception("detector %s applicable() raised", det.name)
    return out


async def run_detectors(device: DeviceInfo, http, *, active: bool,
                        detectors: list[Detector] | None = None) -> list[Finding]:
    """Run every applicable detector; return all findings (host filled in)."""
    findings: list[Finding] = []
    for det in applicable_detectors(device, detectors):
        try:
            results = await det.check(device, http, active=active)
        except Exception:  # noqa: BLE001 - one detector must not abort the rest
            log.exception("detector %s check() raised", det.name)
            continue
        for f in results:
            if not f.host:
                f.host = device.ip
            findings.append(f)
    return findings
