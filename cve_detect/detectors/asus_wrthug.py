"""WrtHug — ASUS WRT vulnerability chain (AiCloud-centric).

Covers CVE-2023-39780, CVE-2025-2492, CVE-2023-41345..41348, CVE-2024-12912.
Detection-only: ASUS WRT + AiCloud service (usually 8443) + vulnerable/EoL
firmware → likely, one finding per CVE. No payloads.
"""
from __future__ import annotations

from ..base import CONF_LIKELY, CONF_WEAK, DeviceInfo, Detector, Finding, Status

CHAIN = [
    ("CVE-2023-39780", "ASUS WRT authenticated command injection", "high"),
    ("CVE-2025-2492", "ASUS WRT improper auth (AiCloud)", "critical"),
    ("CVE-2023-41345", "ASUS WRT config injection (chain)", "high"),
    ("CVE-2023-41346", "ASUS WRT config injection (chain)", "high"),
    ("CVE-2023-41347", "ASUS WRT config injection (chain)", "high"),
    ("CVE-2023-41348", "ASUS WRT config injection (chain)", "high"),
    ("CVE-2024-12912", "ASUS WRT information disclosure", "medium"),
]
# Illustrative EoL model tokens — refine against ASUS advisories.
EOL_MODELS = {"rt-ac66u", "rt-ac68u", "rt-ac87u", "rt-n66u", "dsl-ac68u"}


class AsusWrtHug(Detector):
    name = "ASUS WRT chain (WrtHug)"
    cves = tuple(c for c, _, _ in CHAIN)

    def applicable(self, device: DeviceInfo) -> bool:
        blob = device.blob()
        return ("asus" in blob or "asuswrt" in blob or "rt-ac" in blob
                or "rt-n" in blob or device.has_port(8443))

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        aicloud = await self._aicloud_present(device, http)
        blob = device.blob()
        eol = any(m in blob for m in EOL_MODELS)

        conf = CONF_LIKELY if (aicloud or eol) else CONF_WEAK
        status = Status.LIKELY if (aicloud or eol) else Status.UNKNOWN
        ev_common = "ASUS WRT"
        if aicloud:
            ev_common += "; сервис AiCloud доступен (8443)"
        if eol:
            ev_common += "; модель в списке EoL"

        remediation = ("Обновить прошивку (для поддерживаемых моделей); отключить "
                       "AiCloud; EoL-модели — замена.")
        findings: list[Finding] = []
        for cve, title, severity in CHAIN:
            findings.append(Finding(
                cve=cve, title=title, severity=severity, status=status,
                confidence=conf, affected_component="ASUS WRT / AiCloud",
                evidence=ev_common, eol=eol, remediation=remediation,
                references=[f"https://nvd.nist.gov/vuln/detail/{cve}"]))
        return findings

    async def _aicloud_present(self, device: DeviceInfo, http) -> bool:
        if not device.has_port(8443, 443):
            return False
        for port in (8443, 443):
            if not device.has_port(port):
                continue
            try:
                r = await http.get(f"https://{device.ip}:{port}/")
                low = (r.text or "").lower()
                if "aicloud" in low or "asus" in low:
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False
