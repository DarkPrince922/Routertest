"""CVE-2023-1389 — TP-Link Archer AX21/AX1800 unauthenticated command injection.

Detection-only: we fingerprint the model + firmware and confirm the web login
endpoint exists. We never send the ``country``/``operation=write`` payload — the
active confirmation for this CVE is left to the vetted nuclei template, run via
``nuclei_bridge`` when ``--active`` is set.
"""
from __future__ import annotations

from ..base import (
    CONF_LIKELY,
    CONF_WEAK,
    DeviceInfo,
    Detector,
    Finding,
    Status,
)
from ..versions import is_below

FIXED = "1.1.4 Build 20230219"


class TplinkArcherAx21(Detector):
    name = "TP-Link Archer AX21 (CVE-2023-1389)"
    cves = ("CVE-2023-1389",)

    def applicable(self, device: DeviceInfo) -> bool:
        blob = device.blob()
        return (("archer ax21" in blob or "archer ax1800" in blob or "ax1800" in blob)
                or ("tp-link" in blob and "archer" in blob and device.has_port(80, 8080)))

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        below = is_below(device.firmware, FIXED)
        if below is False:
            return [self._finding(Status.NOT_VULNERABLE, CONF_WEAK,
                                  f"прошивка {device.firmware} >= {FIXED} (пропатчена)")]

        # Non-destructive endpoint presence (GET the login page).
        endpoint_seen = await self._login_present(device, http)
        if below is True:
            conf = CONF_LIKELY + (0.05 if endpoint_seen else 0.0)
            ev = f"модель Archer AX21/AX1800, прошивка {device.firmware} ниже фикса {FIXED}"
        else:
            conf = CONF_WEAK + (0.1 if endpoint_seen else 0.0)
            ev = "модель Archer AX21/AX1800; версия прошивки не определена"
        if endpoint_seen:
            ev += "; веб-эндпоинт логина доступен"
        return [self._finding(Status.LIKELY, conf, ev)]

    async def _login_present(self, device: DeviceInfo, http) -> bool:
        for port in (80, 8080):
            if not device.has_port(port):
                continue
            try:
                r = await http.get(f"http://{device.ip}:{port}/")
                if r.status < 500:
                    return True
            except Exception:  # noqa: BLE001 - presence probe is best-effort
                continue
        return False

    def _finding(self, status: str, conf: float, evidence: str) -> Finding:
        return Finding(
            cve="CVE-2023-1389", title="TP-Link Archer AX21 unauth command injection",
            severity="critical", status=status, confidence=conf,
            affected_component="web management (tmpToken/country)", evidence=evidence,
            remediation="Обновить прошивку до пропатченной (>= 1.1.4 Build 20230219); "
                        "закрыть веб-управление с WAN.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-1389"])
