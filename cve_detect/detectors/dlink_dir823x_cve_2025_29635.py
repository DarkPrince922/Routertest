"""CVE-2025-29635 — D-Link DIR-823X command injection (EoL, no patch).

Detection-only: model DIR-823X + known vulnerable firmware token → likely. The
device is end-of-life, so the finding is flagged ``eol`` (recommend replacement).
"""
from __future__ import annotations

from ..base import CONF_LIKELY, CONF_WEAK, DeviceInfo, Detector, Finding, Status
from ..versions import in_vulnerable_set

VULN_FW = {"240126", "24082"}


class DlinkDir823x(Detector):
    name = "D-Link DIR-823X (CVE-2025-29635)"
    cves = ("CVE-2025-29635",)

    def applicable(self, device: DeviceInfo) -> bool:
        return "dir-823x" in device.blob() or "dir823x" in device.blob()

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        fw_match = in_vulnerable_set(device.firmware, VULN_FW)
        present = await self._http_present(device, http)
        conf = CONF_LIKELY if fw_match else CONF_WEAK
        if present:
            conf = min(0.9, conf + 0.05)
        ev = "модель DIR-823X" + (
            f", прошивка {device.firmware} в уязвимом списке" if fw_match
            else "; версия прошивки не подтверждена")
        if present:
            ev += "; веб-эндпоинт управления доступен"
        return [Finding(
            cve="CVE-2025-29635", title="D-Link DIR-823X command injection (EoL)",
            severity="high", status=Status.LIKELY, confidence=conf,
            affected_component="web management", evidence=ev, eol=True,
            remediation="Устройство снято с поддержки (патча нет): вывод из "
                        "эксплуатации/замена; временно — полная изоляция WAN-доступа "
                        "к управлению.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-29635"])]

    async def _http_present(self, device: DeviceInfo, http) -> bool:
        for port in (80, 8080):
            if not device.has_port(port):
                continue
            try:
                r = await http.get(f"http://{device.ip}:{port}/")
                if r.status < 500:
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False
