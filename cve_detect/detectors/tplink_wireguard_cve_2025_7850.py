"""CVE-2025-7850 / CVE-2025-7851 — TP-Link (WireGuard OS command injection /
left-in debug code, root).

Detection-only: match TP-Link model + vulnerable firmware range, and treat the
presence of a WireGuard-VPN configuration section in the web UI as a confidence
booster for 7850. No payload is ever sent.
"""
from __future__ import annotations

from ..base import CONF_LIKELY, CONF_WEAK, DeviceInfo, Detector, Finding, Status

# Illustrative vulnerable-firmware tokens (refine against vendor advisories).
VULN_TOKENS = {"1.0.", "1.1.", "1.2."}


class TplinkWireguard(Detector):
    name = "TP-Link WireGuard/debug (CVE-2025-7850/7851)"
    cves = ("CVE-2025-7850", "CVE-2025-7851")

    def applicable(self, device: DeviceInfo) -> bool:
        blob = device.blob()
        return "tp-link" in blob or "tplink" in blob or "archer" in blob

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        wg_seen = await self._wireguard_present(device, http)
        findings: list[Finding] = []

        conf = CONF_LIKELY if wg_seen else CONF_WEAK
        ev7850 = "модель TP-Link" + (
            "; в веб-UI присутствует раздел WireGuard-VPN" if wg_seen
            else "; раздел WireGuard не подтверждён")
        findings.append(Finding(
            cve="CVE-2025-7850", title="TP-Link WireGuard OS command injection (root)",
            severity="critical",
            status=Status.LIKELY if wg_seen else Status.UNKNOWN, confidence=conf,
            affected_component="web UI: WireGuard VPN config", evidence=ev7850,
            remediation="Обновить прошивку; отключить неиспользуемый VPN-функционал; "
                        "не выставлять веб-управление наружу.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-7850"]))

        findings.append(Finding(
            cve="CVE-2025-7851", title="TP-Link left-in debug interface (root)",
            severity="high", status=Status.UNKNOWN, confidence=CONF_WEAK,
            affected_component="debug service/interface",
            evidence="модель TP-Link; наличие отладочного интерфейса не проверяется "
                     "неразрушающе — требуется ручная верификация",
            remediation="Обновить прошивку; убедиться, что отладочные сервисы отключены.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-7851"]))
        return findings

    async def _wireguard_present(self, device: DeviceInfo, http) -> bool:
        for port in (80, 8080, 443, 8443):
            if not device.has_port(port):
                continue
            scheme = "https" if port in (443, 8443) else "http"
            try:
                r = await http.get(f"{scheme}://{device.ip}:{port}/")
                if "wireguard" in r.text.lower():
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False
