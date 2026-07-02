"""XiongMai / TBK DVR-NVR-CCTV — P2P tunnel + default creds (e.g. CVE-2024-3721).

Detection-only: fingerprint the XiongMai/TBK web UI and characteristic ports
(34567 media, 9527), treat the presence of the P2P service as an extra indicator.
No credential checks here (default-cred verification would be an active,
authorized-only step handled elsewhere).
"""
from __future__ import annotations

from ..base import CONF_LIKELY, CONF_WEAK, DeviceInfo, Detector, Finding, Status

VENDOR_TOKENS = ("xiongmai", "tbk", "netsurveillance", "dvrdvs", "hi3520")


class XiongmaiTbkDvr(Detector):
    name = "XiongMai/TBK DVR (CVE-2024-3721)"
    cves = ("CVE-2024-3721",)

    def applicable(self, device: DeviceInfo) -> bool:
        blob = device.blob()
        return (any(t in blob for t in VENDOR_TOKENS)
                or device.has_port(34567, 9527))

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        vendor_hit = any(t in device.blob() for t in VENDOR_TOKENS)
        media_port = device.has_port(34567)
        ui_seen = await self._ui_present(device, http)

        conf = CONF_WEAK
        if vendor_hit:
            conf = CONF_LIKELY
        if media_port:
            conf = min(0.85, conf + 0.15)
        ev_bits = []
        if vendor_hit:
            ev_bits.append("сигнатуры XiongMai/TBK")
        if media_port:
            ev_bits.append("медиапорт 34567 открыт (P2P-индикатор)")
        if ui_seen:
            ev_bits.append("веб-интерфейс DVR доступен")
        ev = "; ".join(ev_bits) or "признаки XiongMai/TBK DVR"

        return [Finding(
            cve="CVE-2024-3721", title="XiongMai/TBK DVR default creds / P2P exposure",
            severity="high", status=Status.LIKELY if vendor_hit else Status.UNKNOWN,
            confidence=conf, affected_component="DVR web UI / P2P", evidence=ev,
            remediation="Отключить P2P/UPnP; сменить дефолт-креды; вынести в отдельный "
                        "VLAN; при EoL — замена.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-3721"])]

    async def _ui_present(self, device: DeviceInfo, http) -> bool:
        for port in (80, 8080, 9527):
            if not device.has_port(port):
                continue
            try:
                r = await http.get(f"http://{device.ip}:{port}/")
                if r.status < 500:
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False
