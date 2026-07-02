"""CVE-2017-17215 — Huawei HG532 and kin, TR-064 command injection (UPnP 37215).

Detection-only: fingerprint the model + reachability of the TR-064 control
endpoint ``/ctrlt/DeviceUpgrade_1``. We never send the ``NewStatusURL`` injection;
the safe check only confirms the endpoint responds (GET/HEAD, no SOAP payload).
"""
from __future__ import annotations

from ..base import CONF_LIKELY, CONF_WEAK, DeviceInfo, Detector, Finding, Status

TR064_PATH = "/ctrlt/DeviceUpgrade_1"


class HuaweiHg532Tr064(Detector):
    name = "Huawei HG532 TR-064 (CVE-2017-17215)"
    cves = ("CVE-2017-17215",)

    def applicable(self, device: DeviceInfo) -> bool:
        blob = device.blob()
        model_hit = "hg532" in blob or "hg5" in blob or "echolife" in blob
        return model_hit or device.has_port(37215, 52869)

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        reachable = await self._tr064_reachable(device, http)
        model_hit = "hg53" in device.blob() or "echolife" in device.blob()

        if reachable:
            conf = CONF_LIKELY + (0.1 if model_hit else 0.0)
            ev = f"TR-064 контрол-эндпоинт {TR064_PATH} отвечает на 37215"
        else:
            conf = CONF_WEAK if model_hit else 0.3
            ev = "модель/порт Huawei HG5xx; TR-064-эндпоинт не подтверждён"
        return [Finding(
            cve="CVE-2017-17215", title="Huawei HG532 TR-064 command injection",
            severity="critical", status=Status.LIKELY, confidence=min(conf, 0.9),
            affected_component="TR-064 (UPnP) DeviceUpgrade", evidence=ev,
            remediation="Обновить прошивку/сменить у провайдера; закрыть TR-064 с WAN; "
                        "отключить UPnP наружу.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-17215"])]

    async def _tr064_reachable(self, device: DeviceInfo, http) -> bool:
        for port in (37215, 52869, 7547):
            if not device.has_port(port):
                continue
            try:
                # Presence only — a GET on the control path (no SOAP body/injection).
                r = await http.get(f"http://{device.ip}:{port}{TR064_PATH}")
                if r.status in (200, 400, 401, 405, 500):
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False
