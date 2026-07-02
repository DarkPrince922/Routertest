"""D-Link DIR-620 and kin — hardcoded credentials / backdoor.

Detection-only. Safe: model/firmware fingerprint against the known-vulnerable
list → likely. The default/hardcoded-credential check runs ONLY in ``--active``
and is a SINGLE attempt with the one known pair (no brute force), against a host
already explicitly authorized in scope.
"""
from __future__ import annotations

import base64

from ..base import (
    CONF_CONFIRMED,
    CONF_LIKELY,
    CONF_WEAK,
    DeviceInfo,
    Detector,
    Finding,
    Status,
)

VULN_MODELS = {"dir-620", "dir620"}
# The single publicly-documented backdoor pair (checked once, never brute-forced).
_KNOWN_USER = "anonymous"
_KNOWN_PASS = "anonymous"


class DlinkDir620Backdoor(Detector):
    name = "D-Link DIR-620 backdoor"
    cves = ("CVE-2018-6213",)

    def applicable(self, device: DeviceInfo) -> bool:
        blob = device.blob()
        return any(m in blob for m in VULN_MODELS)

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        status, conf = Status.LIKELY, CONF_LIKELY
        ev = "модель DIR-620 из известного уязвимого списка"

        if active:
            confirmed = await self._single_cred_try(device, http)
            if confirmed is True:
                status, conf = Status.VULNERABLE, CONF_CONFIRMED
                ev = ("активная проверка: одна попытка известной hardcoded-пары "
                      "принята устройством (учётные данные в отчёт не пишутся)")
            elif confirmed is False:
                conf = CONF_WEAK
                ev += "; известная пара не принята"

        return [Finding(
            cve="CVE-2018-6213", title="D-Link DIR-620 hardcoded credentials/backdoor",
            severity="high", status=status, confidence=conf,
            affected_component="web/telnet auth", evidence=ev, eol=True,
            remediation="Вывод из эксплуатации; смена всех учётных данных; изоляция.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2018-6213"])]

    async def _single_cred_try(self, device: DeviceInfo, http) -> bool | None:
        """ONE HTTP-Basic attempt with the known pair (active-only, no brute)."""
        token = base64.b64encode(
            f"{_KNOWN_USER}:{_KNOWN_PASS}".encode()).decode()
        for port in (80, 8080):
            if not device.has_port(port):
                continue
            try:
                r = await http.active_get(
                    f"http://{device.ip}:{port}/",
                    headers={"Authorization": f"Basic {token}"})
            except Exception:  # noqa: BLE001
                continue
            return r.status not in (401, 403) and r.status < 400
        return None
