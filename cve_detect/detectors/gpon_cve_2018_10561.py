"""CVE-2018-10561 / CVE-2018-10562 — GPON home gateways (Dasan/ZTE ONT).

Detection-only. Safe: fingerprint the GPON web UI (``/GponForm/``, title/Server).
Active (opt-in): a NON-destructive auth-bypass probe — compare the response of an
auth-required page with the same path + ``?images/`` marker. We only observe
whether the bypass returns authorized content; we never append a shell command.
"""
from __future__ import annotations

from ..base import (
    CONF_CONFIRMED,
    CONF_LIKELY,
    CONF_WEAK,
    DeviceInfo,
    Detector,
    Finding,
    Status,
)

AUTH_PAGE = "/menu.html"


class GponAuthBypass(Detector):
    name = "GPON ONT auth-bypass/RCE (CVE-2018-10561/10562)"
    cves = ("CVE-2018-10561", "CVE-2018-10562")

    def applicable(self, device: DeviceInfo) -> bool:
        blob = device.blob()
        return ("gpon" in blob or "gponform" in blob
                or ("ont" in blob and device.has_port(80, 443)))

    async def check(self, device: DeviceInfo, http, *, active: bool) -> list[Finding]:
        fingerprinted = await self._gpon_ui(device, http)
        status, conf, ev = Status.UNKNOWN, CONF_WEAK, "признаки GPON-шлюза"
        if fingerprinted:
            status, conf = Status.LIKELY, CONF_LIKELY
            ev = "обнаружена веб-форма GPON (/GponForm/ или сигнатуры страницы)"

        if active:
            bypass = await self._auth_bypass(device, http)
            if bypass is True:
                status, conf = Status.VULNERABLE, CONF_CONFIRMED
                ev = ("активная неразрушающая проверка: обращение к защищённой "
                      "странице с маркером '?images/' вернуло авторизованный ответ "
                      "(обход аутентификации подтверждён)")
            elif bypass is False and fingerprinted:
                status, conf = Status.NOT_VULNERABLE, 0.6
                ev = "обход аутентификации не сработал (страница осталась закрытой)"

        return [Finding(
            cve="CVE-2018-10562", title="GPON ONT auth bypass + RCE",
            severity="critical", status=status, confidence=conf,
            affected_component="web UI (GponForm/diag)", evidence=ev,
            remediation="Обновить прошивку ONT; закрыть веб-доступ с WAN.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2018-10562"])]

    async def _gpon_ui(self, device: DeviceInfo, http) -> bool:
        for scheme, port in (("http", 80), ("https", 443)):
            if not device.has_port(port):
                continue
            try:
                r = await http.get(f"{scheme}://{device.ip}:{port}/")
                low = (r.text or "").lower()
                if "gponform" in low or "gpon" in low:
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False

    async def _auth_bypass(self, device: DeviceInfo, http) -> bool | None:
        """Compare authed page vs '?images/' marker. Returns True if bypassed,
        False if not, None if the probe couldn't run. No command is ever sent."""
        for scheme, port in (("http", 80), ("https", 443)):
            if not device.has_port(port):
                continue
            base = f"{scheme}://{device.ip}:{port}"
            try:
                plain = await http.get(f"{base}{AUTH_PAGE}")
                marked = await http.active_get(f"{base}{AUTH_PAGE}?images/")
            except Exception:  # noqa: BLE001
                continue
            # Bypass: the marked request yields 200 authorized content where the
            # plain one was redirected/blocked.
            if marked.status == 200 and plain.status != 200:
                return True
            return False
        return None
