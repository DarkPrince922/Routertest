"""vulners stage — map detected service versions to CVEs via nmap's NSE script.

``nmap -sV --script vulners`` takes the service/version output and queries the
Vulners DB, returning known CVEs (with CVSS) per service. This is VERSION-BASED
INFERENCE (like the fingerprint KB), not an active exploit check — so hits are
recorded as an inference method and the verify stage can re-check them.

Needs outbound access to vulners.com (the script is an online lookup). If the
script isn't installed or there's no connectivity, the stage degrades to an info
finding rather than failing the scan. Skipped in batch/subnet (light) scans to
avoid hammering the Vulners API across many hosts.
"""
from __future__ import annotations

import logging
import re
from xml.etree import ElementTree as ET

from ..cve_db import record_cve
from ..models import Finding, Severity
from ..runtime import get_config
from ._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

VULNERS_TIMEOUT = 300.0
# Lines look like:  CVE-2021-28041  7.1  https://vulners.com/cve/CVE-2021-28041
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{3,7})\s+(\d+(?:\.\d+)?)")
# Cap how many individual CVE findings we emit (the rest are summarised).
MAX_INDIVIDUAL = 40


def _severity(cvss: float) -> Severity:
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss > 0:
        return Severity.LOW
    return Severity.INFO


async def vulners_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    cfg = get_config()
    ctx = ctx or {}
    if not cfg.vulners_enabled:
        return [Finding("vulners", Severity.INFO,
                        "vulners: выключен (⚙️ Настройки)", {})]
    # An online per-host lookup — too chatty to run across a whole subnet.
    if ctx.get("light"):
        return [Finding("vulners", Severity.INFO,
                        "vulners: пропущен в пакетном/подсетевом скане", {})]

    open_ports = ctx.get("open_ports") or []
    cmd = ["nmap", "-sV", "--script", "vulners", "-Pn", "-T4",
           "--host-timeout", "180s"]
    if open_ports:
        cmd += ["-p", ",".join(str(p) for p in open_ports)]
    cmd += ["-oX", "-", target]

    try:
        _, stdout, stderr = await run_cmd(cmd, timeout=VULNERS_TIMEOUT)
    except ToolNotFound:
        return [Finding("vulners", Severity.INFO, "nmap не установлен",
                        {"error": "nmap not found on PATH"})]
    except Exception as exc:  # noqa: BLE001
        return [Finding("vulners", Severity.INFO,
                        f"vulners: ошибка запуска ({exc})", {})]

    return _parse_vulners(stdout, stderr, ctx)


def _parse_vulners(xml_text: str, stderr: str, ctx: dict) -> list[Finding]:
    # cve -> (max_cvss, port, service)
    hits: dict[str, tuple[float, str, str]] = {}
    saw_script = False
    try:
        root = ET.fromstring(xml_text) if xml_text.strip() else None
    except ET.ParseError:
        root = None

    if root is not None:
        for host in root.findall("host"):
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                portid = port.get("portid", "?")
                svc_el = port.find("service")
                service = ""
                if svc_el is not None:
                    service = (svc_el.get("product", "")
                               + " " + svc_el.get("version", "")).strip()
                for script in port.findall("script"):
                    if script.get("id") != "vulners":
                        continue
                    saw_script = True
                    output = script.get("output", "") or ""
                    for m in _CVE_RE.finditer(output):
                        cve, score = m.group(1).upper(), _to_float(m.group(2))
                        prev = hits.get(cve)
                        if prev is None or score > prev[0]:
                            hits[cve] = (score, portid, service)

    if not hits:
        low = stderr.lower()
        if "vulners" in low and ("not" in low or "error" in low):
            return [Finding("vulners", Severity.INFO,
                            "vulners: NSE-скрипт недоступен — обновите nmap-скрипты "
                            "(`nmap --script-updatedb`)", {"stderr": stderr[:200]})]
        note = ("совпадений нет" if saw_script
                else "нет данных (нет доступа к vulners.com или версии не определены)")
        return [Finding("vulners", Severity.INFO, f"vulners: {note}", {})]

    ordered = sorted(hits.items(), key=lambda kv: kv[1][0], reverse=True)
    findings: list[Finding] = []
    minor = 0
    for cve, (cvss, port, service) in ordered:
        sev = _severity(cvss)
        if sev in (Severity.HIGH, Severity.CRITICAL) and len(findings) < MAX_INDIVIDUAL:
            svc = f" · {service}" if service else ""
            findings.append(Finding(
                "vulners", sev, f"{cve} (CVSS {cvss}) — порт {port}{svc}",
                {"cve": cve, "cvss": cvss, "port": port, "service": service,
                 "reference": f"https://vulners.com/cve/{cve}"}))
            record_cve(ctx, cve, "vulners")  # inference — verify re-checks
        else:
            minor += 1

    crit = sum(1 for _c, (s, _p, _sv) in ordered if s >= 9.0)
    high = sum(1 for _c, (s, _p, _sv) in ordered if 7.0 <= s < 9.0)
    findings.append(Finding(
        "vulners", Severity.INFO,
        f"vulners: всего CVE {len(ordered)} (critical {crit}, high {high}); "
        f"остальные {minor} — ниже high",
        {"total": len(ordered), "critical": crit, "high": high}))
    return findings


def _to_float(s: str) -> float:
    try:
        return float(s)
    except ValueError:
        return 0.0
