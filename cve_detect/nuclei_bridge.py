"""Bridge to nuclei for CVEs that have a vetted community template.

Runs ``nuclei -silent -jsonl -id <CVE> -u <scoped-url>`` and normalizes matches
into the module's :class:`Finding`. Only ever targets the scope-approved host
URLs passed in — nuclei is never pointed at anything the caller didn't authorize.
Best-effort: if nuclei is missing or errors, returns no findings.
"""
from __future__ import annotations

import json
import logging

from .base import CONF_CONFIRMED, Finding, Status

log = logging.getLogger(__name__)

NUCLEI_TIMEOUT = 180.0
# CVEs we trust a community template for (active confirmation).
BRIDGED_CVES = {
    "CVE-2023-1389": ("critical", "TP-Link Archer AX21 command injection"),
    "CVE-2018-10562": ("critical", "GPON auth bypass + RCE"),
    "CVE-2017-17215": ("critical", "Huawei HG532 TR-064 command injection"),
}


async def run_nuclei(cve: str, urls: list[str], *, timeout: float = NUCLEI_TIMEOUT
                     ) -> list[Finding]:
    """Confirm ``cve`` with its nuclei template against ``urls``. Active check."""
    if cve not in BRIDGED_CVES or not urls:
        return []
    # Lazy import keeps cve_detect importable without the engine present (tests).
    from engine.stages._common import ToolNotFound, run_cmd

    cmd = ["nuclei", "-silent", "-jsonl", "-timeout", "5", "-id", cve]
    for u in urls:
        cmd += ["-u", u]
    try:
        _, stdout, _ = await run_cmd(cmd, timeout=timeout)
    except ToolNotFound:
        return []
    except Exception:  # noqa: BLE001
        log.debug("nuclei bridge failed for %s", cve, exc_info=True)
        return []

    severity, title = BRIDGED_CVES[cve]
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        matched = obj.get("matched-at") or obj.get("host") or ""
        return [Finding(
            cve=cve, title=title, severity=severity, status=Status.VULNERABLE,
            confidence=CONF_CONFIRMED, affected_component="nuclei template match",
            evidence=f"nuclei-темплейт {cve} сработал" + (f" @ {matched}" if matched else ""),
            remediation="См. remediation соответствующего детектора; обновить прошивку.",
            references=[f"https://nvd.nist.gov/vuln/detail/{cve}"])]
    return []
