"""SNMP stage — detect default/weak SNMP community strings (UDP 161).

A readable default community (e.g. ``public``) leaks device config/inventory and
is a very common router misconfiguration. Uses the ``snmpget`` CLI (net-snmp); if
it is not installed the stage degrades to an info finding.
"""
from __future__ import annotations

import logging

from ..cve_db import match_fingerprint, record_cve
from ..models import Finding, Severity
from ..runtime import get_config
from ._common import ToolNotFound, run_cmd
from .nmap_stage import detect_vendor

log = logging.getLogger(__name__)

SNMP_TIMEOUT = 20.0
SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"  # the device's system description


async def snmp_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    """Try default community strings against sysDescr; report any that answer."""
    communities = get_config().snmp_communities
    findings: list[Finding] = []
    found_any = False

    for community in communities:
        cmd = ["snmpget", "-v2c", "-c", community, "-t", "1", "-r", "1",
               "-Ovq", target, SYSDESCR_OID]
        try:
            rc, stdout, stderr = await run_cmd(cmd, timeout=SNMP_TIMEOUT)
        except ToolNotFound:
            return [Finding("snmp", Severity.INFO, "snmp tools not installed",
                            {"error": "snmpget (net-snmp) not found on PATH"})]

        sysdescr = stdout.strip().strip('"')
        ok = (rc == 0 and sysdescr
              and "Timeout" not in stderr
              and "No Such" not in sysdescr
              and "No Response" not in stderr)
        if ok:
            found_any = True
            findings.append(Finding(
                "snmp", Severity.HIGH,
                f"SNMP: доступна community '{community}' (чтение)",
                {"community": community, "sysDescr": sysdescr[:300]},
            ))
            findings.append(Finding(
                "snmp", Severity.INFO, f"🧭 Модель (SNMP): {sysdescr[:160]}",
                {"sysDescr": sysdescr[:300]}))
            # The sysDescr often reveals model/firmware → check it for CVEs too
            # (passive inference; the verify stage re-checks these actively).
            for cve_finding in match_fingerprint(sysdescr.lower()):
                findings.append(cve_finding)
                record_cve(ctx, cve_finding.detail.get("cve"), "fingerprint")
            # sysDescr is the most precise model source — enrich the shared ctx.
            if ctx is not None:
                ctx["model"] = sysdescr[:160]
                if not ctx.get("vendor"):
                    ctx["vendor"] = detect_vendor(sysdescr.lower())
                ctx["fingerprint_blob"] = (
                    ctx.get("fingerprint_blob", "") + " " + sysdescr.lower())
            break  # one working community is enough

    if not found_any:
        findings.append(Finding("snmp", Severity.INFO,
                                "SNMP: дефолтные community не отвечают", {}))
    return findings
