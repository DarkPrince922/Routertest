"""SNMP stage — detect default/weak SNMP community strings (UDP 161).

A readable default community (e.g. ``public``) leaks device config/inventory and
is a very common router misconfiguration. Uses the ``snmpget`` CLI (net-snmp); if
it is not installed the stage degrades to an info finding.
"""
from __future__ import annotations

import logging

from ..cve_db import match_fingerprint
from ..models import Finding, Severity
from ..runtime import get_config
from ._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

SNMP_TIMEOUT = 20.0
SYSDESCR_OID = "1.3.6.1.2.1.1.1.0"  # the device's system description


async def snmp_stage(target: str) -> list[Finding]:
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
            # The sysDescr often reveals model/firmware → check it for CVEs too.
            findings.extend(match_fingerprint(sysdescr.lower()))

    if not found_any:
        findings.append(Finding("snmp", Severity.INFO,
                                "SNMP: дефолтные community не отвечают", {}))
    return findings
