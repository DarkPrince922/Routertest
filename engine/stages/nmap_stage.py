"""nmap stage — service/version detection, parsed from XML output."""
from __future__ import annotations

import logging
from xml.etree import ElementTree as ET

from ..models import Finding, Severity
from ._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

NMAP_TIMEOUT = 600.0


async def nmap_stage(target: str) -> list[Finding]:
    """Run ``nmap -sV -Pn -oX -`` and emit one Finding per open port."""
    cmd = ["nmap", "-sV", "-Pn", "-oX", "-", target]
    try:
        rc, stdout, stderr = await run_cmd(cmd, timeout=NMAP_TIMEOUT)
    except ToolNotFound:
        return [Finding("nmap", Severity.INFO, "nmap not installed",
                        {"error": "nmap binary not found on PATH"})]

    if not stdout.strip():
        return [Finding("nmap", Severity.INFO, "nmap produced no output",
                        {"returncode": rc, "stderr": stderr[:500]})]

    try:
        return _parse_nmap_xml(stdout)
    except ET.ParseError as exc:
        return [Finding("nmap", Severity.INFO, "nmap XML parse error",
                        {"error": str(exc)})]


def _parse_nmap_xml(xml_text: str) -> list[Finding]:
    findings: list[Finding] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "?")
            proto = port.get("protocol", "?")
            svc = port.find("service")
            service = svc.get("name", "unknown") if svc is not None else "unknown"
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""

            label = f"{portid}/{proto} open: {service}"
            if product:
                label += f" ({product} {version})".rstrip()

            findings.append(
                Finding(
                    stage="nmap",
                    severity=Severity.INFO,
                    title=label,
                    detail={
                        "port": portid,
                        "protocol": proto,
                        "service": service,
                        "product": product,
                        "version": version,
                    },
                )
            )
    if not findings:
        findings.append(Finding("nmap", Severity.INFO, "no open ports found", {}))
    return findings
