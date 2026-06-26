"""nmap stage — service/version + OS/device detection, parsed from XML output.

Besides per-port findings, this stage emits a single ``fingerprint`` finding that
classifies the target as ``router`` / ``not_router`` / ``unknown``. The runner
reads that verdict (via :func:`router_verdict`) to decide whether to skip the
deeper router-oriented stages on a non-router target.
"""
from __future__ import annotations

import logging
from xml.etree import ElementTree as ET

from ..models import Finding, Severity
from ._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

NMAP_TIMEOUT = 600.0

# osclass "type" values we treat as router-like.
ROUTER_TYPES = {
    "router", "broadband router", "wap", "wireless access point",
    "gateway", "firewall", "load balancer",
}
# Recognized device types that are clearly NOT routers.
NON_ROUTER_TYPES = {
    "general purpose", "printer", "print server", "storage-misc", "phone",
    "webcam", "media device", "game console", "power-device", "switch",
    "remote management", "specialized", "pbx",
}
# Vendor/product banner keywords that strongly imply a router/CPE.
ROUTER_KEYWORDS = (
    "mikrotik", "routeros", "routerboard", "dd-wrt", "openwrt", "tomato",
    "d-link", "dlink", "tp-link", "tplink", "netgear", "asuswrt", "huawei",
    "zyxel", "draytek", "ubiquiti", "edgeos", "edgerouter", "pfsense", "opnsense",
    "fritz!box", "fritzbox", "tenda", "linksys", "routerboard", "gpon", "ont",
    "cpe", "dsl", "cisco ios", "juniper", "vyos", "hg8", "broadband",
)


async def nmap_stage(target: str) -> list[Finding]:
    """Run nmap with service + OS detection and classify the device type.

    Tries ``-sV -O``; if OS detection needs privileges we don't have, falls back
    to ``-sV`` so port/service results still work.
    """
    cmd = ["nmap", "-sV", "-O", "-Pn", "-oX", "-", target]
    try:
        rc, stdout, stderr = await run_cmd(cmd, timeout=NMAP_TIMEOUT)
    except ToolNotFound:
        return [Finding("nmap", Severity.INFO, "nmap not installed",
                        {"error": "nmap binary not found on PATH"})]

    # -O requires raw sockets; without privileges nmap quits before scanning.
    if _needs_privileges(stderr) or not stdout.strip():
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


def _needs_privileges(stderr: str) -> bool:
    return "requires root privileges" in stderr.lower() or "requires r" in stderr.lower()


def _parse_nmap_xml(xml_text: str) -> list[Finding]:
    findings: list[Finding] = []
    products: list[str] = []
    services: list[str] = []
    root = ET.fromstring(xml_text)

    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is not None:
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

                services.append(service)
                if product:
                    products.append(product)

                label = f"{portid}/{proto} open: {service}"
                if product:
                    label += f" ({product} {version})".rstrip()
                findings.append(Finding(
                    stage="nmap", severity=Severity.INFO, title=label,
                    detail={"port": portid, "protocol": proto, "service": service,
                            "product": product, "version": version},
                ))

        os_info = _parse_os(host)
        # Build the device-type fingerprint finding for this host.
        findings.append(_fingerprint_finding(products, services, os_info))

    if not findings:
        findings.append(Finding("nmap", Severity.INFO, "no open ports found", {}))
    return findings


def _parse_os(host: ET.Element) -> dict:
    """Extract the best (highest-accuracy) OS/device classification."""
    os_el = host.find("os")
    if os_el is None:
        return {}
    best: dict = {}
    best_acc = -1
    # osclass elements may sit under <osmatch> or directly under <os>.
    osclasses = os_el.findall(".//osclass")
    for oc in osclasses:
        try:
            acc = int(oc.get("accuracy", "0"))
        except ValueError:
            acc = 0
        if acc >= best_acc:
            best_acc = acc
            best = {
                "device_type": (oc.get("type") or "").lower(),
                "vendor": oc.get("vendor") or "",
                "osfamily": oc.get("osfamily") or "",
                "accuracy": acc,
            }
    osmatch = os_el.find("osmatch")
    if osmatch is not None:
        best["os_name"] = osmatch.get("name", "")
    return best


def _fingerprint_finding(products: list[str], services: list[str], os_info: dict) -> Finding:
    verdict, label, confidence = _classify(products, services, os_info)
    icon = {"router": "🧭", "not_router": "🚫", "unknown": "❔"}[verdict]
    title = f"Тип устройства: {label}"
    return Finding(
        stage="fingerprint",
        severity=Severity.INFO,
        title=f"{icon} {title}",
        detail={
            "verdict": verdict,
            "label": label,
            "confidence": confidence,
            "device_type": os_info.get("device_type", ""),
            "vendor": os_info.get("vendor", ""),
            "osfamily": os_info.get("osfamily", ""),
            "os_name": os_info.get("os_name", ""),
            "accuracy": os_info.get("accuracy", 0),
        },
    )


def _classify(products: list[str], services: list[str], os_info: dict) -> tuple[str, str, str]:
    """Return (verdict, human_label, confidence).

    verdict ∈ {"router", "not_router", "unknown"}.
    """
    blob = " ".join(products + services + [
        os_info.get("vendor", ""), os_info.get("osfamily", ""),
        os_info.get("os_name", ""),
    ]).lower()

    # 1) Strong signal: known router vendor/product in banners or OS name.
    matched_kw = next((kw for kw in ROUTER_KEYWORDS if kw in blob), None)
    if matched_kw:
        name = os_info.get("os_name") or os_info.get("vendor") or matched_kw
        return "router", f"роутер ({name})", "высокая"

    # 2) nmap device type.
    dtype = os_info.get("device_type", "")
    acc = os_info.get("accuracy", 0)
    if dtype:
        name = os_info.get("os_name") or dtype
        if dtype in ROUTER_TYPES:
            return "router", f"роутер ({name}, {acc}%)", "средняя"
        if dtype in NON_ROUTER_TYPES:
            return "not_router", f"не роутер ({name}, {acc}%)", "средняя"
        return "unknown", f"неопределённо ({name}, {acc}%)", "низкая"

    # 3) No OS data at all.
    return "unknown", "не удалось определить", "нет данных"


def router_verdict(findings: list[Finding]) -> tuple[str, str]:
    """Pull (verdict, label) out of the fingerprint finding; default unknown."""
    for f in findings:
        if f.stage == "fingerprint":
            return f.detail.get("verdict", "unknown"), f.detail.get("label", "")
    return "unknown", ""
