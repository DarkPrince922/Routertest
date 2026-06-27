"""nmap stage — service/version + OS/device detection, parsed from XML output.

Besides per-port findings, this stage emits a single ``fingerprint`` finding that
classifies the target as ``router`` / ``not_router`` / ``unknown``. The runner
reads that verdict (via :func:`router_verdict`) to decide whether to skip the
deeper router-oriented stages on a non-router target.
"""
from __future__ import annotations

import asyncio
import logging
from xml.etree import ElementTree as ET

from ..cve_db import match_fingerprint
from ..models import Finding, Severity
from ..portscan import masscan_available, masscan_ports
from ..runtime import get_config
from ._banners import grab_banners
from ._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

NMAP_TIMEOUT = 600.0
# Per-host wall-clock cap so dead IPs in a batch don't burn the full timeout.
NMAP_HOST_TIMEOUT = "120s"
# Router/CPE-relevant TCP ports (incl. MikroTik Winbox 8291 / API 8728-8729,
# TR-069 7547, common alt-HTTP and mgmt ports). Scanning ~30 ports instead of
# nmap's default 1000 is the main per-target speedup.
ROUTER_PORTS = (
    "21,22,23,53,80,81,88,443,515,631,2000,2222,4433,5000,7547,8000,8080,8081,"
    "8088,8291,8443,8728,8729,8888,9000,9999,10000,49152,52869"
)

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


async def nmap_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    """Discover open ports and classify the device type.

    Port discovery uses masscan when available/selected (fast, raw-SYN — gets
    through connect-scan limits), then nmap ``-sV`` enriches just those ports with
    service/version/OS. Otherwise nmap scans directly (router ports, with a
    top-1000 fallback). Banner grabbing + CVE matching run regardless.
    """
    port_findings: list[Finding] = []
    products: list[str] = []
    services: list[str] = []
    os_info: dict = {}
    open_ports: list[int] = []

    # --- 1. masscan fast path ------------------------------------------------
    cfg = get_config()
    scanner = cfg.port_scanner
    use_masscan = scanner in ("auto", "masscan") and masscan_available()
    if use_masscan:
        # Scan the same short router-port list as nmap (fast). No all-ports sweep.
        mports, merr = await masscan_ports(target, ROUTER_PORTS, str(cfg.masscan_rate))
        if mports:
            open_ports = mports
            # Enrich with nmap -sV on just the open ports (best-effort).
            enriched = await _run_and_parse(
                target, ["-p", ",".join(str(p) for p in mports)])
            if enriched is not None and enriched[4]:
                port_findings, products, services, os_info, open_ports = enriched
            else:
                port_findings = [_bare_port_finding(p) for p in mports]
        else:
            # masscan found nothing (or couldn't run) — fall back to the nmap path.
            if merr:
                log.info("masscan unusable (%s) — falling back to nmap", merr)
            use_masscan = False

    # --- 2. nmap path (default / fallback) -----------------------------------
    if not open_ports and not use_masscan:
        parsed = await _run_and_parse(target, ["-p", ROUTER_PORTS])
        if parsed is None:
            return [Finding("nmap", Severity.INFO, "no port scanner available",
                            {"error": "neither masscan nor nmap produced output"})]
        port_findings, products, services, os_info, open_ports = parsed
        if not open_ports:
            wider = await _run_and_parse(target, ["--top-ports", "1000"])
            if wider is not None and wider[4]:
                port_findings, products, services, os_info, open_ports = wider

    # Active banner enrichment (HTTP Server/title, SSH/Telnet) to sharpen the
    # model/firmware fingerprint. Best-effort and proxied if configured.
    banners: dict = {}
    if open_ports:
        try:
            banners = await asyncio.to_thread(
                grab_banners, target, open_ports, get_config().proxy)
        except Exception:  # noqa: BLE001
            banners = {}

    # Vendor hints from characteristic open ports (works even when -sV is
    # blocked and there are no service banners — e.g. MikroTik Winbox 8291).
    hints = _port_hints(open_ports)
    blob = _blob(products, services, os_info, banners, hints)

    fp = _fingerprint_finding(products, services, os_info, banners, hints)
    findings: list[Finding] = list(port_findings)
    findings.append(fp)
    # Version-aware CVE hits from the curated KB against the whole fingerprint.
    findings.extend(match_fingerprint(blob))

    # Share what we learned with later stages (routersploit reads the vendor).
    if ctx is not None:
        ctx["verdict"] = fp.detail.get("verdict")
        ctx["vendor"] = detect_vendor(blob)
        ctx["model"] = fp.detail.get("label", "")
        ctx["open_ports"] = open_ports
        ctx["fingerprint_blob"] = blob

    if not findings:
        findings.append(Finding("nmap", Severity.INFO, "no open ports found", {}))
    return findings


# Characteristic ports that strongly imply a vendor/platform even with no banner.
PORT_VENDOR_HINTS = {
    8291: "mikrotik routeros winbox",
    8728: "mikrotik routeros api",
    8729: "mikrotik routeros api-ssl",
    7547: "tr-069 cwmp cpe broadband",
    52869: "rompager upnp",   # Misfortune Cookie-era CPE
    49152: "upnp cpe",
}


def _port_hints(open_ports: list[int]) -> str:
    return " ".join(PORT_VENDOR_HINTS[p] for p in open_ports if p in PORT_VENDOR_HINTS)


# Canonical vendor -> aliases to look for in the fingerprint blob. The canonical
# key matches routersploit's exploit package name (routers.<vendor>).
VENDOR_ALIASES = {
    "mikrotik": ("mikrotik", "routeros", "routerboard", "rosssh", "winbox"),
    "dlink": ("d-link", "dlink", "dir-6", "dir-8", "dsl-"),
    "tplink": ("tp-link", "tplink", "archer", "tl-wr", "tl-wa"),
    "netgear": ("netgear",),
    "asus": ("asuswrt", "asus router", "asus"),
    "huawei": ("huawei", "hg8", "hg53", "echolife"),
    "zyxel": ("zyxel",),
    "linksys": ("linksys",),
    "cisco": ("cisco ios", "cisco"),
    "ubiquiti": ("ubiquiti", "edgeos", "edgerouter", "airos"),
    "juniper": ("juniper",),
    "fortinet": ("fortinet", "fortigate"),
    "tenda": ("tenda",),
    "comtrend": ("comtrend",),
    "billion": ("billion",),
    "technicolor": ("technicolor", "thomson"),
    "draytek": ("draytek", "vigor"),
}


def detect_vendor(blob: str) -> str | None:
    """Return a canonical vendor key from the fingerprint blob, or None."""
    low = blob.lower()
    for vendor, aliases in VENDOR_ALIASES.items():
        if any(a in low for a in aliases):
            return vendor
    return None


def _bare_port_finding(port: int) -> Finding:
    """Port finding from masscan alone (no nmap service detection available)."""
    return Finding(
        stage="nmap", severity=Severity.INFO, title=f"{port}/tcp open",
        detail={"port": str(port), "protocol": "tcp", "service": "unknown",
                "product": "", "version": ""})


def _needs_privileges(stderr: str) -> bool:
    return "requires root privileges" in stderr.lower() or "requires r" in stderr.lower()


async def _run_and_parse(target: str, port_args: list[str]):
    """Run nmap (-sV -O, falling back to -sV) for the given ports and parse XML.

    Returns the parsed tuple, or None if nmap is missing / produced no usable
    output.
    """
    fast = get_config().nmap_fast
    base = ["-sV", "-Pn", "-T4", "--host-timeout", NMAP_HOST_TIMEOUT,
            *port_args, "-oX", "-", target]
    if fast:
        # Light version detection (fewer probes) — much faster on routers.
        base = ["--version-light", *base]

    # Fast mode skips slow OS detection entirely (we fingerprint via
    # ports/banners/SNMP anyway); full mode adds -O with a no-privilege fallback.
    first = ["nmap", *base] if fast else ["nmap", "-O", *base]
    try:
        _, stdout, stderr = await run_cmd(first, timeout=NMAP_TIMEOUT)
    except ToolNotFound:
        return None

    # -O needs raw sockets; without privileges nmap quits before scanning.
    if not fast and (_needs_privileges(stderr) or not stdout.strip()):
        try:
            _, stdout, stderr = await run_cmd(["nmap", *base], timeout=NMAP_TIMEOUT)
        except ToolNotFound:
            return None

    if not stdout.strip():
        return None
    try:
        return _parse_nmap_xml(stdout)
    except ET.ParseError:
        return None


def _parse_nmap_xml(xml_text: str):
    """Parse nmap XML.

    Returns ``(port_findings, products, services, os_info, open_ports)``.
    """
    port_findings: list[Finding] = []
    products: list[str] = []
    services: list[str] = []
    open_ports: list[int] = []
    os_info: dict = {}
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
                try:
                    open_ports.append(int(portid))
                except ValueError:
                    pass

                label = f"{portid}/{proto} open: {service}"
                if product:
                    label += f" ({product} {version})".rstrip()
                port_findings.append(Finding(
                    stage="nmap", severity=Severity.INFO, title=label,
                    detail={"port": portid, "protocol": proto, "service": service,
                            "product": product, "version": version},
                ))

        parsed = _parse_os(host)
        if parsed:
            os_info = parsed

    return port_findings, products, services, os_info, open_ports


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


def _blob(products: list[str], services: list[str], os_info: dict, banners: dict,
          hints: str = "") -> str:
    """Combined lowercase fingerprint text used for classification + CVE match."""
    return " ".join(products + services + [
        os_info.get("vendor", ""), os_info.get("osfamily", ""),
        os_info.get("os_name", ""),
        banners.get("http_server", ""), banners.get("http_title", ""),
        banners.get("ssh_banner", ""), banners.get("telnet_banner", ""),
        hints,
    ]).lower()


def _firmware(os_info: dict, banners: dict) -> str:
    """Best-effort firmware/version string for display (from banners or OS)."""
    return (banners.get("http_server") or banners.get("ssh_banner")
            or os_info.get("os_name") or "")


def _fingerprint_finding(products: list[str], services: list[str], os_info: dict,
                         banners: dict, hints: str = "") -> Finding:
    verdict, label, confidence = _classify(products, services, os_info, banners, hints)
    icon = {"router": "🧭", "not_router": "🚫", "unknown": "❔"}[verdict]
    return Finding(
        stage="fingerprint",
        severity=Severity.INFO,
        title=f"{icon} Тип устройства: {label}",
        detail={
            "verdict": verdict,
            "label": label,
            "confidence": confidence,
            "device_type": os_info.get("device_type", ""),
            "vendor": os_info.get("vendor", ""),
            "osfamily": os_info.get("osfamily", ""),
            "os_name": os_info.get("os_name", ""),
            "accuracy": os_info.get("accuracy", 0),
            "firmware": _firmware(os_info, banners),
            "http_server": banners.get("http_server", ""),
            "http_title": banners.get("http_title", ""),
            "ssh_banner": banners.get("ssh_banner", ""),
            "telnet_banner": banners.get("telnet_banner", ""),
        },
    )


def _classify(products: list[str], services: list[str], os_info: dict,
              banners: dict, hints: str = "") -> tuple[str, str, str]:
    """Return (verdict, human_label, confidence).

    verdict ∈ {"router", "not_router", "unknown"}.
    """
    blob = _blob(products, services, os_info, banners, hints)
    # Prefer a concrete name from banners (model/title) over the nmap OS guess.
    best_name = (banners.get("http_title") or os_info.get("os_name")
                 or banners.get("http_server") or os_info.get("vendor"))

    # 1) Strong signal: known router vendor/product in banners or OS name.
    matched_kw = next((kw for kw in ROUTER_KEYWORDS if kw in blob), None)
    if matched_kw:
        name = best_name or matched_kw
        return "router", f"роутер ({name})", "высокая"

    # 2) nmap device type.
    dtype = os_info.get("device_type", "")
    acc = os_info.get("accuracy", 0)
    if dtype:
        name = best_name or dtype
        if dtype in ROUTER_TYPES:
            return "router", f"роутер ({name}, {acc}%)", "средняя"
        if dtype in NON_ROUTER_TYPES:
            return "not_router", f"не роутер ({name}, {acc}%)", "средняя"
        return "unknown", f"неопределённо ({name}, {acc}%)", "низкая"

    # 3) Banner-only signal (no OS data) — at least show what we saw.
    if best_name:
        return "unknown", f"неопределённо ({best_name})", "низкая"
    return "unknown", "не удалось определить", "нет данных"


def router_verdict(findings: list[Finding]) -> tuple[str, str]:
    """Pull (verdict, label) out of the fingerprint finding; default unknown."""
    for f in findings:
        if f.stage == "fingerprint":
            return f.detail.get("verdict", "unknown"), f.detail.get("label", "")
    return "unknown", ""
