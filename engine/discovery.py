"""Host discovery (liveness sweep) over a CIDR subnet.

Uses ``nmap -sn`` (ping scan: ICMP / ARP on a local net / TCP probes) to find
which hosts are up, so the orchestrator only spends time scanning live hosts.
"""
from __future__ import annotations

import ipaddress
import logging
from xml.etree import ElementTree as ET

from .stages._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

DISCOVERY_TIMEOUT = 600.0
# Refuse to sweep absurdly large ranges (a /20 is already 4094 hosts).
MAX_SUBNET_HOSTS = 4096


def subnet_host_count(cidr: str) -> int | None:
    """Usable host count of a CIDR, or None if it isn't a valid network."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if net.num_addresses <= 2:
        return net.num_addresses
    return net.num_addresses - 2  # drop network + broadcast for IPv4


async def discover_hosts(cidr: str) -> tuple[list[str], int, str | None]:
    """Ping-sweep ``cidr``.

    Returns ``(live_hosts, total_hosts, error)``. ``error`` is a human message
    when the sweep can't run (bad CIDR / too large / nmap missing), else None.
    """
    total = subnet_host_count(cidr)
    if total is None:
        return [], 0, "некорректная подсеть"
    if total > MAX_SUBNET_HOSTS:
        return [], total, (f"слишком большая подсеть ({total} хостов, лимит "
                           f"{MAX_SUBNET_HOSTS})")

    cmd = ["nmap", "-sn", "-n", "-T4", "--max-retries", "1", "-oX", "-", cidr]
    try:
        _, stdout, _ = await run_cmd(cmd, timeout=DISCOVERY_TIMEOUT)
    except ToolNotFound:
        return [], total, "nmap не установлен"
    except Exception as exc:  # noqa: BLE001
        log.warning("discovery failed for %s: %s", cidr, exc)
        return [], total, f"ошибка discovery: {exc}"

    live = _parse_live_hosts(stdout)
    return live, total, None


def _parse_live_hosts(xml_text: str) -> list[str]:
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    live: list[str] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in host.findall("address")
                     if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if addr:
            live.append(addr)
    return live
