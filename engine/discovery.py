"""Host discovery (liveness sweep) over a CIDR subnet.

Uses ``nmap -sn`` (ping scan: ICMP / ARP on a local net / TCP probes) to find
which hosts are up, so the orchestrator only spends time scanning live hosts.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
from collections.abc import Awaitable, Callable
from xml.etree import ElementTree as ET

from .stages._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

DISCOVERY_TIMEOUT = 3600.0
# Absolute safety ceiling — allows up to a /16 (65534 hosts). Bigger ranges
# (e.g. a /8 with millions of hosts) are refused to avoid an accidental footgun.
MAX_SUBNET_HOSTS = 65536


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


HostCallback = Callable[[str], Awaitable[None]]


async def discover_hosts_stream(cidr: str, on_host: HostCallback
                                ) -> tuple[int, str | None]:
    """Ping-sweep ``cidr``, calling ``on_host(ip)`` for each live host as it is
    found (so it can be queued immediately). Returns ``(total_hosts, error)``.
    """
    total = subnet_host_count(cidr)
    if total is None:
        return 0, "некорректная подсеть"
    if total > MAX_SUBNET_HOSTS:
        return total, (f"слишком большая подсеть ({total} хостов, лимит "
                       f"{MAX_SUBNET_HOSTS})")

    argv = ["nmap", "-sn", "-n", "-T4", "--max-retries", "1", cidr]
    # stdbuf forces line buffering so live hosts stream out as they're found
    # (nmap block-buffers stdout when piped, which would batch them to the end).
    if shutil.which("stdbuf"):
        argv = ["stdbuf", "-oL", *argv]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except FileNotFoundError:
        return total, "nmap не установлен"

    prefix = "Nmap scan report for "
    try:
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            # In `-sn -n`, every "scan report" line is a host that is UP.
            if line.startswith(prefix):
                ip = line[len(prefix):].strip().split(" ")[0]
                if ip:
                    await on_host(ip)
        await proc.wait()
    except asyncio.CancelledError:
        # Stop pressed — kill the sweep immediately.
        with _suppress_proc_errors():
            proc.kill()
        raise
    except Exception as exc:  # noqa: BLE001
        with _suppress_proc_errors():
            proc.kill()
        return total, f"ошибка discovery: {exc}"
    finally:
        if proc.returncode is None:
            with _suppress_proc_errors():
                proc.kill()
    return total, None


class _suppress_proc_errors:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, (ProcessLookupError, OSError))


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
