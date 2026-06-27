"""masscan-based fast port discovery (optional).

masscan sends raw SYN packets with its own TCP/IP stack, which is much faster
than nmap and can get through environments that restrict connect()-style scans.
It needs raw-socket privileges (CAP_NET_RAW, granted to the service) and only
finds open ports — service/version detection is left to a follow-up nmap -sV on
just those ports. Degrades gracefully when masscan isn't available/permitted.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import socket

log = logging.getLogger(__name__)

MASSCAN_TIMEOUT = 180.0
DEFAULT_RATE = "5000"
# Seconds masscan waits for late replies after sending (default is 10 — too long
# for a short port list on a local target).
MASSCAN_WAIT = "2"
# masscan prints "Discovered open port 80/tcp on 192.168.1.1" to stdout per hit.
_OPEN_RE = re.compile(r"Discovered open port (\d+)/tcp", re.IGNORECASE)


def masscan_available() -> bool:
    return shutil.which("masscan") is not None


def resolve_ip(target: str) -> str | None:
    """masscan needs an IP literal, not a hostname."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


async def masscan_ports(target: str, ports_csv: str, rate: str = DEFAULT_RATE
                        ) -> tuple[list[int], str | None]:
    """Return ``(open_ports, error)`` for ``target`` over ``ports_csv``."""
    ip = resolve_ip(target)
    if ip is None:
        return [], "не удалось отрезолвить хост для masscan"

    # Lazy import avoids a circular import (stages -> nmap_stage -> portscan).
    from .stages._common import ToolNotFound, run_cmd

    cmd = ["masscan", ip, "-p", ports_csv, "--rate", rate, "--wait", MASSCAN_WAIT]
    try:
        rc, stdout, stderr = await run_cmd(cmd, timeout=MASSCAN_TIMEOUT)
    except ToolNotFound:
        return [], "masscan не установлен"

    ports = sorted({int(m.group(1)) for m in _OPEN_RE.finditer(stdout)})
    if ports:
        return ports, None

    # No ports — distinguish "nothing open" from "couldn't run" (perm/iface).
    low = stderr.lower()
    if "permission" in low or "denied" in low or "failed" in low or "must be" in low:
        return [], (stderr.strip().splitlines()[-1] if stderr.strip() else
                    "masscan не смог запуститься (нужен root/CAP_NET_RAW)")
    return [], None
