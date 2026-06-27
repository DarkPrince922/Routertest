"""Host discovery (liveness sweep) over a CIDR subnet.

Uses ``nmap -sn`` (ping scan: ICMP / ARP on a local net / TCP probes) to find
which hosts are up, so the orchestrator only spends time scanning live hosts.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import shutil
from collections.abc import Awaitable, Callable
from xml.etree import ElementTree as ET

from .portscan import masscan_available
from .runtime import get_config
from .stages._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

DISCOVERY_TIMEOUT = 3600.0
# Absolute safety ceiling — allows up to a /16 (65534 hosts). Bigger ranges
# (e.g. a /8 with millions of hosts) are refused to avoid an accidental footgun.
MAX_SUBNET_HOSTS = 65536
# Ports masscan probes to decide a host is "alive". A live router almost always
# answers on at least one of these (and TCP catches ICMP-blocking routers).
DISCOVERY_PORTS = "21,22,23,53,80,81,443,7547,8080,8081,8291,8443,8888,7676,37215"
_MASSCAN_OPEN_RE = re.compile(r"Discovered open port \d+/tcp on (\S+)", re.IGNORECASE)


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
    """Sweep ``cidr`` for live hosts, calling ``on_host(ip)`` per host as found.

    Method per config: masscan (fast TCP, also finds ICMP-blocking routers) or
    nmap -sn ping. Returns ``(total_hosts, error)``.
    """
    total = subnet_host_count(cidr)
    if total is None:
        return 0, "некорректная подсеть"
    if total > MAX_SUBNET_HOSTS:
        return total, (f"слишком большая подсеть ({total} хостов, лимит "
                       f"{MAX_SUBNET_HOSTS})")

    method = get_config().discovery_method
    use_masscan = method == "masscan" or (method == "auto" and masscan_available())
    if use_masscan:
        found, err = await _stream_masscan(cidr, total, on_host)
        # If masscan couldn't run (perms/missing) and found nothing, try nmap.
        if err and found == 0 and method == "auto":
            log.info("masscan discovery unusable (%s) — falling back to nmap -sn", err)
            return await _stream_nmap(cidr, total, on_host)
        return total, (None if found else err)
    return await _stream_nmap(cidr, total, on_host)


async def _stream_masscan(cidr: str, total: int, on_host: HostCallback
                          ) -> tuple[int, str | None]:
    """Fast TCP liveness sweep via masscan; dedups hosts as they stream in."""
    rate = str(get_config().discovery_rate)
    argv = ["masscan", cidr, "-p", DISCOVERY_PORTS, "--rate", rate, "--wait", "2"]
    if shutil.which("stdbuf"):
        argv = ["stdbuf", "-oL", *argv]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        return 0, "masscan не установлен"

    seen: set[str] = set()
    try:
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            m = _MASSCAN_OPEN_RE.search(raw.decode("utf-8", errors="replace"))
            if m:
                ip = m.group(1).strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    await on_host(ip)
        await proc.wait()
        err = None
        if not seen:
            stderr = (await proc.stderr.read()).decode("utf-8", errors="replace").lower()
            if any(k in stderr for k in ("permission", "denied", "fail", "must be")):
                err = "masscan не смог запуститься (нужен root/CAP_NET_RAW)"
        return len(seen), err
    except asyncio.CancelledError:
        with _suppress_proc_errors():
            proc.kill()
        raise
    except Exception as exc:  # noqa: BLE001
        with _suppress_proc_errors():
            proc.kill()
        return len(seen), f"ошибка discovery: {exc}"
    finally:
        if proc.returncode is None:
            with _suppress_proc_errors():
                proc.kill()


async def _stream_nmap(cidr: str, total: int, on_host: HostCallback
                       ) -> tuple[int, str | None]:
    """nmap -sn ping sweep (ICMP/ARP/TCP), tuned for speed."""
    argv = ["nmap", "-sn", "-n", "-T4", "--max-retries", "1",
            "--min-hostgroup", "128", cidr]
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
    found = 0
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
                    found += 1
                    await on_host(ip)
        await proc.wait()
        return total, None
    except asyncio.CancelledError:
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
