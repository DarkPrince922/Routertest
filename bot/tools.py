"""Detect installed tool versions for the status screen."""
from __future__ import annotations

import asyncio
import importlib.util


async def _version(cmd: list[str]) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out_b, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
    except (FileNotFoundError, asyncio.TimeoutError):
        return "не установлен"
    out = out_b.decode("utf-8", errors="replace").strip()
    return out.splitlines()[0] if out else "?"


async def tool_versions() -> dict[str, str]:
    nmap, nuclei, masscan, hydra, snmp, msf = await asyncio.gather(
        _version(["nmap", "--version"]),
        _version(["nuclei", "-version"]),
        _version(["masscan", "--version"]),
        _version(["hydra", "-h"]),
        _version(["snmpget", "--version"]),
        _version(["msfconsole", "--version"]),
    )
    rsf = "установлен" if importlib.util.find_spec("routersploit") else "не установлен"
    return {
        "nmap": nmap.replace("Nmap version ", "").split(" (")[0] if nmap != "не установлен" else nmap,
        "nuclei": nuclei,
        "routersploit": rsf,
        "masscan": "✅" if masscan != "не установлен" else "❌",
        "hydra": "✅" if hydra != "не установлен" else "❌",
        "snmp": "✅" if snmp != "не установлен" else "❌",
        "metasploit": "✅" if msf != "не установлен" else "❌",
    }
