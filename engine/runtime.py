"""Runtime configuration for the engine and its stages.

Kept separate from the bot's pydantic Settings so the engine stays Telegram-free
and self-contained. ``bot.main`` builds an :class:`EngineConfig` from the loaded
settings and calls :func:`configure` once at startup; stages read it via
:func:`get_config`.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass(slots=True)
class EngineConfig:
    # Outbound proxy for HTTP-layer tooling (nuclei, banner grab). Examples:
    # "http://127.0.0.1:8080", "socks5://127.0.0.1:9050". nmap is NOT proxied
    # (run the service on a VPN/jump host for full tunneling).
    proxy: str | None = None
    # routersploit: run only *_default credential modules (few attempts, low
    # lockout risk) and skip the slower *_bruteforce ones.
    rsf_default_only: bool = True
    # When True, also skip the deep stages on targets whose device type could
    # NOT be determined (verdict "unknown"), not just confirmed non-routers.
    skip_unknown: bool = False
    # Port-discovery engine: "auto" (masscan if installed, else nmap),
    # "masscan", or "nmap". masscan is faster and bypasses connect-scan limits.
    port_scanner: str = "auto"
    # masscan packets-per-second. Higher = faster but more aggressive; cheap
    # routers may drop replies if it's too high.
    masscan_rate: int = 5000
    # Subnet liveness sweep: "auto" (masscan if installed, else nmap), "masscan"
    # (fast TCP sweep — also finds ICMP-blocking routers), or "nmap" (-sn ping).
    discovery_method: str = "auto"
    # masscan rate for the liveness sweep (many hosts at once → higher default).
    discovery_rate: int = 20000
    # nuclei template tag filter. Empty = run the full template set (most
    # thorough). Set e.g. "router,iot,cve,default-login,exposure" to speed it up.
    nuclei_tags: str = ""
    # nuclei template concurrency (-c). Higher = faster, more CPU/RAM.
    nuclei_concurrency: int = 50
    # Fast nmap: skip slow OS detection (-O) and use light version detection.
    # Device type still comes from ports/banners/SNMP. Set False for full -sV -O.
    nmap_fast: bool = True
    # Optional external password list for hydra in +bruteforce mode.
    hydra_pass_list: str = ""
    # Metasploit stage (heavy: msfconsole startup + RAM). Off by default.
    metasploit_enabled: bool = False
    # Max heavy tools (nuclei/routersploit) running at once, regardless of
    # MAX_CONCURRENT. Bounds RAM/CPU so high concurrency doesn't OOM the box.
    heavy_tool_limit: int = 2
    # Economy mode for weak hardware: serialize heavy tools (effective heavy
    # limit = 1), throttle nuclei concurrency and masscan rates, and process
    # batch subnets strictly one-at-a-time. Trades speed for a much lighter CPU.
    economy: bool = False
    # cve_detect active mode: allow the module's non-destructive ACTIVE probes
    # (GPON auth-bypass compare, single known-cred try, nuclei confirmation).
    # Off = safe mode (fingerprint + endpoint presence only). Off by default.
    cve_active: bool = False
    # vulners stage: nmap --script vulners (version→CVE via vulners.com). Needs
    # outbound internet. On by default; turn off if the box has no connectivity.
    vulners_enabled: bool = True
    # SNMP community strings to test (default/weak).
    snmp_communities: tuple[str, ...] = ("public", "private", "admin")


_config = EngineConfig()


def configure(config: EngineConfig) -> None:
    global _config
    _config = config


def get_config() -> EngineConfig:
    return _config


_heavy_sem: asyncio.Semaphore | None = None
_heavy_sem_size: int = 0


def effective_heavy_limit() -> int:
    """How many heavy tools may run at once — forced to 1 in economy mode."""
    if _config.economy:
        return 1
    return max(1, _config.heavy_tool_limit)


def heavy_semaphore() -> asyncio.Semaphore:
    """Process-wide limit on concurrent heavy tools (nuclei/routersploit).

    Lazily created inside the running event loop; sized from the effective heavy
    limit. Recreated when that size changes (e.g. economy mode toggled) so the new
    limit takes effect on subsequent acquisitions.
    """
    global _heavy_sem, _heavy_sem_size
    size = effective_heavy_limit()
    if _heavy_sem is None or _heavy_sem_size != size:
        _heavy_sem = asyncio.Semaphore(size)
        _heavy_sem_size = size
    return _heavy_sem


def effective_nuclei_concurrency() -> int:
    """nuclei ``-c`` value — capped low in economy mode to spare the CPU."""
    if _config.economy:
        return min(8, _config.nuclei_concurrency)
    return _config.nuclei_concurrency


def effective_masscan_rate() -> int:
    """Per-host port-scan masscan rate — throttled in economy mode."""
    if _config.economy:
        return min(1000, _config.masscan_rate)
    return _config.masscan_rate


def effective_discovery_rate() -> int:
    """Subnet-sweep masscan rate — throttled in economy mode."""
    if _config.economy:
        return min(2000, _config.discovery_rate)
    return _config.discovery_rate


_masscan_lock: asyncio.Lock | None = None


def masscan_lock() -> asyncio.Lock:
    """Process-wide lock serializing ALL masscan runs.

    masscan uses a raw socket and its own pcap capture of the interface; two
    masscan processes running at once on the same machine swallow each other's
    reply packets and stall. So every masscan invocation — the subnet discovery
    sweep and each per-host port scan — takes this lock, guaranteeing only one
    masscan runs at a time. Without it, a subnet scan with >1 worker deadlocks at
    the port-scanning stage (discovery masscan vs. per-host masscan)."""
    global _masscan_lock
    if _masscan_lock is None:
        _masscan_lock = asyncio.Lock()
    return _masscan_lock


def set_proxy(proxy: str | None) -> None:
    """Update the outbound proxy live (used by the in-bot settings screen)."""
    _config.proxy = proxy or None


def set_rsf_default_only(enabled: bool) -> None:
    _config.rsf_default_only = enabled


def set_skip_unknown(enabled: bool) -> None:
    _config.skip_unknown = enabled


def set_port_scanner(value: str) -> None:
    if value in ("auto", "masscan", "nmap"):
        _config.port_scanner = value


def set_discovery_method(value: str) -> None:
    if value in ("auto", "masscan", "nmap"):
        _config.discovery_method = value


def set_metasploit_enabled(enabled: bool) -> None:
    _config.metasploit_enabled = enabled


def set_economy(enabled: bool) -> None:
    """Toggle economy mode live. The heavy semaphore is resized lazily on the
    next :func:`heavy_semaphore` call."""
    _config.economy = enabled


def set_cve_active(enabled: bool) -> None:
    _config.cve_active = enabled


def set_vulners_enabled(enabled: bool) -> None:
    _config.vulners_enabled = enabled
