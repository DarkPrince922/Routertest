"""Runtime configuration for the engine and its stages.

Kept separate from the bot's pydantic Settings so the engine stays Telegram-free
and self-contained. ``bot.main`` builds an :class:`EngineConfig` from the loaded
settings and calls :func:`configure` once at startup; stages read it via
:func:`get_config`.
"""
from __future__ import annotations

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
    # SNMP community strings to test (default/weak).
    snmp_communities: tuple[str, ...] = ("public", "private", "admin")


_config = EngineConfig()


def configure(config: EngineConfig) -> None:
    global _config
    _config = config


def get_config() -> EngineConfig:
    return _config


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
