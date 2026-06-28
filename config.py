"""Application configuration loaded from the environment / .env file.

Uses pydantic-settings so values are validated and typed once, at startup.
"""
from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the orchestrator.

    Read from environment variables (and the local ``.env`` file). ``ADMIN_IDS``
    is parsed from a comma-separated string into a ``set[int]`` so membership
    checks in the admin-guard middleware are O(1).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    bot_token: str = "PUT_YOUR_TOKEN_HERE"
    # NoDecode disables pydantic-settings' default JSON decoding of complex types
    # so the comma-separated env value reaches the validator below as a raw str.
    admin_ids: Annotated[set[int], NoDecode] = set()
    max_concurrent: int = 2
    db_path: Path = Path("./scans.db")
    log_level: str = "INFO"
    scope_path: Path = Path("./scope.yaml")
    # HTTP-layer proxy for nuclei + banner grabbing (nmap is not proxied).
    scan_proxy: str = ""
    # routersploit: only run *_default credential modules (skip *_bruteforce).
    rsf_default_only: bool = True
    # Also skip deep stages when the device type can't be determined (unknown).
    skip_unknown: bool = False
    # Port-discovery engine: auto | masscan | nmap.
    port_scanner: str = "auto"
    # masscan packets-per-second (higher = faster, more aggressive).
    masscan_rate: int = 5000
    # Subnet liveness sweep: auto | masscan | nmap.
    discovery_method: str = "auto"
    # masscan rate for the liveness sweep (many hosts → higher default).
    discovery_rate: int = 20000
    # nuclei tag filter; empty = full template set (most thorough).
    nuclei_tags: str = ""
    # nuclei template concurrency (-c); higher = faster, more CPU/RAM.
    nuclei_concurrency: int = 50
    # Fast nmap: skip -O and use light version detection.
    nmap_fast: bool = True
    # Optional external password list for hydra (+bruteforce mode).
    hydra_pass_list: str = ""
    # Enable the heavy Metasploit stage (off by default).
    metasploit_enabled: bool = False
    # Max heavy tools (nuclei/routersploit) running at once (bounds RAM/CPU).
    heavy_tool_limit: int = 2
    # Economy mode for weak hardware (throttles heavy tools, nuclei, masscan; runs
    # batch subnets one at a time). Toggle live in ⚙️ Настройки.
    economy: bool = False

    @field_validator("admin_ids", mode="before")
    @classmethod
    def _parse_admin_ids(cls, value: object) -> object:
        """Accept ``"1,2,3"`` (env style) as well as a real iterable."""
        if value is None or value == "":
            return set()
        if isinstance(value, str):
            return {int(part.strip()) for part in value.split(",") if part.strip()}
        return value

    @property
    def token_is_placeholder(self) -> bool:
        return self.bot_token.strip() in {"", "PUT_YOUR_TOKEN_HERE"}


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return a process-wide singleton ``Settings`` instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
