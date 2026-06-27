"""hydra stage — robust default/weak credential checks via THC-Hydra.

Scoped to SSH / Telnet / FTP, where hydra is reliable. HTTP logins are handled
elsewhere (the built-in HTTP-Basic check in the routersploit stage, and nuclei's
default-login templates for form logins) — hydra's http-get success/failure
detection is unreliable on router web UIs, so it's intentionally not used here.

Uses a small curated default-credential combo list (few attempts, ``-f`` stops on
first hit) to stay fast and avoid tripping router lockouts. Set the bot's creds
mode to "+bruteforce" to allow a larger wordlist via ``HYDRA_PASS_LIST``.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import socket
import tempfile

from ..models import Finding, Severity
from ..runtime import get_config
from ._common import run_cmd

# Per-service wall-clock budget.
HYDRA_TIMEOUT = 45.0
# TCP services hydra checks directly (HTTP handled by the built-in Basic check
# and nuclei — hydra's http login detection is unreliable on router UIs).
LOGIN_SERVICES = {22: "ssh", 23: "telnet", 21: "ftp"}
PROBE_TIMEOUT = 1.2

# Curated factory/weak credentials (login:password). Small on purpose.
DEFAULT_COMBOS = [
    "admin:admin", "admin:password", "admin:", "admin:1234", "admin:12345",
    "admin:admin123", "admin:pass", "root:root", "root:admin", "root:",
    "user:user", "support:support", "admin:router", "telecomadmin:admintelecom",
    "ubnt:ubnt", "cisco:cisco",
]

_RESULT_RE = re.compile(
    r"\[\d+\]\[(\w[\w-]*)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S*)")


async def hydra_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    """Brute the open login services with a small default-cred list."""
    if shutil.which("hydra") is None:
        return [Finding("hydra", Severity.INFO, "hydra not installed",
                        {"error": "hydra (thc-hydra) not found on PATH"})]

    open_ports = set((ctx or {}).get("open_ports") or [])
    if not open_ports:
        open_ports = await asyncio.to_thread(_probe, target, list(LOGIN_SERVICES))

    services = [(p, s) for p, s in LOGIN_SERVICES.items() if p in open_ports]
    if not services:
        return [Finding("hydra", Severity.INFO,
                        "hydra: SSH/Telnet/FTP не открыты — пропускаю", {})]

    ip = await asyncio.to_thread(_resolve, target)
    combo_path = _write_combo()
    findings: list[Finding] = []
    try:
        for port, svc in services:
            findings += await _hydra(ip, port, f"{svc}://{ip}:{port}", combo_path)
    finally:
        with _suppress():
            os.unlink(combo_path)

    if not any(f.severity == Severity.HIGH for f in findings):
        findings.append(Finding("hydra", Severity.INFO,
                                "hydra: слабых учётных данных не найдено", {}))
    return findings


async def _hydra(ip: str, port: int, service_url: str, combo_path: str) -> list[Finding]:
    cmd = ["hydra", "-C", combo_path, "-f", "-t", "4", "-w", "5", "-I", service_url]
    try:
        _, stdout, _ = await run_cmd(cmd, timeout=HYDRA_TIMEOUT)
    except asyncio.TimeoutError:
        return [Finding("hydra", Severity.INFO,
                        f"hydra: таймаут на {service_url}", {"service_url": service_url})]
    except Exception as exc:  # noqa: BLE001
        return [Finding("hydra", Severity.INFO, f"hydra: ошибка на {service_url}",
                        {"service_url": service_url, "error": str(exc)})]

    findings: list[Finding] = []
    for m in _RESULT_RE.finditer(stdout):
        svc, host, login, password = m.group(1), m.group(2), m.group(3), m.group(4)
        cred = f"{login}:{password}"
        findings.append(Finding(
            "hydra", Severity.HIGH,
            f"default/weak creds {cred} ({svc} порт {port})",
            {"service": svc, "port": port, "host": host, "credentials": cred}))
    return findings


def _write_combo() -> str:
    cfg = get_config()
    combos = list(DEFAULT_COMBOS)
    # In bruteforce mode, append an external password list if configured.
    extra = getattr(cfg, "hydra_pass_list", "")
    if not cfg.rsf_default_only and extra and os.path.isfile(extra):
        try:
            with open(extra, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    pw = line.strip()
                    if pw:
                        combos.append(f"admin:{pw}")
                        combos.append(f"root:{pw}")
        except OSError:
            pass
    fd, path = tempfile.mkstemp(prefix="hydra_combo_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(combos) + "\n")
    return path


def _probe(target: str, ports: list[int]) -> set[int]:
    ip = _resolve(target)
    found: set[int] = set()
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=PROBE_TIMEOUT):
                found.add(port)
        except OSError:
            continue
    return found


def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, Exception)
