"""routersploit (rsf) stage — default/weak credential checks and scanners.

routersploit is synchronous, so each module is executed in a worker thread via
``asyncio.to_thread`` and wrapped in ``asyncio.wait_for`` to enforce a per-module
timeout (the abandoned thread is harmless; rsf modules are self-contained).

Because the stage signature is ``stage(target)`` only, we do a fast local TCP
probe of common router service ports and run the relevant credential modules for
the ports that are open. Any discovered credentials are reported as ``high``.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import socket

from ..models import Finding, Severity

log = logging.getLogger(__name__)

# Per-module wall-clock budget (seconds).
MODULE_TIMEOUT = 120.0
# Ports we probe and the rsf creds modules to try against each.
PORT_PROBES: dict[int, list[str]] = {
    21: ["routersploit.modules.creds.generic.ftp_default",
         "routersploit.modules.creds.generic.ftp_bruteforce"],
    22: ["routersploit.modules.creds.generic.ssh_default",
         "routersploit.modules.creds.generic.ssh_bruteforce"],
    23: ["routersploit.modules.creds.generic.telnet_default",
         "routersploit.modules.creds.generic.telnet_bruteforce"],
    80: ["routersploit.modules.creds.generic.http_basic_bruteforce",
         "routersploit.modules.creds.generic.http_form_bruteforce"],
    443: ["routersploit.modules.creds.generic.http_basic_bruteforce"],
    8080: ["routersploit.modules.creds.generic.http_basic_bruteforce",
           "routersploit.modules.creds.generic.http_form_bruteforce"],
}
PROBE_CONNECT_TIMEOUT = 1.5


async def routersploit_stage(target: str) -> list[Finding]:
    """Run rsf credential modules against open common ports on ``target``."""
    if not _routersploit_available():
        return [Finding("routersploit", Severity.INFO, "routersploit not installed",
                        {"error": "routersploit package not importable"})]

    open_ports = await asyncio.to_thread(_probe_ports, target, list(PORT_PROBES))
    if not open_ports:
        return [Finding("routersploit", Severity.INFO,
                        "no common router service ports open for rsf", {})]

    findings: list[Finding] = []
    for port in open_ports:
        for module_path in PORT_PROBES[port]:
            try:
                creds, raw = await asyncio.wait_for(
                    asyncio.to_thread(_run_module, module_path, target, port),
                    timeout=MODULE_TIMEOUT,
                )
            except asyncio.TimeoutError:
                findings.append(Finding(
                    "routersploit", Severity.INFO,
                    f"module timed out: {_short(module_path)} (port {port})",
                    {"module": module_path, "port": port},
                ))
                continue
            except Exception as exc:  # noqa: BLE001 - isolate per-module failures
                findings.append(Finding(
                    "routersploit", Severity.INFO,
                    f"module error: {_short(module_path)} (port {port})",
                    {"module": module_path, "port": port, "error": str(exc)},
                ))
                continue

            for cred in creds:
                findings.append(Finding(
                    "routersploit", Severity.HIGH,
                    f"default/weak creds {cred} (port {port})",
                    {"module": module_path, "port": port, "credentials": cred},
                ))
            if not creds:
                log.debug("rsf %s port %s: no creds (%s)", module_path, port, raw[:120])

    if not findings:
        findings.append(Finding("routersploit", Severity.INFO,
                                "no default/weak credentials found", {}))
    return findings


# --------------------------------------------------------------------------- helpers
def _routersploit_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("routersploit") is not None


def _short(module_path: str) -> str:
    return module_path.rsplit(".", 1)[-1]


def _probe_ports(target: str, ports: list[int]) -> list[int]:
    """Return the subset of ``ports`` that accept a TCP connection."""
    # Resolve once; rsf modules take the IP directly.
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = target
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=PROBE_CONNECT_TIMEOUT):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


def _run_module(module_path: str, target: str, port: int) -> tuple[list[str], str]:
    """Import, configure and run a single rsf module (blocking).

    Returns ``(credentials, captured_output)``. ``credentials`` is a list of
    ``"user:pass"`` strings extracted from the module after it runs.
    """
    import importlib

    try:
        module = importlib.import_module(module_path)
    except ImportError:
        return [], f"module not present: {module_path}"

    exploit_cls = getattr(module, "Exploit", None)
    if exploit_cls is None:
        return [], f"no Exploit in {module_path}"

    exploit = exploit_cls()
    # Configure common options defensively (attribute names are stable in rsf).
    _set_if_present(exploit, "target", _resolve(target))
    _set_if_present(exploit, "port", port)
    _set_if_present(exploit, "stop_on_success", True)
    _set_if_present(exploit, "verbosity", False)
    _set_if_present(exploit, "threads", 8)

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            exploit.run()
        except Exception as exc:  # noqa: BLE001
            return [], f"run() raised: {exc}"

    return _extract_credentials(exploit), buf.getvalue()


def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def _set_if_present(obj: object, attr: str, value: object) -> None:
    if hasattr(obj, attr):
        try:
            setattr(obj, attr, value)
        except Exception:  # noqa: BLE001 - option setters can validate
            pass


def _extract_credentials(exploit: object) -> list[str]:
    """Pull found credentials out of an rsf module after ``run()``.

    Across rsf versions creds land in ``credentials`` as a list of tuples/dicts;
    we normalize whatever is there to ``"user:pass"`` strings.
    """
    raw = getattr(exploit, "credentials", None)
    if not raw:
        return []
    out: list[str] = []
    for item in raw:
        out.append(_format_cred(item))
    return out


def _format_cred(item: object) -> str:
    if isinstance(item, dict):
        user = item.get("username") or item.get("user") or "?"
        pwd = item.get("password") or item.get("pass") or ""
        return f"{user}:{pwd}"
    if isinstance(item, (list, tuple)):
        # Common shapes: (target, port, user, pass) or (user, pass).
        parts = [str(p) for p in item]
        if len(parts) >= 2:
            return f"{parts[-2]}:{parts[-1]}"
        return ":".join(parts)
    return str(item)
