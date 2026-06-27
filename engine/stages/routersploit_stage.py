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
import base64
import contextlib
import io
import logging
import socket
import ssl
import urllib.request

from ..models import Finding, Severity
from ..runtime import get_config

log = logging.getLogger(__name__)

# Per-module wall-clock budget (seconds).
MODULE_TIMEOUT = 120.0
# rsf creds modules for non-HTTP services (HTTP is handled by our own reliable
# Basic-auth check below, which also works in default-only mode).
PORT_PROBES: dict[int, list[str]] = {
    21: ["routersploit.modules.creds.generic.ftp_default",
         "routersploit.modules.creds.generic.ftp_bruteforce"],
    22: ["routersploit.modules.creds.generic.ssh_default",
         "routersploit.modules.creds.generic.ssh_bruteforce"],
    23: ["routersploit.modules.creds.generic.telnet_default",
         "routersploit.modules.creds.generic.telnet_bruteforce"],
}
WEB_HTTP_PORTS = [80, 8080, 8000, 8081, 8888, 81, 8090, 7547]
WEB_HTTPS_PORTS = [443, 8443, 4433, 8843]
PROBE_CONNECT_TIMEOUT = 1.5
HTTP_TIMEOUT = 4

# Curated factory/weak credentials tried against HTTP Basic auth (few attempts,
# stops on first hit — low lockout risk, runs even in default-only mode).
DEFAULT_HTTP_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "1234"),
    ("admin", "12345"), ("admin", "admin123"), ("admin", "pass"), ("root", "root"),
    ("root", "admin"), ("root", ""), ("user", "user"), ("support", "support"),
    ("admin", "router"), ("telecomadmin", "admintelecom"),
]


async def routersploit_stage(target: str) -> list[Finding]:
    """Check default/weak credentials: rsf for FTP/SSH/Telnet, a built-in
    Basic-auth check for the web UI on whatever ports are open."""
    findings: list[Finding] = []
    default_only = get_config().rsf_default_only

    # --- non-HTTP services via routersploit -----------------------------------
    if _routersploit_available():
        open_ports = await asyncio.to_thread(_probe_ports, target, list(PORT_PROBES))
        for port in open_ports:
            modules = PORT_PROBES[port]
            if default_only:
                modules = [m for m in modules if "bruteforce" not in m]
            for module_path in modules:
                try:
                    creds, raw = await asyncio.wait_for(
                        asyncio.to_thread(_run_module, module_path, target, port),
                        timeout=MODULE_TIMEOUT)
                except asyncio.TimeoutError:
                    findings.append(Finding("routersploit", Severity.INFO,
                        f"module timed out: {_short(module_path)} (port {port})",
                        {"module": module_path, "port": port}))
                    continue
                except Exception as exc:  # noqa: BLE001
                    findings.append(Finding("routersploit", Severity.INFO,
                        f"module error: {_short(module_path)} (port {port})",
                        {"module": module_path, "port": port, "error": str(exc)}))
                    continue
                for cred in creds:
                    findings.append(Finding("routersploit", Severity.HIGH,
                        f"default/weak creds {cred} (port {port})",
                        {"module": module_path, "port": port, "credentials": cred}))
    else:
        findings.append(Finding("routersploit", Severity.INFO,
                                "routersploit not installed (FTP/SSH/Telnet creds skipped)",
                                {"error": "routersploit package not importable"}))

    # --- HTTP Basic-auth default creds (built-in, reliable) -------------------
    web = await asyncio.to_thread(_probe_ports, target, WEB_HTTP_PORTS + WEB_HTTPS_PORTS)
    for port in web:
        https = port in WEB_HTTPS_PORTS
        try:
            cred = await asyncio.wait_for(
                asyncio.to_thread(_http_basic_creds, target, port, https),
                timeout=MODULE_TIMEOUT)
        except asyncio.TimeoutError:
            continue
        if cred:
            findings.append(Finding("routersploit", Severity.HIGH,
                f"default/weak creds {cred} (HTTP {'https' if https else 'http'} порт {port})",
                {"service": "http-basic", "port": port, "credentials": cred}))

    if not any(f.severity == Severity.HIGH for f in findings):
        findings.append(Finding("routersploit", Severity.INFO,
                                "no default/weak credentials found", {}))
    return findings


# ------------------------------------------------------------- HTTP basic auth
def _http_basic_creds(target: str, port: int, https: bool) -> str | None:
    """Try default creds against HTTP Basic auth; return 'user:pass' on success.

    Only engages when the endpoint actually challenges with 401 (Basic), so it
    won't false-positive on form-login pages (those are covered by nuclei).
    """
    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    base = _http_status(url, None, ctx)
    if base != 401:
        return None  # not Basic-auth protected
    for user, pwd in DEFAULT_HTTP_CREDS:
        code = _http_status(url, (user, pwd), ctx)
        if code is not None and code not in (401, 403, None) and code < 400:
            return f"{user}:{pwd}"
    return None


def _http_status(url: str, creds: tuple[str, str] | None, ctx) -> int | None:
    req = urllib.request.Request(url)
    if creds is not None:
        token = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:  # noqa: BLE001
        return None


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
