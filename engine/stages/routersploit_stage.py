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


async def routersploit_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    """Credential checks (rsf FTP/SSH/Telnet + built-in HTTP Basic) and, when a
    vendor was detected upstream, vendor-specific routersploit exploit checks."""
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

    # --- vendor-specific exploit checks (the real routersploit power) ---------
    vendor = (ctx or {}).get("vendor")
    if vendor and _routersploit_available():
        web_port = next((p for p in (web or []) if p in WEB_HTTP_PORTS), 80)
        findings.extend(await _run_vendor_exploits(target, vendor, web_port))

    if not any(f.severity == Severity.HIGH for f in findings):
        findings.append(Finding("routersploit", Severity.INFO,
                                "no default/weak credentials or known exploits", {}))
    return findings


# ----------------------------------------------------- vendor exploit checks
# Cap and budget so a vendor with many modules can't run forever.
MAX_VENDOR_MODULES = 40
EXPLOIT_CHECK_TIMEOUT = 20.0


async def _run_vendor_exploits(target: str, vendor: str, port: int) -> list[Finding]:
    """Run check() on each routersploit exploit module for ``vendor`` and report
    the ones the target appears vulnerable to (check only — non-destructive)."""
    module_paths = await asyncio.to_thread(_list_vendor_modules, vendor)
    if not module_paths:
        return [Finding("routersploit", Severity.INFO,
                        f"routersploit: модулей для вендора '{vendor}' не найдено", {})]

    findings: list[Finding] = [Finding(
        "routersploit", Severity.INFO,
        f"routersploit: проверяю {len(module_paths)} эксплойт(ов) для {vendor}",
        {"vendor": vendor, "count": len(module_paths)})]

    for module_path in module_paths:
        try:
            vulnerable, info = await asyncio.wait_for(
                asyncio.to_thread(_check_exploit, module_path, target, port),
                timeout=EXPLOIT_CHECK_TIMEOUT)
        except asyncio.TimeoutError:
            continue
        except Exception:  # noqa: BLE001
            continue
        if vulnerable:
            name = info.get("name") or _short(module_path)
            findings.append(Finding(
                "routersploit", Severity.HIGH,
                f"🎯 Потенциально уязвим: {name} [{_short(module_path)}]",
                {"module": module_path, "vendor": vendor, **info}))
    return findings


def _list_vendor_modules(vendor: str) -> list[str]:
    """Enumerate routersploit exploit module paths for a vendor's router package."""
    import importlib
    import pkgutil

    pkg_name = f"routersploit.modules.exploits.routers.{vendor}"
    try:
        pkg = importlib.import_module(pkg_name)
    except ImportError:
        return []
    found: list[str] = []
    for _, name, is_pkg in pkgutil.walk_packages(pkg.__path__, pkg_name + "."):
        if not is_pkg:
            found.append(name)
        if len(found) >= MAX_VENDOR_MODULES:
            break
    return found


def _check_exploit(module_path: str, target: str, port: int) -> tuple[bool, dict]:
    """Import an exploit module, run its check() (non-destructive). Returns
    ``(vulnerable, info)``."""
    import importlib

    try:
        module = importlib.import_module(module_path)
    except Exception:  # noqa: BLE001
        return False, {}
    exploit_cls = getattr(module, "Exploit", None)
    if exploit_cls is None:
        return False, {}
    try:
        exploit = exploit_cls()
    except Exception:  # noqa: BLE001
        return False, {}

    _set_if_present(exploit, "target", _resolve(target))
    _set_if_present(exploit, "port", port)
    info = _exploit_info(exploit, module)
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            result = exploit.check()
        except Exception:  # noqa: BLE001
            return False, info
    return (result is True), info


def _exploit_info(exploit: object, module: object) -> dict:
    info: dict = {}
    name = getattr(exploit, "_name_", None) or getattr(module, "__name__", "")
    if name:
        info["name"] = str(name)
    refs = getattr(exploit, "_references_", None) or getattr(exploit, "references", None)
    if refs:
        info["references"] = [str(r) for r in list(refs)[:5]]
    cve = next((str(r) for r in (refs or []) if "CVE" in str(r).upper()), None)
    if cve:
        info["cve"] = cve
    return info


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
