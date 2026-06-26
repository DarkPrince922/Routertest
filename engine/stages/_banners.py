"""Lightweight active banner grabbing to sharpen the device fingerprint.

Pure stdlib (urllib + sockets), run inside ``asyncio.to_thread`` from nmap_stage.
Best-effort: every probe is wrapped so a failure just yields no extra data.
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
import urllib.request

log = logging.getLogger(__name__)

HTTP_PORTS = {80, 8000, 8080, 8081, 8088, 8888, 81}
HTTPS_PORTS = {443, 8443, 4433, 8843}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HTTP_TIMEOUT = 4
_BANNER_TIMEOUT = 3


def grab_banners(target: str, open_ports: list[int], proxy: str | None = None) -> dict:
    """Collect HTTP Server/title and SSH/Telnet banners from open ports."""
    info: dict = {}
    ports = set(open_ports)

    http_port = next((p for p in (80, 8080, 8000, 8081, 8888, 81) if p in ports), None)
    https_port = next((p for p in (443, 8443, 4433) if p in ports), None)
    if http_port:
        _http_probe(f"http://{target}:{http_port}/", info, proxy)
    if https_port and "http_server" not in info:
        _http_probe(f"https://{target}:{https_port}/", info, proxy)

    if 22 in ports:
        b = _line_banner(target, 22)
        if b:
            info["ssh_banner"] = b
    if 23 in ports:
        b = _line_banner(target, 23, send_newline=True)
        if b:
            info["telnet_banner"] = b
    return info


def _http_probe(url: str, info: dict, proxy: str | None) -> None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # routers use self-signed certs

        handlers: list = [urllib.request.HTTPSHandler(context=ctx)]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=_HTTP_TIMEOUT) as resp:
            server = resp.headers.get("Server")
            if server:
                info["http_server"] = server
            body = resp.read(20000).decode("utf-8", errors="replace")
        m = _TITLE_RE.search(body)
        if m:
            info["http_title"] = " ".join(m.group(1).split())[:120]
    except Exception as exc:  # noqa: BLE001 - banner grab is best-effort
        log.debug("http probe failed for %s: %s", url, exc)


def _line_banner(target: str, port: int, send_newline: bool = False) -> str | None:
    try:
        with socket.create_connection((target, port), timeout=_BANNER_TIMEOUT) as sock:
            sock.settimeout(_BANNER_TIMEOUT)
            if send_newline:
                try:
                    sock.sendall(b"\r\n")
                except OSError:
                    pass
            data = sock.recv(256)
        text = data.decode("utf-8", errors="replace").strip()
        return text[:160] or None
    except OSError as exc:
        log.debug("banner grab failed %s:%d: %s", target, port, exc)
        return None
