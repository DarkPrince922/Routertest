"""SafeHTTP — the only network boundary cve_detect is allowed to use.

Every request passes through here so the mandatory guarantees hold in one place:
  * **Scope gate** — the target host is checked BEFORE any socket is opened; an
    out-of-scope host raises :class:`ScopeDenied` and no packet is sent.
  * **Safe mode** — with ``safe=True`` (default) only GET/HEAD without a payload
    are allowed; any mutating/payload request raises :class:`UnsafeRequest`.
  * **Rate limit + timeout** per host, so weak SOHO devices aren't knocked over.
  * **Audit** — every attempt (method, url, decision, status) goes to the audit
    callback / logger.

``_fetch`` is the single low-level method that actually touches the network, so
tests subclass/patch it to assert request counts and types without real I/O.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 4.0
DEFAULT_MIN_INTERVAL = 0.3   # min seconds between requests to the same host
_MAX_BODY = 200_000
_UA = "cve-detect/1.0 (authorized-scan)"


class ScopeDenied(Exception):
    """Raised when a request targets a host outside the authorized scope."""


class UnsafeRequest(Exception):
    """Raised when a mutating/payload request is attempted in safe mode."""


@dataclass(slots=True)
class Response:
    status: int
    headers: dict
    text: str
    url: str


class SafeHTTP:
    def __init__(self, scope_allows: Callable[[str], bool], *, safe: bool = True,
                 timeout: float = DEFAULT_TIMEOUT, proxy: str | None = None,
                 min_interval: float = DEFAULT_MIN_INTERVAL,
                 audit: Callable[[dict], None] | None = None) -> None:
        self._scope_allows = scope_allows
        self.safe = safe
        self._timeout = timeout
        self._proxy = proxy
        self._min_interval = min_interval
        self._audit = audit or (lambda rec: log.info("cve_detect http %s", rec))
        self._last_hit: dict[str, float] = {}
        self.request_count = 0   # observable by tests

    # ------------------------------------------------------------------ public
    async def get(self, url: str, headers: dict | None = None) -> Response:
        return await self._request("GET", url, headers=headers)

    async def head(self, url: str, headers: dict | None = None) -> Response:
        return await self._request("HEAD", url, headers=headers)

    async def active_get(self, url: str, headers: dict | None = None) -> Response:
        """A GET used as a non-destructive *active* probe (e.g. auth-bypass path).

        Refused in safe mode — callers must have an explicit ``active`` mandate.
        """
        if self.safe:
            raise UnsafeRequest(f"active probe blocked in safe mode: {url}")
        return await self._request("GET", url, headers=headers, active=True)

    # ----------------------------------------------------------------- internal
    async def _request(self, method: str, url: str, *, headers: dict | None = None,
                       active: bool = False) -> Response:
        host = urlparse(url).hostname or url
        if self.safe and method not in ("GET", "HEAD"):
            self._audit({"method": method, "url": url, "decision": "BLOCKED_UNSAFE"})
            raise UnsafeRequest(f"{method} blocked in safe mode: {url}")

        # SCOPE GATE — before any network activity.
        if not self._scope_allows(host):
            self._audit({"method": method, "url": url, "host": host,
                         "decision": "SCOPE_DENIED"})
            raise ScopeDenied(host)

        await self._rate_wait(host)
        self.request_count += 1
        try:
            resp = await self._fetch(method, url, headers or {})
        except Exception as exc:  # noqa: BLE001
            self._audit({"method": method, "url": url, "host": host,
                         "decision": "ALLOWED", "active": active, "error": str(exc)})
            raise
        self._audit({"method": method, "url": url, "host": host,
                     "decision": "ALLOWED", "active": active, "status": resp.status})
        return resp

    async def _rate_wait(self, host: str) -> None:
        now = time.monotonic()
        last = self._last_hit.get(host, 0.0)
        delta = now - last
        if delta < self._min_interval:
            await asyncio.sleep(self._min_interval - delta)
        self._last_hit[host] = time.monotonic()

    async def _fetch(self, method: str, url: str, headers: dict) -> Response:
        """The single real-network method (patched out in tests)."""
        return await asyncio.to_thread(self._fetch_sync, method, url, headers)

    def _fetch_sync(self, method: str, url: str, headers: dict) -> Response:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # routers use self-signed certs
        handlers: list = [urllib.request.HTTPSHandler(context=ctx)]
        if self._proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": self._proxy, "https": self._proxy}))
        # Never auto-follow redirects (could bounce to an out-of-scope host).
        handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, method=method,
                                     headers={"User-Agent": _UA, **headers})
        try:
            with opener.open(req, timeout=self._timeout) as resp:
                body = b"" if method == "HEAD" else resp.read(_MAX_BODY)
                return Response(resp.status, dict(resp.headers),
                                body.decode("utf-8", errors="replace"), resp.geturl())
        except urllib.error.HTTPError as exc:
            body = b"" if method == "HEAD" else exc.read(_MAX_BODY)
            return Response(exc.code, dict(exc.headers or {}),
                            body.decode("utf-8", errors="replace"), url)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None  # surface the 3xx instead of following it
