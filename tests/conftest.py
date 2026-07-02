"""Shared pytest fixtures/helpers for the cve_detect + engine tests.

No pytest-asyncio dependency: async coroutines are driven with ``run()``
(asyncio.run) from ordinary sync tests.
"""
from __future__ import annotations

import asyncio

from cve_detect.base import DeviceInfo
from cve_detect.http import Response, SafeHTTP


def run(coro):
    """Drive a coroutine to completion in a fresh event loop."""
    return asyncio.run(coro)


class FakeHTTP(SafeHTTP):
    """SafeHTTP with the real scope/safe logic but a mocked network boundary.

    Records every ``_fetch`` (real-network) call so tests can assert request
    counts/types, and returns scripted responses keyed by URL substring.
    """

    def __init__(self, scope_allows=lambda _h: True, *, safe: bool = True,
                 responses: dict[str, Response] | None = None) -> None:
        super().__init__(scope_allows, safe=safe, min_interval=0.0)
        self._responses = responses or {}
        self.calls: list[tuple[str, str]] = []   # (method, url) actually fetched

    async def _fetch(self, method: str, url: str, headers: dict) -> Response:
        self.calls.append((method, url))
        # Prefer a suffix match ("/favicon.ico", "?images/"); else substring.
        # Longest key wins so specific paths beat "/".
        matches = [k for k in self._responses if url.endswith(k)]
        if not matches:
            matches = [k for k in self._responses if k in url]
        if matches:
            return self._responses[max(matches, key=len)]
        return Response(200, {}, "", url)


def make_device(**kw) -> DeviceInfo:
    base = dict(ip="192.0.2.10", vendor=None, model=None, firmware=None,
                open_ports=[80], http_signatures={}, raw_banners={})
    base.update(kw)
    return DeviceInfo(**base)
