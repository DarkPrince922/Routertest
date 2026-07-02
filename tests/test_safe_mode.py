"""Safe mode: no detector may send an active payload without --active."""
from __future__ import annotations

import pytest

from conftest import FakeHTTP, make_device, run
from cve_detect.http import Response, UnsafeRequest
from cve_detect.detectors.gpon_cve_2018_10561 import GponAuthBypass
from cve_detect.detectors.dlink_dir620_backdoor import DlinkDir620Backdoor


def test_active_get_blocked_in_safe_mode():
    http = FakeHTTP(safe=True)
    with pytest.raises(UnsafeRequest):
        run(http.active_get("http://192.0.2.10/?images/"))
    assert http.calls == []           # blocked before touching the network


def test_post_blocked_in_safe_mode():
    http = FakeHTTP(safe=True)
    with pytest.raises(UnsafeRequest):
        run(http._request("POST", "http://192.0.2.10/"))


def test_gpon_safe_mode_sends_no_bypass_probe():
    dev = make_device(model="gpon home gateway", open_ports=[80],
                      http_signatures={"title": "GPON"})
    http = FakeHTTP(safe=True, responses={"/": Response(200, {}, "GponForm", "")})
    run(GponAuthBypass().check(dev, http, active=False))
    # Only plain GETs, never the '?images/' auth-bypass marker.
    assert all("?images/" not in url for _m, url in http.calls)
    assert all(method == "GET" for method, _url in http.calls)


def test_gpon_active_mode_runs_bypass_probe():
    dev = make_device(model="gpon home gateway", open_ports=[80],
                      http_signatures={"title": "GPON"})
    # plain page blocked (302), marker page authorized (200) -> vulnerable
    http = FakeHTTP(safe=False, responses={
        "?images/": Response(200, {}, "authorized menu", ""),
        "/menu.html": Response(302, {}, "", ""),
        "/": Response(200, {}, "GponForm", ""),
    })
    findings = run(GponAuthBypass().check(dev, http, active=True))
    assert any("?images/" in url for _m, url in http.calls)
    assert findings[0].status == "vulnerable"


def test_dir620_single_cred_only_in_active():
    dev = make_device(model="DIR-620", vendor="d-link", open_ports=[80])
    safe_http = FakeHTTP(safe=True)
    run(DlinkDir620Backdoor().check(dev, safe_http, active=False))
    assert safe_http.calls == []      # no cred attempt in safe mode
