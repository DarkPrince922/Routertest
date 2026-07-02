"""Scope-gate is mandatory: an out-of-scope host must produce ZERO network I/O.

Covers both the module's SafeHTTP transport and the engine ScopeGate.
"""
from __future__ import annotations

import ipaddress

import pytest

from conftest import FakeHTTP, make_device, run
from cve_detect.http import ScopeDenied
from cve_detect.detectors.gpon_cve_2018_10561 import GponAuthBypass


def test_safehttp_denies_before_any_fetch():
    http = FakeHTTP(scope_allows=lambda _h: False)
    with pytest.raises(ScopeDenied):
        run(http.get("http://192.0.2.10/"))
    assert http.calls == []          # no real network call
    assert http.request_count == 0


def test_detector_makes_no_network_call_when_out_of_scope():
    # A detector swallows the ScopeDenied in its probe and falls back to
    # fingerprint-only — but must not have hit the network at all.
    http = FakeHTTP(scope_allows=lambda _h: False)
    device = make_device(model="gpon home gateway", open_ports=[80],
                         http_signatures={"title": "GPON"})
    findings = run(GponAuthBypass().check(device, http, active=False))
    assert http.calls == []          # zero requests despite the detector running
    assert findings                  # still returns a fingerprint-based verdict


def test_safehttp_allows_when_in_scope():
    http = FakeHTTP(scope_allows=lambda _h: True)
    resp = run(http.get("http://192.0.2.10/"))
    assert resp.status == 200
    assert http.calls == [("GET", "http://192.0.2.10/")]


# ---- engine ScopeGate ------------------------------------------------------
def _gate(allow_all=False, cidrs=("192.168.1.0/24",), hosts=("myrouter.local",)):
    from engine.scope import ScopeConfig, ScopeGate
    from engine.store import Store
    cfg = ScopeConfig(
        engagement_id="test",
        allowed_cidrs=[ipaddress.ip_network(c) for c in cidrs],
        allowed_hosts=set(hosts), allow_all=allow_all)
    return ScopeGate(cfg, Store(":memory:"))


def test_engine_scope_allows_in_cidr():
    assert _gate().allows("192.168.1.50") is True


def test_engine_scope_rejects_outside_cidr():
    assert _gate().allows("10.0.0.1") is False


def test_engine_scope_allow_all_accepts_everything():
    assert _gate(allow_all=True).allows("8.8.8.8") is True


def test_engine_scope_dns_fail_rejects():
    # A name that won't resolve and isn't an allowed host → not allowed.
    assert _gate().allows("nonexistent.invalid") is False


def test_engine_scope_check_audits(tmp_path):
    from engine.scope import ScopeConfig, ScopeGate
    from engine.store import Store
    store = Store(str(tmp_path / "a.db"))
    gate = ScopeGate(ScopeConfig("e", [ipaddress.ip_network("192.168.1.0/24")],
                                 set(), False), store)
    decision = gate.check("10.0.0.9")
    assert decision.allowed is False
