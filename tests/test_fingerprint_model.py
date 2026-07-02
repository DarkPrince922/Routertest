"""Independent model identification: murmur3/favicon + signature matching."""
from __future__ import annotations

import base64

import pytest

from conftest import FakeHTTP, make_device, run
from cve_detect.fingerprint import (
    enrich,
    favicon_hash,
    identify_model,
    murmur3_32,
)
from cve_detect.http import Response


# ---- MurmurHash3 correctness ----------------------------------------------
def test_murmur3_empty_is_zero():
    assert murmur3_32(b"", 0) == 0


def test_murmur3_deterministic():
    assert murmur3_32(b"favicon-bytes", 0) == murmur3_32(b"favicon-bytes", 0)


def test_murmur3_matches_reference_library_if_available():
    mmh3 = pytest.importorskip("mmh3")
    for s in [b"", b"a", b"abc", b"hello world", b"\x00\x01\x02\x03", b"DIR-620"]:
        # mmh3.hash returns a signed 32-bit int; convert ours the same way.
        ours = murmur3_32(s, 0)
        ours_signed = ours - 0x100000000 if ours & 0x80000000 else ours
        assert ours_signed == mmh3.hash(s, 0)


def test_favicon_hash_is_shodan_style():
    mmh3 = pytest.importorskip("mmh3")
    raw = b"\x89PNG fake favicon bytes"
    assert favicon_hash(raw) == mmh3.hash(base64.encodebytes(raw))


# ---- signature-based identification ---------------------------------------
def test_identify_dir620_by_body_when_title_generic():
    # Device advertises nothing useful; only the page body reveals the model.
    dev = make_device(vendor="dlink", model="роутер (Router)", open_ports=[80],
                      raw_banners={"http_title": "Router"})
    http = FakeHTTP(responses={
        "/favicon.ico": Response(404, {}, "", ""),
        "/": Response(200, {"Server": "mathopd/1.5"},
                      "<title>Router</title> ... model DIR-620 ...", ""),
    })
    match = run(identify_model(dev, http))
    assert match is not None
    assert match.model == "DIR-620"


def test_enrich_writes_model_into_device():
    dev = make_device(vendor="tplink", model="роутер (?)", open_ports=[80],
                      raw_banners={})
    http = FakeHTTP(responses={
        "/": Response(200, {"Server": "TP-LINK"},
                      "<title>Archer AX21</title>", ""),
    })
    match = run(enrich(dev, http))
    assert match is not None
    assert dev.model == "Archer AX21"
    assert dev.http_signatures.get("model_match") == "Archer AX21"


def test_identify_favicon_hash_pins_model():
    # A quiet device (no model text) matched purely by favicon hash.
    raw = b"a quiet router favicon"
    fav = favicon_hash(raw)
    from cve_detect import fingerprint
    fingerprint._signatures = [fingerprint.Signature(
        vendor="dlink", model="DIR-620", ports=[80], favicon=[fav])]
    dev = make_device(vendor="dlink", model="", open_ports=[80], raw_banners={})
    http = FakeHTTP(responses={
        "/": Response(200, {}, "<title>Login</title>", ""),
        "/favicon.ico": Response(200, {}, raw.decode("latin1"), "", content=raw),
    })
    try:
        match = run(identify_model(dev, http))
        assert match is not None and match.model == "DIR-620"
        assert "favicon" in match.evidence
    finally:
        fingerprint._signatures = None  # reset cache for other tests


def test_identify_scope_denied_makes_no_call():
    dev = make_device(vendor="dlink", model="", open_ports=[80])
    http = FakeHTTP(scope_allows=lambda _h: False)
    match = run(identify_model(dev, http))
    assert http.calls == []
    assert match is None
