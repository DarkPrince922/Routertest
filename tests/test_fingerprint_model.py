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


# ---- self-learning favicon → model ----------------------------------------
class DictLearner:
    """In-memory favicon→model store (stand-in for the DB-backed learner)."""

    def __init__(self):
        self.db: dict[int, tuple[str, str]] = {}

    def lookup(self, favicon):
        return self.db.get(favicon)

    def learn(self, favicon, vendor, model):
        self.db[favicon] = (vendor, model)


def test_bot_learns_favicon_from_text_match_then_pins_quiet_device():
    learner = DictLearner()
    fav = b"dir620-favicon-blob"

    # 1) First device advertises the model in its body -> confident text match.
    #    The bot should LEARN this favicon -> DIR-620.
    talkative = make_device(vendor="dlink", model="", open_ports=[80], raw_banners={})
    http1 = FakeHTTP(responses={
        "/favicon.ico": Response(200, {}, fav.decode("latin1"), "", content=fav),
        "/": Response(200, {"Server": "mathopd"}, "<title>Login</title> DIR-620 A1", ""),
    })
    m1 = run(identify_model(talkative, http1, learner=learner))
    assert m1.model == "DIR-620"
    assert learner.db  # favicon was learned

    # 2) Second device is a QUIET DIR-620: same favicon, but zero model text.
    #    It must be pinned purely from the learned favicon.
    quiet = make_device(vendor="dlink", model="", open_ports=[80], raw_banners={})
    http2 = FakeHTTP(responses={
        "/favicon.ico": Response(200, {}, fav.decode("latin1"), "", content=fav),
        "/": Response(200, {}, "<title>Login</title>", ""),
    })
    m2 = run(identify_model(quiet, http2, learner=learner))
    assert m2 is not None
    assert m2.model == "DIR-620"
    assert "изучен" in m2.evidence


def test_store_favicon_count_and_clear():
    from engine.store import Store
    store = Store(":memory:")
    assert store.count_favicon_models() == 0
    store.learn_favicon_model(123, "dlink", "DIR-620")
    store.learn_favicon_model(123, "dlink", "DIR-620")   # upsert, hits++
    store.learn_favicon_model(456, "tplink", "Archer AX21")
    assert store.count_favicon_models() == 2
    assert store.get_favicon_model(123) == ("dlink", "DIR-620")
    assert store.clear_favicon_models() == 2
    assert store.count_favicon_models() == 0


def test_no_learning_without_text_confidence():
    learner = DictLearner()
    dev = make_device(vendor="dlink", model="", open_ports=[80], raw_banners={})
    # Generic page, unknown favicon, no signature match -> nothing learned.
    http = FakeHTTP(responses={
        "/favicon.ico": Response(200, {}, "x", "", content=b"x"),
        "/": Response(200, {}, "<title>Login</title>", ""),
    })
    run(identify_model(dev, http, learner=learner))
    assert learner.db == {}

