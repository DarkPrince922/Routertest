"""Version matching: boundary cases must give the right verdict."""
from __future__ import annotations

from cve_detect.versions import cmp_versions, in_vulnerable_set, is_below, parse_version


def test_parse_version_extracts_numbers():
    assert parse_version("1.1.4 Build 20230219 Rel.xxx") == (1, 1, 4, 20230219)
    assert parse_version(None) == ()
    assert parse_version("no-digits") == ()


def test_cmp_versions_orders_correctly():
    assert cmp_versions("1.1.3", "1.1.4") == -1
    assert cmp_versions("1.1.4", "1.1.4") == 0
    assert cmp_versions("1.2.0", "1.1.9") == 1


def test_is_below_boundary():
    fixed = "1.1.4 Build 20230219"
    assert is_below("1.1.4 Build 20230218", fixed) is True    # one below
    assert is_below("1.1.4 Build 20230219", fixed) is False   # exactly the fix
    assert is_below("1.1.5 Build 20230101", fixed) is False   # above
    assert is_below(None, fixed) is None                      # unparseable


def test_in_vulnerable_set():
    assert in_vulnerable_set("DIR-823X fw 240126", {"240126", "24082"}) is True
    assert in_vulnerable_set("DIR-823X fw 250101", {"240126"}) is False
    assert in_vulnerable_set(None, {"240126"}) is False
