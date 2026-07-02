"""Engine target parsing (closes the earlier 'no tests' gap for parse_targets)."""
from __future__ import annotations

from bot.targets import is_cidr, parse_targets


def test_is_cidr():
    assert is_cidr("192.168.1.0/24") is True
    assert is_cidr("192.168.1.1") is False
    assert is_cidr("myrouter.local") is False


def test_parse_targets_dedup_and_split():
    text = "192.168.1.1, 192.168.1.1\n10.0.0.5 host.local\n# comment\n"
    targets, skipped, truncated = parse_targets(text)
    assert targets == ["192.168.1.1", "10.0.0.5", "host.local"]
    assert truncated == 0


def test_parse_targets_counts_invalid():
    targets, skipped, _ = parse_targets("192.168.1.1\n!!!bad!!!\n")
    assert "192.168.1.1" in targets
    assert skipped >= 1


def test_parse_targets_accepts_cidr():
    targets, _, _ = parse_targets("192.168.0.0/24 10.0.0.0/16")
    assert "192.168.0.0/24" in targets and "10.0.0.0/16" in targets
