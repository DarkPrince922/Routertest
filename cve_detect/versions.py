"""Firmware/version parsing helpers for detection (best-effort, vendor-agnostic).

Router firmware strings are wildly inconsistent ("1.1.4 Build 20230219 Rel.xxxx",
"3.0.0.4.386_51529", "240126"). We extract the leading numeric components and
compare them as tuples. ``is_below`` returns ``None`` when a string can't be
parsed so callers can degrade to a model-only (weaker) verdict instead of
guessing.
"""
from __future__ import annotations

import re

_NUM_RE = re.compile(r"\d+")


def parse_version(text: str | None) -> tuple[int, ...]:
    """Extract the numeric components of a version string as a tuple of ints.

    "1.1.4 Build 20230219" -> (1, 1, 4, 20230219). Empty/None -> ()."""
    if not text:
        return ()
    return tuple(int(n) for n in _NUM_RE.findall(text)[:6])


def cmp_versions(a: str | None, b: str | None) -> int:
    """Return -1/0/1 comparing ``a`` vs ``b`` component-wise (missing = 0)."""
    ta, tb = parse_version(a), parse_version(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def is_below(firmware: str | None, fixed: str) -> bool | None:
    """True if ``firmware`` is older than ``fixed``; None if unparseable."""
    if not parse_version(firmware):
        return None
    return cmp_versions(firmware, fixed) < 0


def in_vulnerable_set(firmware: str | None, vulnerable: set[str]) -> bool:
    """True if the firmware string contains any of the known-vulnerable tokens."""
    if not firmware:
        return False
    low = firmware.lower()
    return any(v.lower() in low for v in vulnerable)
