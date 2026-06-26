"""Loader/matcher for the curated router CVE knowledge base.

Matches a detected fingerprint blob (vendor/product/version/banners) against a
small offline list of well-known router CVEs. Transparent and extensible — see
``data/router_cves.yaml``.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import Finding, normalize_severity

log = logging.getLogger(__name__)

_DATA = Path(__file__).parent / "data" / "router_cves.yaml"


@dataclass(slots=True)
class _Entry:
    pattern: re.Pattern
    cve: str
    severity: str
    title: str
    reference: str


_entries: list[_Entry] | None = None


def _load() -> list[_Entry]:
    global _entries
    if _entries is not None:
        return _entries
    entries: list[_Entry] = []
    try:
        raw = yaml.safe_load(_DATA.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("cve_db: could not load %s: %s", _DATA, exc)
        _entries = []
        return _entries
    for item in raw.get("cves", []):
        try:
            entries.append(_Entry(
                pattern=re.compile(str(item["match"]), re.IGNORECASE),
                cve=str(item["cve"]),
                severity=str(item.get("severity", "medium")),
                title=str(item.get("title", item["cve"])),
                reference=str(item.get("reference", "")),
            ))
        except (KeyError, re.error) as exc:
            log.warning("cve_db: skipping invalid entry %r: %s", item, exc)
    _entries = entries
    return _entries


def match_fingerprint(blob: str) -> list[Finding]:
    """Return CVE Findings whose pattern matches the fingerprint ``blob``."""
    if not blob.strip():
        return []
    findings: list[Finding] = []
    for entry in _load():
        if entry.pattern.search(blob):
            findings.append(Finding(
                stage="cve",
                severity=normalize_severity(entry.severity),
                title=f"{entry.cve}: {entry.title}",
                detail={"cve": entry.cve, "reference": entry.reference,
                        "matched": entry.pattern.pattern},
            ))
    return findings
