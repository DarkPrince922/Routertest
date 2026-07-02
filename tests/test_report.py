"""Report aggregation: grouping, severity sort, EoL summary, valid JSON shape."""
from __future__ import annotations

import json

from cve_detect.base import Finding, Status
from cve_detect.report import build_json, build_markdown


def _findings():
    return [
        Finding("CVE-2018-10562", "GPON RCE", "critical", Status.VULNERABLE, 0.95,
                "web", "bypass confirmed", "patch", host="192.0.2.10"),
        Finding("CVE-2025-29635", "DIR-823X", "high", Status.LIKELY, 0.7,
                "web", "fw match", "replace", eol=True, host="192.0.2.10"),
        Finding("CVE-2024-3721", "DVR", "high", Status.UNKNOWN, 0.4,
                "dvr", "port", "isolate", host="192.0.2.11"),
    ]


def test_json_summary_counts():
    data = build_json(_findings())
    s = data["summary"]
    assert s["hosts"] == 2
    assert s["actionable"] == 2          # vulnerable + likely (unknown excluded)
    assert s["critical"] == 1
    assert s["high"] == 1
    assert s["eol_devices_to_replace"] == ["192.0.2.10"]


def test_json_is_serializable():
    data = build_json(_findings())
    json.dumps(data)                      # must not raise


def test_markdown_sorted_and_has_remediation():
    md = build_markdown(_findings())
    # critical must appear before the high finding for the same host
    assert md.index("CVE-2018-10562") < md.index("CVE-2025-29635")
    assert "Устранение" in md
    assert "Приоритетные действия" in md


def test_markdown_empty():
    assert "Находок нет" in build_markdown([])
