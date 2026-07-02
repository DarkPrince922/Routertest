"""vulners stage parser: nmap --script vulners XML → findings + CVE recording."""
from __future__ import annotations

from engine.models import Severity
from engine.stages.vulners_stage import _parse_vulners, _severity

# A trimmed nmap -oX with a vulners script block on an SSH port.
_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh" product="OpenSSH" version="7.4"/>
    <script id="vulners" output="&#10;  cpe:/a:openbsd:openssh:7.4:&#10;    CVE-2021-99999  9.8  https://vulners.com/cve/CVE-2021-99999&#10;    CVE-2019-6111  5.8  https://vulners.com/cve/CVE-2019-6111&#10;    CVE-2020-15778  7.8  https://vulners.com/cve/CVE-2020-15778&#10;"/>
   </port>
  </ports>
 </host>
</nmaprun>"""


def test_severity_bands():
    assert _severity(9.8) == Severity.CRITICAL
    assert _severity(7.8) == Severity.HIGH
    assert _severity(5.8) == Severity.MEDIUM
    assert _severity(1.0) == Severity.LOW
    assert _severity(0.0) == Severity.INFO


def test_parse_extracts_high_critical_and_records():
    ctx: dict = {}
    findings = _parse_vulners(_XML, "", ctx)
    titles = " ".join(f.title for f in findings)
    # critical + high emitted individually; medium folded into the summary.
    assert "CVE-2021-99999" in titles
    assert "CVE-2020-15778" in titles
    assert "CVE-2019-6111" not in titles  # medium -> summary only
    # only high/critical are recorded for the verify stage
    assert set(ctx.get("cves", {})) == {"CVE-2021-99999", "CVE-2020-15778"}
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_parse_no_data():
    findings = _parse_vulners("<nmaprun></nmaprun>", "", {})
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_parse_script_missing_hint():
    findings = _parse_vulners("", "NSE: 'vulners' did not match / error", {})
    assert "скрипт" in findings[0].title.lower() or "vulners" in findings[0].title.lower()
