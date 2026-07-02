"""Regression from a real scan: ASUS RT-AC51U was mislabelled 'не определить'.

The nmap -sV product ("Asus RT-AC51U WAP http config") clearly names the device,
so the fingerprint must call it a router and the ASUS detector must flag it
(EoL) rather than emitting weak 'unknown' verdicts.
"""
from __future__ import annotations

from conftest import FakeHTTP, make_device, run
from cve_detect.base import Status
from cve_detect.detectors.asus_wrthug import AsusWrtHug
from engine.stages.nmap_stage import _classify


def test_classify_names_device_from_nmap_product():
    verdict, label, _conf = _classify(
        products=["Asus RT-AC51U WAP http config"], services=["http"],
        os_info={}, banners={})
    assert verdict == "router"
    assert "asus" in label.lower() or "rt-ac51u" in label.lower()


def test_asus_rtac51u_is_likely_and_eol():
    # Model comes in via the nmap-derived model string (folded by the stage into
    # DeviceInfo.model); AiCloud port is closed, but RT-AC51U is EoL.
    dev = make_device(vendor="asus",
                      model="роутер (Asus RT-AC51U WAP http config)",
                      open_ports=[80, 23])
    findings = run(AsusWrtHug().check(dev, FakeHTTP(), active=False))
    assert findings, "ASUS detector should fire"
    assert all(f.status == Status.LIKELY for f in findings)
    assert all(f.eol for f in findings)
    assert any("RT-AC51U" in f.evidence for f in findings)
