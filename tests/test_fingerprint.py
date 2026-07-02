"""Fingerprint → detector applicability and version-driven status."""
from __future__ import annotations

from conftest import FakeHTTP, make_device, run
from cve_detect.base import Status
from cve_detect.detectors.dlink_dir823x_cve_2025_29635 import DlinkDir823x
from cve_detect.detectors.tplink_archer_cve_2023_1389 import TplinkArcherAx21
from cve_detect.registry import applicable_detectors


def test_archer_applicable_only_to_tplink():
    tplink = make_device(model="Archer AX21", vendor="tp-link", open_ports=[80])
    dlink = make_device(model="DIR-823X", vendor="d-link", open_ports=[80])
    det = TplinkArcherAx21()
    assert det.applicable(tplink) is True
    assert det.applicable(dlink) is False


def test_registry_dispatch_filters_by_vendor():
    dlink = make_device(model="DIR-823X fw 240126", vendor="d-link", open_ports=[80])
    dets = applicable_detectors(dlink)
    names = {d.name for d in dets}
    assert any("DIR-823X" in n for n in names)
    assert not any("Archer" in n for n in names)


def test_archer_patched_firmware_not_vulnerable():
    dev = make_device(model="Archer AX21", vendor="tp-link",
                      firmware="1.1.4 Build 20230219", open_ports=[80])
    http = FakeHTTP()
    findings = run(TplinkArcherAx21().check(dev, http, active=False))
    assert findings[0].status == Status.NOT_VULNERABLE


def test_archer_old_firmware_is_likely():
    dev = make_device(model="Archer AX21", vendor="tp-link",
                      firmware="1.1.4 Build 20230101", open_ports=[80])
    http = FakeHTTP()
    findings = run(TplinkArcherAx21().check(dev, http, active=False))
    assert findings[0].status == Status.LIKELY
    assert findings[0].confidence >= 0.7


def test_dir823x_flagged_eol():
    dev = make_device(model="DIR-823X", vendor="d-link",
                      firmware="240126", open_ports=[80])
    http = FakeHTTP()
    findings = run(DlinkDir823x().check(dev, http, active=False))
    assert findings[0].eol is True
