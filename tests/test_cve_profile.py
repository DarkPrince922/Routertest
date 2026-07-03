"""CVE-only profile: self-probes ports (no nmap) and runs just cve_detect."""
from __future__ import annotations

import asyncio
import socket

from engine.models import ScanProfile
from engine.runner import PROFILE_STAGES
from engine.stages.cve_detect_stage import _probe_ports


def test_cve_profile_is_cve_detect_only():
    names = [n for n, _ in PROFILE_STAGES[ScanProfile.CVE]]
    assert names == ["cve_detect"]


def test_probe_ports_detects_open_and_skips_closed():
    # Open a real listening socket on a random localhost port.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    open_port = srv.getsockname()[1]
    # A very likely-closed port (nothing listening).
    closed_port = 1
    try:
        found = asyncio.run(_probe_ports("127.0.0.1", [open_port, closed_port]))
        assert open_port in found
        assert closed_port not in found
    finally:
        srv.close()
