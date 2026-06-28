"""nuclei stage — template-based vuln/exposure scanning, JSONL output."""
from __future__ import annotations

import asyncio
import json
import logging
import socket

from ..cve_db import record_cve
from ..models import Finding, normalize_severity
from ..runtime import effective_nuclei_concurrency, get_config, heavy_semaphore
from ._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

NUCLEI_TIMEOUT = 900.0
# Common router web ports to probe so nuclei hits the admin UI wherever it lives
# (not just 80/443). Each open one is passed to nuclei as an explicit URL.
HTTP_PORTS = [80, 8080, 8000, 8081, 8888, 81, 8090, 7547]
HTTPS_PORTS = [443, 8443, 4433, 8843]
_PROBE_TIMEOUT = 1.0


async def nuclei_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    """Run nuclei against the target's open web ports (+ the host for network
    templates). Uses the full template set by default; ``NUCLEI_TAGS`` may
    restrict it for speed.
    """
    urls = await asyncio.to_thread(_build_targets, target)

    cfg = get_config()
    cmd = ["nuclei", "-jsonl", "-silent", "-timeout", "5",
           "-c", str(effective_nuclei_concurrency())]
    tags = cfg.nuclei_tags.strip()
    if tags:
        cmd += ["-tags", tags]
    for url in urls:
        cmd += ["-u", url]
    proxy = get_config().proxy
    if proxy:
        cmd += ["-proxy", proxy]
    try:
        # Bound concurrent nuclei runs so high MAX_CONCURRENT doesn't OOM the box.
        async with heavy_semaphore():
            rc, stdout, stderr = await run_cmd(cmd, timeout=NUCLEI_TIMEOUT)
    except ToolNotFound:
        return [Finding("nuclei", normalize_severity("info"), "nuclei not installed",
                        {"error": "nuclei binary not found on PATH"})]

    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        f = _parse_nuclei_event(obj)
        findings.append(f)
        tid = (f.detail.get("template_id") or "")
        if tid.upper().startswith("CVE"):
            record_cve(ctx, tid, "nuclei")

    if not findings:
        low = stderr.lower()
        if ("no templates" in low or "could not find any" in low
                or "templates directory" in low or "no valid templates" in low):
            # The usual cause of "nuclei finds nothing": templates aren't
            # installed. Make it loud so the operator fixes it.
            findings.append(Finding(
                "nuclei", normalize_severity("medium"),
                "⚠️ nuclei: шаблоны не установлены — запустите "
                "`nuclei -update-templates` (иначе уязвимости не ищутся)",
                {"stderr": stderr[:300]}))
        else:
            findings.append(
                Finding("nuclei", normalize_severity("info"), "no nuclei matches",
                        {"returncode": rc, "stderr": stderr[:300]}))
    return findings


def _build_targets(target: str) -> list[str]:
    """Build the nuclei target list: the bare host (network templates) + a URL
    for each open web port (http/https templates hit the real admin UI)."""
    urls: list[str] = [target]  # bare host → network/non-HTTP templates
    ip = _resolve(target)
    for port in HTTP_PORTS:
        if _is_open(ip, port):
            urls.append(f"http://{target}" if port == 80 else f"http://{target}:{port}")
    for port in HTTPS_PORTS:
        if _is_open(ip, port):
            urls.append(f"https://{target}" if port == 443 else f"https://{target}:{port}")
    # If nothing probed open, still try the defaults so nuclei does something.
    if len(urls) == 1:
        urls += [f"http://{target}", f"https://{target}"]
    return urls


def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def _is_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=_PROBE_TIMEOUT):
            return True
    except OSError:
        return False


def _parse_nuclei_event(obj: dict) -> Finding:
    info = obj.get("info", {}) if isinstance(obj.get("info"), dict) else {}
    severity = normalize_severity(info.get("severity"))
    name = info.get("name") or obj.get("template-id") or "nuclei match"
    matched = obj.get("matched-at") or obj.get("host") or ""
    title = f"{name}" + (f" @ {matched}" if matched else "")
    return Finding(
        stage="nuclei",
        severity=severity,
        title=title,
        detail={
            "template_id": obj.get("template-id"),
            "matched_at": matched,
            "type": obj.get("type"),
            "tags": info.get("tags"),
            "reference": info.get("reference"),
        },
    )
