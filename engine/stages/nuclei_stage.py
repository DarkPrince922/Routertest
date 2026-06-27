"""nuclei stage — template-based vuln/exposure scanning, JSONL output."""
from __future__ import annotations

import json
import logging

from ..models import Finding, normalize_severity
from ..runtime import get_config
from ._common import ToolNotFound, run_cmd

log = logging.getLogger(__name__)

NUCLEI_TIMEOUT = 900.0
NUCLEI_TAGS = "router,iot,exposure,default-login,cve"


async def nuclei_stage(target: str) -> list[Finding]:
    """Run nuclei with router/IoT-focused tags and parse JSONL results."""
    cmd = [
        "nuclei", "-u", target, "-jsonl", "-silent",
        "-tags", NUCLEI_TAGS,
    ]
    proxy = get_config().proxy
    if proxy:
        cmd += ["-proxy", proxy]
    try:
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
        findings.append(_parse_nuclei_event(obj))

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
