"""verify stage — cross-check CVE findings to cut false positives.

CVEs reach this stage tagged by detection method (in ``ctx["cves"]``):
  * ``fingerprint`` — PASSIVE inference from the curated KB (vendor/banner match);
    high false-positive risk on its own.
  * ``nuclei`` / ``routersploit`` — ACTIVE checks that actually probed the target.

For each CVE we report a confidence:
  * confirmed by an active method, or corroborated by ≥2 methods → ✅;
  * inference-only → we ACTIVELY RE-CHECK by running that exact nuclei template
    (``-id <CVE>``). Match → ✅ confirmed; ran but no match → ⚠️ likely false;
    no template to check with → ℹ️ unverified.
"""
from __future__ import annotations

import asyncio
import json
import logging

from ..models import Finding, Severity
from ..runtime import heavy_semaphore
from ._common import ToolNotFound, run_cmd
from .nuclei_stage import _build_targets

log = logging.getLogger(__name__)

VERIFY_TIMEOUT = 180.0
_ACTIVE = {"nuclei", "routersploit", "metasploit"}


async def verify_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    """Correlate + actively re-verify CVE findings from earlier stages."""
    cves: dict[str, set] = (ctx or {}).get("cves", {})
    if not cves:
        return [Finding("verify", Severity.INFO, "перепроверка: CVE не найдено", {})]

    urls = await asyncio.to_thread(_build_targets, target)
    findings: list[Finding] = []

    for cve, methods in sorted(cves.items()):
        active = methods & _ACTIVE
        if active:
            label = "подтверждён активной проверкой" if len(methods) < 2 else "подтверждён (несколько методов)"
            findings.append(Finding(
                "verify", Severity.HIGH, f"✅ {cve}: {label} ({', '.join(sorted(methods))})",
                {"cve": cve, "methods": sorted(methods), "status": "confirmed"}))
            continue

        # Inference-only (fingerprint) → actively re-check with that CVE template.
        matched, ran = await _nuclei_recheck(urls, cve)
        if matched:
            findings.append(Finding(
                "verify", Severity.HIGH,
                f"✅ {cve}: подтверждён активной перепроверкой (nuclei)",
                {"cve": cve, "methods": sorted(methods | {"nuclei"}), "status": "confirmed"}))
        elif ran:
            findings.append(Finding(
                "verify", Severity.LOW,
                f"⚠️ {cve}: НЕ подтверждён активной проверкой — вероятно ложное "
                "(найден только по фингерпринту)",
                {"cve": cve, "methods": sorted(methods), "status": "unconfirmed"}))
        else:
            findings.append(Finding(
                "verify", Severity.INFO,
                f"ℹ️ {cve}: найден только по фингерпринту; у nuclei нет шаблона "
                "именно для этого CVE — перепроверить нечем "
                "(это не значит, что шаблоны не установлены)",
                {"cve": cve, "methods": sorted(methods), "status": "unverified"}))
    return findings


async def _template_exists(cve: str) -> bool:
    """Ask nuclei whether a template with this CVE id is installed (-tl filter)."""
    try:
        _, stdout, _ = await run_cmd(
            ["nuclei", "-tl", "-id", cve, "-silent"], timeout=30.0)
    except ToolNotFound:
        return False
    except Exception:  # noqa: BLE001
        return False
    return any(line.strip() for line in stdout.splitlines())


async def _nuclei_recheck(urls: list[str], cve: str) -> tuple[bool, bool]:
    """Run just the ``cve`` nuclei template. Returns ``(matched, ran)``.

    ``ran`` is False only when no template with that exact CVE id is installed
    (determined definitively via ``-tl``), so the message can't be confused with
    "templates not installed at all".
    """
    if not await _template_exists(cve):
        return False, False

    cmd = ["nuclei", "-jsonl", "-silent", "-timeout", "5", "-id", cve]
    for url in urls:
        cmd += ["-u", url]
    try:
        async with heavy_semaphore():
            _, stdout, _ = await run_cmd(cmd, timeout=VERIFY_TIMEOUT)
    except ToolNotFound:
        return False, False
    except Exception:  # noqa: BLE001
        return False, True  # template exists but the run errored

    for line in stdout.splitlines():
        line = line.strip()
        if line:
            try:
                json.loads(line)
                return True, True  # a match for this CVE id
            except json.JSONDecodeError:
                continue
    return False, True  # template ran, no match → likely false positive
