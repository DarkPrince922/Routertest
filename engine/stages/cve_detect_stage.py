"""cve_detect stage — runs the detection-only CVE module inside the pipeline.

Builds a :class:`cve_detect.DeviceInfo` from what nmap/snmp already learned (no
re-fingerprinting), runs the applicable detectors through the scope-gated SafeHTTP
transport, optionally confirms a few CVEs via the nuclei bridge (active mode
only), and converts the module's findings into engine findings so they flow into
history, alerts, verify and the PDF/JSON export like everything else.

Safe by default: active/non-destructive probes run only when ``CVE_ACTIVE`` (⚙️
Настройки → 🔬 Активные проверки) is on.
"""
from __future__ import annotations

import logging

from cve_detect import DeviceInfo, SafeHTTP, run_detectors
from cve_detect.base import Status
from cve_detect.fingerprint import enrich as enrich_model
from cve_detect.nuclei_bridge import BRIDGED_CVES, run_nuclei

from ..cve_db import record_cve
from ..models import Finding, Severity, normalize_severity
from ..runtime import get_config

log = logging.getLogger(__name__)

_STATUS_LABEL = {
    Status.VULNERABLE: "🔴 УЯЗВИМО",
    Status.LIKELY: "🟠 вероятно уязвимо",
    Status.NOT_VULNERABLE: "🟢 не уязвимо",
    Status.UNKNOWN: "⚪ не определено",
}


async def cve_detect_stage(target: str, ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    device = _device_from_ctx(target, ctx)
    active = get_config().cve_active
    http = SafeHTTP(
        ctx.get("_scope_allows", lambda _h: True),
        safe=not active,
        proxy=get_config().proxy,
        audit=lambda rec: log.info("cve_detect http %s", rec),
    )

    # Independently pin the model (favicon hash + title/Server/body/path/port
    # signatures) so detectors fire even when the device is "quiet" (generic UI,
    # SNMP closed). Also share it back so later stages/UI see the sharper model.
    model_finding: list[Finding] = []
    try:
        match = await enrich_model(device, http)
    except Exception:  # noqa: BLE001
        match = None
    if match is not None:
        ctx["model"] = device.model
        if not ctx.get("vendor"):
            ctx["vendor"] = device.vendor
        model_finding = [Finding("cve_detect", Severity.INFO,
                                 f"🔎 Модель уточнена: {device.model} "
                                 f"(conf {match.confidence:.2f}; {match.evidence})",
                                 {"model": device.model, "vendor": device.vendor,
                                  "confidence": round(match.confidence, 2),
                                  "evidence": match.evidence})]

    cve_findings = await run_detectors(device, http, active=active)

    # Active confirmation via nuclei for the few CVEs with vetted templates.
    if active:
        urls = _web_urls(target, device.open_ports)
        applicable_cves = {f.cve for f in cve_findings if f.cve in BRIDGED_CVES}
        for cve in applicable_cves:
            try:
                cve_findings += await run_nuclei(cve, urls)
            except Exception:  # noqa: BLE001
                log.debug("nuclei bridge error for %s", cve, exc_info=True)

    return model_finding + _to_engine_findings(cve_findings, ctx)


def _device_from_ctx(target: str, ctx: dict) -> DeviceInfo:
    banners = ctx.get("banners") or {}
    firmware = (banners.get("http_server") or banners.get("ssh_banner")
                or banners.get("telnet_banner") or "")
    http_sig = {
        "server": banners.get("http_server", ""),
        "title": banners.get("http_title", ""),
    }
    return DeviceInfo(
        ip=target,
        vendor=ctx.get("vendor"),
        model=ctx.get("model"),
        firmware=firmware or None,
        open_ports=list(ctx.get("open_ports") or []),
        http_signatures=http_sig,
        raw_banners=dict(banners),
    )


def _web_urls(target: str, open_ports: list[int]) -> list[str]:
    urls: list[str] = []
    for p in (80, 8080, 8000, 8081, 8888):
        if p in open_ports:
            urls.append(f"http://{target}" if p == 80 else f"http://{target}:{p}")
    for p in (443, 8443, 4433):
        if p in open_ports:
            urls.append(f"https://{target}" if p == 443 else f"https://{target}:{p}")
    return urls or [f"http://{target}", f"https://{target}"]


def _to_engine_findings(cve_findings, ctx: dict) -> list[Finding]:
    if not cve_findings:
        return [Finding("cve_detect", Severity.INFO,
                        "cve_detect: применимых детекторов не сработало", {})]
    out: list[Finding] = []
    # Dedup by CVE keeping the strongest status (vulnerable > likely > ...).
    _rank = {Status.VULNERABLE: 3, Status.LIKELY: 2, Status.UNKNOWN: 1,
             Status.NOT_VULNERABLE: 0}
    best: dict[str, object] = {}
    for f in cve_findings:
        cur = best.get(f.cve)
        if cur is None or _rank.get(f.status, 0) > _rank.get(cur.status, 0):
            best[f.cve] = f

    for f in best.values():
        actionable = f.status in (Status.VULNERABLE, Status.LIKELY)
        if f.status == Status.VULNERABLE:
            sev = normalize_severity(f.severity)
        elif f.status == Status.LIKELY:
            sev = normalize_severity(f.severity)
        else:
            sev = Severity.INFO
        label = _STATUS_LABEL.get(f.status, f.status)
        eol = " · EoL, под замену" if f.eol else ""
        title = f"{label}: {f.cve} — {f.title} (conf {f.confidence:.2f}{eol})"
        out.append(Finding("cve_detect", sev, title, {
            "cve": f.cve, "status": f.status, "confidence": round(f.confidence, 2),
            "severity": f.severity, "affected_component": f.affected_component,
            "evidence": f.evidence, "remediation": f.remediation,
            "references": list(f.references), "eol": f.eol,
        }))
        if actionable:
            # A VULNERABLE verdict came from an active non-destructive check (or
            # the nuclei bridge) → counts as active for the verify stage; a
            # LIKELY verdict is fingerprint inference → verify will re-check it.
            method = ("cve_detect_active" if f.status == Status.VULNERABLE
                      else "cve_detect")
            record_cve(ctx, f.cve, method)
    return out
