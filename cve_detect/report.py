"""Aggregate cve_detect findings into a human report (Markdown) and machine JSON.

Grouping: host → severity. The summary counts critical/high, lists EoL devices
recommended for replacement, and produces a prioritized remediation action list.
"""
from __future__ import annotations

from .base import Finding

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STATUS_ICON = {
    "vulnerable": "🔴", "likely": "🟠", "not_vulnerable": "🟢", "unknown": "⚪",
}


def _by_host(findings: list[Finding]) -> dict[str, list[Finding]]:
    hosts: dict[str, list[Finding]] = {}
    for f in findings:
        hosts.setdefault(f.host or "?", []).append(f)
    for items in hosts.values():
        items.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), -f.confidence))
    return hosts


def _actionable(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.status in ("vulnerable", "likely")]


def build_json(findings: list[Finding]) -> dict:
    """Machine-readable aggregate."""
    actionable = _actionable(findings)
    crit = sum(1 for f in actionable if f.severity == "critical")
    high = sum(1 for f in actionable if f.severity == "high")
    eol_hosts = sorted({f.host for f in actionable if f.eol})
    return {
        "summary": {
            "hosts": len({f.host for f in findings}),
            "actionable": len(actionable),
            "critical": crit, "high": high,
            "eol_devices_to_replace": eol_hosts,
        },
        "hosts": {
            host: [f.to_dict() for f in items]
            for host, items in _by_host(findings).items()
        },
    }


def build_markdown(findings: list[Finding]) -> str:
    """Human-readable report for the chat / client hand-off."""
    if not findings:
        return "# Отчёт cve_detect\n\nНаходок нет."
    actionable = _actionable(findings)
    crit = sum(1 for f in actionable if f.severity == "critical")
    high = sum(1 for f in actionable if f.severity == "high")
    eol_hosts = sorted({f.host for f in actionable if f.eol})

    lines = [
        "# Отчёт cve_detect (detection-only)",
        "",
        f"**Хостов:** {len({f.host for f in findings})} · "
        f"**Требуют внимания:** {len(actionable)} "
        f"(critical: {crit}, high: {high})",
    ]
    if eol_hosts:
        lines.append(f"**EoL-устройства под замену:** {', '.join(eol_hosts)}")
    lines.append("")

    for host, items in _by_host(findings).items():
        lines.append(f"## {host}")
        for f in items:
            icon = _STATUS_ICON.get(f.status, "•")
            lines.append(
                f"- {icon} **{f.cve}** [{f.severity}] — {f.title} "
                f"(_{f.status}_, conf {f.confidence:.2f})")
            lines.append(f"  - Признак: {f.evidence}")
            lines.append(f"  - Устранение: {f.remediation}")
            if f.references:
                lines.append(f"  - Ссылки: {', '.join(f.references)}")
        lines.append("")

    prio = _prioritized_actions(actionable)
    if prio:
        lines.append("## Приоритетные действия")
        for i, action in enumerate(prio, 1):
            lines.append(f"{i}. {action}")
    return "\n".join(lines).rstrip() + "\n"


def _prioritized_actions(actionable: list[Finding]) -> list[str]:
    """Dedup remediations, most-severe first, host-tagged."""
    seen: set[str] = set()
    ordered = sorted(actionable,
                     key=lambda f: (_SEV_ORDER.get(f.severity, 9), -f.confidence))
    out: list[str] = []
    for f in ordered:
        key = f"{f.host}|{f.remediation}"
        if key in seen:
            continue
        seen.add(key)
        out.append(f"[{f.host}] {f.cve}: {f.remediation}")
    return out
