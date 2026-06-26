"""Pure text-rendering helpers (no Telegram calls) for messages."""
from __future__ import annotations

import html

from engine.models import (
    Finding,
    ScanJob,
    ScanProfile,
    Severity,
    severity_rank,
)
from engine.scope import ScopeConfig

PROFILE_RU = {
    "QUICK": "Быстрый",
    "STANDARD": "Стандартный",
    "FULL": "Полный",
    "FIRMWARE": "Firmware",
}

SEVERITY_EMOJI = {
    Severity.INFO: "ℹ️",
    Severity.LOW: "🟢",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🔴",
    Severity.CRITICAL: "🟣",
}


def esc(text: str) -> str:
    return html.escape(str(text))


def short_id(job: ScanJob) -> str:
    return f"{job.id:x}"


STATUS_ICON = {
    "DONE": "✅",
    "SKIPPED": "⏭️",
    "CANCELLED": "⏹️",
    "ERROR": "⚠️",
    "REJECTED": "⛔",
}


def device_line(findings: list[Finding]) -> str | None:
    """Return the device-type line from the fingerprint finding, if any."""
    for f in findings:
        if f.stage == "fingerprint":
            return f"🧭 {esc(f.detail.get('label', '—'))}"
    return None


def summary(job: ScanJob, findings: list[Finding]) -> str:
    """The scan result summary block."""
    breakdown = _breakdown(findings)
    icon = STATUS_ICON.get(job.status.value, "⚠️")
    profile = PROFILE_RU.get(job.profile.value, job.profile.value)

    lines = [
        f"{icon} <b>{esc(job.target)}</b> [{short_id(job)}] · профиль: {esc(profile)}",
    ]
    dline = device_line(findings)
    if dline:
        lines.append(dline)
    if job.status.value == "SKIPPED":
        lines.append("⏭️ Цель не похожа на роутер — глубокие стадии пропущены.")
    elif job.status.value == "CANCELLED":
        lines.append("⏹️ Скан остановлен пользователем.")
    lines.append(f"Находок: {len(findings)} ({_breakdown_str(breakdown)})")
    if job.error:
        lines.append(f"⚠️ Ошибка: {esc(job.error)}")

    # Show the most severe findings first (up to 8).
    top = sorted(findings, key=lambda f: severity_rank(f.severity), reverse=True)[:8]
    for f in top:
        if f.severity == Severity.INFO:
            continue
        lines.append(f"[{f.severity.value}] {esc(f.stage)}: {esc(f.title)}")
    return "\n".join(lines)


STAGE_START_LINE = {
    "nmap": "🔍 Сканирую порты и определяю устройство…",
    "nuclei": "🧪 Проверяю известные уязвимости…",
    "routersploit": "🔑 Проверяю учётные данные по умолчанию…",
}


def stage_start_line(stage_name: str) -> str:
    """Human 'doing X now' line for the live narrative."""
    return STAGE_START_LINE.get(stage_name, f"▶️ {esc(stage_name)}…")


def stage_done_lines(stage_name: str, findings: list[Finding]) -> list[str]:
    """Human result line(s) for a finished stage, derived from its findings."""
    if stage_name == "nmap":
        ports = [f for f in findings if f.stage == "nmap" and "port" in f.detail]
        lines = [f"🛜 Открытых портов: {len(ports)}"]
        for f in findings:
            if f.stage != "fingerprint":
                continue
            verdict = f.detail.get("verdict", "unknown")
            label = f.detail.get("label", "—")
            if verdict == "router":
                lines.append(f"🧭 Определено устройство: <b>{esc(label)}</b>")
            elif verdict == "not_router":
                lines.append(f"🚫 {esc(label)} — это не роутер")
                lines.append("⏭️ Пропускаю проверки уязвимостей")
            else:
                lines.append(f"❔ Тип устройства: {esc(label)}")
        return lines

    if stage_name == "nuclei":
        matches = [f for f in findings if "template_id" in f.detail]
        if not matches:
            return ["🧪 Уязвимостей не найдено"]
        bd = _breakdown(matches)
        return [f"🧪 Найдено совпадений: {len(matches)} ({_breakdown_str(bd)})"]

    if stage_name == "routersploit":
        creds = [f for f in findings if severity_rank(f.severity) >= severity_rank(Severity.HIGH)]
        if creds:
            return [f"🔑 <b>Найдены слабые/дефолтные креды: {len(creds)}</b>"]
        return ["🔑 Дефолтные креды не найдены"]

    return []


def alert_text(job: ScanJob, finding: Finding, device_label: str) -> str:
    """Immediate push message for a high/critical finding on a (likely) router."""
    dev = f"\nУстройство: {esc(device_label)}" if device_label else ""
    return (
        "🚨 <b>УЯЗВИМЫЙ РОУТЕР</b>\n"
        f"Цель: <code>{esc(job.target)}</code>{dev}\n"
        f"[{finding.severity.value}] {esc(finding.stage)}: {esc(finding.title)}\n"
        f"Скан #{job.id}"
    )


def batch_summary(profile: ScanProfile,
                  results: list[tuple[ScanJob, list[Finding]]],
                  rejected: list[tuple[str, str]]) -> str:
    """Aggregate summary for a finished batch scan."""
    profile_ru = PROFILE_RU.get(profile.value, profile.value)
    total_findings = 0
    agg: dict[str, int] = {}
    notable: list[tuple[ScanJob, Finding]] = []

    for job, findings in results:
        total_findings += len(findings)
        for f in findings:
            agg[f.severity.value] = agg.get(f.severity.value, 0) + 1
            if severity_rank(f.severity) >= severity_rank(Severity.HIGH):
                notable.append((job, f))

    lines = [
        f"✅ <b>Пакетный скан завершён</b> · профиль: {esc(profile_ru)}",
        f"Целей просканировано: {len(results)}"
        + (f" · отклонено scope: {len(rejected)}" if rejected else ""),
        f"Всего находок: {total_findings} ({_breakdown_str(agg)})",
    ]

    if notable:
        lines.append("")
        lines.append(f"<b>Важное ({len(notable)}):</b>")
        for job, f in notable[:10]:
            lines.append(f"🔴 <code>{esc(job.target)}</code> [{f.severity.value}] "
                         f"{esc(f.stage)}: {esc(f.title)}")
        if len(notable) > 10:
            lines.append(f"… и ещё {len(notable) - 10}")

    if rejected:
        lines.append("")
        lines.append("<b>Отклонены scope:</b>")
        for target, reason in rejected[:5]:
            lines.append(f"⛔ <code>{esc(target)}</code> — {esc(reason)}")
        if len(rejected) > 5:
            lines.append(f"… и ещё {len(rejected) - 5}")

    lines.append("")
    lines.append("<i>Детали и JSON по каждой цели — в «📊 История».</i>")
    return "\n".join(lines)


def job_header(job: ScanJob) -> str:
    breakdown_note = ""
    profile = PROFILE_RU.get(job.profile.value, job.profile.value)
    created = job.created_at.strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"📄 <b>Скан #{job.id}</b> · [{short_id(job)}]",
        f"Цель: <code>{esc(job.target)}</code>",
        f"Профиль: {esc(profile)} · Статус: {esc(job.status.value)}",
        f"Создан: {esc(created)}",
    ]
    if job.error:
        lines.append(f"Ошибка: {esc(job.error)}")
    return "\n".join(lines) + breakdown_note


def findings_page(findings: list[Finding], breakdown: dict[str, int]) -> str:
    if breakdown:
        head = "Разбивка: " + ", ".join(f"{k}:{v}" for k, v in breakdown.items())
    else:
        head = "Находок нет."
    lines = [head, ""]
    for f in findings:
        emoji = SEVERITY_EMOJI.get(f.severity, "•")
        lines.append(f"{emoji} <b>[{f.severity.value}]</b> {esc(f.stage)}: {esc(f.title)}")
    return "\n".join(lines)


def scope_view(config: ScopeConfig) -> str:
    cidrs = "\n".join(f"  • <code>{esc(c)}</code>" for c in config.allowed_cidrs) or "  (нет)"
    hosts = "\n".join(f"  • <code>{esc(h)}</code>" for h in sorted(config.allowed_hosts)) or "  (нет)"
    if config.allow_all:
        gate_note = (
            "⚠️ <b>allow_all: ВКЛ</b> — scope-гейт отключён, разрешены любые цели "
            "(решения по-прежнему пишутся в audit).\n\n"
        )
    else:
        gate_note = ""
    return (
        "📋 <b>Scope (read-only)</b>\n\n"
        f"{gate_note}"
        f"engagement_id: <code>{esc(config.engagement_id)}</code>\n\n"
        f"<b>Разрешённые CIDR:</b>\n{cidrs}\n\n"
        f"<b>Разрешённые хосты:</b>\n{hosts}\n\n"
        "<i>Изменение целей — только правкой scope.yaml и рестартом сервиса.</i>"
    )


def _breakdown(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity.value] = out.get(f.severity.value, 0) + 1
    return out


def _breakdown_str(breakdown: dict[str, int]) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    parts = [f"{k}:{breakdown[k]}" for k in order if k in breakdown]
    return ", ".join(parts) if parts else "—"
