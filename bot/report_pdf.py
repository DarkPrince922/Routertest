"""Human-readable PDF report for a scan job (reportlab + DejaVu for Cyrillic).

``build_pdf(job, findings)`` returns the PDF as ``bytes``. The font is registered
once; if no Cyrillic-capable TTF is found we fall back to Helvetica (Latin only)
so report generation still succeeds rather than crashing.
"""
from __future__ import annotations

import html
import logging
import os
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from engine.models import Finding, ScanJob, Severity, severity_rank

log = logging.getLogger(__name__)

# A copy of the DejaVu fonts is bundled in bot/assets so Cyrillic renders even
# when fonts-dejavu-core isn't installed system-wide. System paths are fallbacks.
_ASSETS = Path(__file__).parent / "assets"
_FONT_CANDIDATES = [
    str(_ASSETS / "DejaVuSans.ttf"),
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
]
_FONT_BOLD_CANDIDATES = [
    str(_ASSETS / "DejaVuSans-Bold.ttf"),
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
]

FONT = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
_registered = False


def _register_fonts() -> None:
    """Register a Cyrillic TTF once; keep Helvetica fallback if none is present."""
    global FONT, FONT_BOLD, _registered
    if _registered:
        return
    _registered = True
    reg = next((p for p in _FONT_CANDIDATES if os.path.isfile(p)), None)
    bold = next((p for p in _FONT_BOLD_CANDIDATES if os.path.isfile(p)), None)
    if reg:
        try:
            pdfmetrics.registerFont(TTFont("DejaVu", reg))
            FONT = "DejaVu"
            if bold:
                pdfmetrics.registerFont(TTFont("DejaVu-Bold", bold))
                FONT_BOLD = "DejaVu-Bold"
            else:
                FONT_BOLD = "DejaVu"
        except Exception:  # noqa: BLE001
            log.warning("PDF: failed to register DejaVu font, using Helvetica")
    else:
        log.warning("PDF: no Cyrillic TTF found — Cyrillic may not render. "
                    "Install fonts-dejavu-core.")


# Severity → (label, colour) for the report.
_SEV = {
    Severity.CRITICAL: ("КРИТИЧЕСКАЯ", colors.HexColor("#6b21a8")),
    Severity.HIGH: ("ВЫСОКАЯ", colors.HexColor("#b91c1c")),
    Severity.MEDIUM: ("СРЕДНЯЯ", colors.HexColor("#b45309")),
    Severity.LOW: ("НИЗКАЯ", colors.HexColor("#15803d")),
    Severity.INFO: ("ИНФО", colors.HexColor("#475569")),
}

# Detail keys worth surfacing in the report, in display order, with RU labels.
_DETAIL_LABELS = [
    ("credentials", "Учётные данные"),
    ("cve", "CVE"),
    ("module", "Модуль"),
    ("port", "Порт"),
    ("service", "Сервис"),
    ("product", "Продукт"),
    ("version", "Версия"),
    ("community", "SNMP community"),
    ("sysDescr", "sysDescr"),
    ("matched_at", "Найдено по адресу"),
    ("status", "Статус"),
    ("confidence", "Уверенность"),
    ("evidence", "Признак"),
    ("remediation", "Устранение"),
    ("reference", "Ссылка"),
    ("references", "Ссылки"),
    ("methods", "Методы"),
    ("reason", "Причина"),
]


def _esc(value: object) -> str:
    return html.escape(str(value))


def build_pdf(job: ScanJob, findings: list[Finding]) -> bytes:
    """Render a scan job + its findings into a human-readable PDF (bytes)."""
    _register_fonts()
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Отчёт о сканировании #{job.id}", author="Router Pentest Orchestrator",
    )
    story = _build_story(job, findings)
    doc.build(story)
    return buf.getvalue()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName=FONT_BOLD,
                                 fontSize=18, leading=22, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontName=FONT,
                               fontSize=9, textColor=colors.HexColor("#64748b")),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=FONT_BOLD,
                              fontSize=13, leading=16, spaceBefore=10, spaceAfter=4,
                              textColor=colors.HexColor("#0f172a")),
        "body": ParagraphStyle("b", parent=base["Normal"], fontName=FONT,
                                fontSize=10, leading=14, alignment=TA_LEFT),
        "find": ParagraphStyle("f", parent=base["Normal"], fontName=FONT_BOLD,
                               fontSize=10.5, leading=14, spaceBefore=6),
        "detail": ParagraphStyle("d", parent=base["Normal"], fontName=FONT,
                                  fontSize=9, leading=12, leftIndent=10,
                                  textColor=colors.HexColor("#334155")),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontName=FONT,
                                fontSize=9.5, leading=12),
        "cellb": ParagraphStyle("cb", parent=base["Normal"], fontName=FONT_BOLD,
                                 fontSize=9.5, leading=12),
    }


def _build_story(job: ScanJob, findings: list[Finding]) -> list:
    st = _styles()
    story: list = []

    story.append(Paragraph("Отчёт о сканировании", st["title"]))
    story.append(Paragraph(
        "Router Pentest Orchestrator · авторизованное тестирование", st["sub"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 8))

    # --- summary table -------------------------------------------------------
    story.append(_summary_table(job, st))
    story.append(Spacer(1, 6))

    # --- device fingerprint --------------------------------------------------
    fp = next((f for f in findings if f.stage == "fingerprint"
               and "verdict" in f.detail), None)
    if fp is not None:
        story.append(Paragraph("Устройство", st["h2"]))
        story.append(Paragraph(_esc(fp.detail.get("label", "—")), st["body"]))
        extra = []
        for key, lbl in (("vendor", "Вендор"), ("os_name", "ОС/модель"),
                         ("firmware", "Прошивка")):
            val = fp.detail.get(key)
            if val:
                extra.append(f"{lbl}: {_esc(val)}")
        if extra:
            story.append(Paragraph(" · ".join(extra), st["detail"]))

    # --- severity breakdown --------------------------------------------------
    story.append(Paragraph("Сводка по серьёзности", st["h2"]))
    story.append(_breakdown_table(findings, st))

    # --- findings grouped by severity (most severe first) --------------------
    story.append(Paragraph("Находки", st["h2"]))
    by_sev: dict[Severity, list[Finding]] = {}
    for f in findings:
        by_sev.setdefault(f.severity, []).append(f)

    any_finding = False
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO):
        items = by_sev.get(sev)
        if not items:
            continue
        any_finding = True
        label, colour = _SEV[sev]
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f'<font color="{colour.hexval()}">■</font> '
            f'<b>{label}</b> ({len(items)})', st["find"]))
        for f in items:
            story.append(Paragraph(
                f'<font color="{colour.hexval()}">{_esc(f.stage)}:</font> '
                f'{_esc(f.title)}', st["body"]))
            for line in _detail_lines(f):
                story.append(Paragraph(line, st["detail"]))
    if not any_finding:
        story.append(Paragraph("Находок нет.", st["body"]))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e2e8f0")))
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(
        f"Сгенерировано: {gen} · engagement: {_esc(job.engagement_id)}", st["sub"]))
    return story


def _summary_table(job: ScanJob, st: dict) -> Table:
    def cell(text: str, bold: bool = False) -> Paragraph:
        return Paragraph(_esc(text), st["cellb"] if bold else st["cell"])

    created = job.created_at.strftime("%Y-%m-%d %H:%M UTC")
    finished = (job.finished_at.strftime("%Y-%m-%d %H:%M UTC")
                if job.finished_at else "—")
    rows = [
        [cell("Скан", True), cell(f"#{job.id}")],
        [cell("Цель", True), cell(job.target)],
        [cell("Профиль", True), cell(job.profile.value)],
        [cell("Статус", True), cell(job.status.value)],
        [cell("Создан", True), cell(created)],
        [cell("Завершён", True), cell(finished)],
    ]
    if job.error:
        rows.append([cell("Ошибка", True), cell(job.error)])
    t = Table(rows, colWidths=[35 * mm, None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _breakdown_table(findings: list[Finding], st: dict) -> Table:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
             Severity.LOW, Severity.INFO]
    header, values = [], []
    for sev in order:
        label, colour = _SEV[sev]
        header.append(Paragraph(f'<font color="{colour.hexval()}">{label}</font>',
                                st["cellb"]))
        values.append(Paragraph(str(counts.get(sev, 0)), st["cell"]))
    t = Table([header, values], colWidths=[None] * len(order))
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _detail_lines(f: Finding) -> list[str]:
    """Render the salient detail fields of a finding as 'label: value' lines."""
    lines: list[str] = []
    for key, label in _DETAIL_LABELS:
        if key not in f.detail:
            continue
        val = f.detail[key]
        if val in (None, "", [], {}):
            continue
        if isinstance(val, (list, tuple)):
            val = ", ".join(str(v) for v in val)
        text = _esc(val)
        if len(text) > 300:
            text = text[:300] + "…"
        lines.append(f"<b>{_esc(label)}:</b> {text}")
    return lines
