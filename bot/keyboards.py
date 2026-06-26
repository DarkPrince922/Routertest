"""All inline keyboards live here so the button tree mirrors the spec exactly."""
from __future__ import annotations

import math

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from engine.models import ScanJob, ScanProfile

from .callbacks import JobCB, MenuCB, PageCB, ScanCB, SettingsCB

HISTORY_PAGE_SIZE = 5
FINDINGS_PAGE_SIZE = 5

PROFILE_LABELS: dict[ScanProfile, str] = {
    ScanProfile.QUICK: "⚡ Быстрый",
    ScanProfile.STANDARD: "🔍 Стандартный",
    ScanProfile.FULL: "💣 Полный",
}


def main_menu() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="🎯 Новый скан", callback_data=MenuCB(action="scan"))
    kb.button(text="📊 История", callback_data=MenuCB(action="history"))
    kb.button(text="📋 Scope", callback_data=MenuCB(action="scope"))
    kb.button(text="ℹ️ Статус", callback_data=MenuCB(action="status"))
    kb.button(text="⚙️ Настройки", callback_data=MenuCB(action="settings"))
    kb.adjust(1, 2, 1, 1)
    return kb.as_markup()


def settings_menu(proxy: str | None, rsf_default_only: bool,
                  interrupted: int) -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text=("🔌 Прокси: задать" if not proxy else "🔌 Прокси: изменить"),
              callback_data=SettingsCB(action="proxy_set"))
    if proxy:
        kb.button(text="❌ Убрать прокси", callback_data=SettingsCB(action="proxy_clear"))
    kb.button(
        text=("🔑 Креды: только дефолтные" if rsf_default_only
              else "🔑 Креды: + bruteforce"),
        callback_data=SettingsCB(action="rsf_toggle"))
    if interrupted:
        kb.button(text=f"♻️ Возобновить прерванные ({interrupted})",
                  callback_data=SettingsCB(action="resume"))
    kb.button(text="🏠 Меню", callback_data=MenuCB(action="main"))
    kb.adjust(1)
    return kb.as_markup()


def back_to_menu() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="🏠 Меню", callback_data=MenuCB(action="main"))
    return kb.as_markup()


def target_choice(targets: list[str]) -> InlineKeyboardMarkup:
    """Step 1: one button per scope target + manual entry + back."""
    kb = InlineKeyboardBuilder()
    for idx, target in enumerate(targets):
        kb.button(text=f"🎯 {target}", callback_data=ScanCB(step="target", value=str(idx)))
    kb.button(text="✏️ Ввести вручную", callback_data=ScanCB(step="manual"))
    kb.button(text="📄 Список из TXT", callback_data=ScanCB(step="file"))
    kb.button(text="🏠 Меню", callback_data=MenuCB(action="main"))
    kb.adjust(1)
    return kb.as_markup()


def batch_done() -> InlineKeyboardMarkup:
    """Buttons under a finished batch scan."""
    kb = InlineKeyboardBuilder()
    kb.button(text="📊 История", callback_data=MenuCB(action="history"))
    kb.button(text="🏠 Меню", callback_data=MenuCB(action="main"))
    kb.adjust(2)
    return kb.as_markup()


def profile_choice() -> InlineKeyboardMarkup:
    """Step 2: profile selection."""
    kb = InlineKeyboardBuilder()
    kb.button(text=PROFILE_LABELS[ScanProfile.QUICK],
              callback_data=ScanCB(step="profile", value=ScanProfile.QUICK.value))
    kb.button(text=PROFILE_LABELS[ScanProfile.STANDARD],
              callback_data=ScanCB(step="profile", value=ScanProfile.STANDARD.value))
    kb.button(text=PROFILE_LABELS[ScanProfile.FULL],
              callback_data=ScanCB(step="profile", value=ScanProfile.FULL.value))
    kb.button(text="◀️ Назад", callback_data=ScanCB(step="target"))
    kb.adjust(3, 1)
    return kb.as_markup()


def confirm() -> InlineKeyboardMarkup:
    """Step 3: confirm/run or go back."""
    kb = InlineKeyboardBuilder()
    kb.button(text="✅ Запустить", callback_data=ScanCB(step="run"))
    kb.button(text="◀️ Назад", callback_data=ScanCB(step="profile"))
    kb.adjust(2)
    return kb.as_markup()


def result_actions(job_id: int) -> InlineKeyboardMarkup:
    """Buttons shown under a finished scan summary."""
    kb = InlineKeyboardBuilder()
    kb.button(text="📄 Полный отчёт (JSON)", callback_data=JobCB(action="json", job_id=job_id))
    kb.button(text="🔁 Повторить", callback_data=JobCB(action="repeat", job_id=job_id))
    kb.button(text="🏠 Меню", callback_data=MenuCB(action="main"))
    kb.adjust(1, 2)
    return kb.as_markup()


def scan_running(job_id: int) -> InlineKeyboardMarkup:
    """Stop button shown on the live progress message of a single scan."""
    kb = InlineKeyboardBuilder()
    kb.button(text="⏹️ Стоп", callback_data=JobCB(action="stop", job_id=job_id))
    return kb.as_markup()


def batch_running(batch_key: int) -> InlineKeyboardMarkup:
    """Stop-all button shown on a running batch's aggregate message."""
    kb = InlineKeyboardBuilder()
    kb.button(text="⏹️ Остановить все", callback_data=JobCB(action="stopbatch", job_id=batch_key))
    return kb.as_markup()


def history_list(jobs: list[ScanJob], page: int, total: int) -> InlineKeyboardMarkup:
    """List of jobs with pagination controls."""
    kb = InlineKeyboardBuilder()
    for job in jobs:
        marker = _status_marker(job.status.value)
        label = f"{marker} #{job.id} {job.target} · {job.profile.value}"
        kb.button(text=label, callback_data=JobCB(action="view", job_id=job.id))
    kb.adjust(1)

    pages = max(1, math.ceil(total / HISTORY_PAGE_SIZE))
    nav = _pager_row(PageCB, "history", page, pages)
    if nav:
        kb.row(*nav)
    kb.row(InlineKeyboardButton(text="🏠 Меню", callback_data=MenuCB(action="main").pack()))
    return kb.as_markup()


def job_detail(job_id: int, page: int, total_findings: int) -> InlineKeyboardMarkup:
    """Findings pagination + JSON + menu for a single job."""
    kb = InlineKeyboardBuilder()
    pages = max(1, math.ceil(total_findings / FINDINGS_PAGE_SIZE)) if total_findings else 1
    nav = _pager_row(PageCB, "findings", page, pages, ref=job_id)
    if nav:
        kb.row(*nav)
    kb.row(
        InlineKeyboardButton(text="📄 JSON", callback_data=JobCB(action="json", job_id=job_id).pack()),
        InlineKeyboardButton(text="🏠 Меню", callback_data=MenuCB(action="main").pack()),
    )
    return kb.as_markup()


def _pager_row(cb_cls, scope: str, page: int, pages: int, ref: int = 0
               ) -> list[InlineKeyboardButton]:
    if pages <= 1:
        return []
    row: list[InlineKeyboardButton] = []
    if page > 0:
        row.append(InlineKeyboardButton(
            text="◀️", callback_data=cb_cls(scope=scope, page=page - 1, ref=ref).pack()))
    row.append(InlineKeyboardButton(
        text=f"{page + 1}/{pages}", callback_data=MenuCB(action="main").pack()))
    if page < pages - 1:
        row.append(InlineKeyboardButton(
            text="▶️", callback_data=cb_cls(scope=scope, page=page + 1, ref=ref).pack()))
    return row


def _status_marker(status: str) -> str:
    return {
        "DONE": "✅",
        "RUNNING": "▶️",
        "QUEUED": "⏳",
        "REJECTED": "⛔",
        "ERROR": "⚠️",
        "CANCELLED": "⏹️",
        "SKIPPED": "⏭️",
        "INTERRUPTED": "⛔",
    }.get(status, "•")
