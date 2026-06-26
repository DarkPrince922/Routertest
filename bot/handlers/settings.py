"""⚙️ Настройки — proxy, routersploit creds mode, resume interrupted scans.

Values that should survive a restart (proxy, creds mode) are persisted in the
SQLite ``settings`` table and applied to the live engine runtime config.
"""
from __future__ import annotations

import re

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from engine import runtime
from engine.runner import Engine
from engine.store import Store

from .. import keyboards
from ..callbacks import MenuCB, SettingsCB
from ..render import esc
from ..states import SettingsFlow
from ..utils import safe_edit, safe_edit_message

router = Router(name="settings")

# Accept socks5/socks5h/socks4/http/https URLs with host:port.
_PROXY_RE = re.compile(r"^(socks5h?|socks4|https?)://[^\s/:]+:\d+$", re.IGNORECASE)


def _view_text(store: Store) -> str:
    cfg = runtime.get_config()
    proxy = cfg.proxy or "—"
    rsf = "только дефолтные креды" if cfg.rsf_default_only else "дефолтные + bruteforce"
    unknown = ("пропускать (строгий)" if cfg.skip_unknown
               else "сканировать (мягкий)")
    interrupted = store.count_interrupted()
    lines = [
        "⚙️ <b>Настройки</b>",
        "",
        f"🔌 Прокси: <code>{esc(proxy)}</code>",
        f"🔑 routersploit: {esc(rsf)}",
        f"🧭 Неизвестные устройства: {esc(unknown)}",
    ]
    if interrupted:
        lines.append(f"♻️ Прерванных сканов: <b>{interrupted}</b>")
    return "\n".join(lines)


async def _show(query: CallbackQuery, store: Store) -> None:
    cfg = runtime.get_config()
    await safe_edit(query, _view_text(store),
                    keyboards.settings_menu(cfg.proxy, cfg.rsf_default_only,
                                            store.count_interrupted(),
                                            cfg.skip_unknown))


@router.callback_query(MenuCB.filter(F.action == "settings"))
async def show_settings(query: CallbackQuery, state: FSMContext, store: Store) -> None:
    await state.clear()
    await _show(query, store)
    await query.answer()


# ------------------------------------------------------------------- proxy
@router.callback_query(SettingsCB.filter(F.action == "proxy_set"))
async def ask_proxy(query: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(SettingsFlow.entering_proxy)
    await safe_edit(
        query,
        "🔌 Пришлите адрес прокси одним сообщением, например:\n"
        "<code>socks5://127.0.0.1:9050</code> или <code>http://10.0.0.1:8080</code>\n\n"
        "Применяется к nuclei и грабу баннеров (nmap не проксируется).",
        keyboards.back_to_menu(),
    )
    await query.answer()


@router.message(SettingsFlow.entering_proxy)
async def receive_proxy(message: Message, state: FSMContext, store: Store) -> None:
    value = (message.text or "").strip()
    if not _PROXY_RE.match(value):
        await message.answer(
            "❌ Неверный формат. Нужно <code>схема://host:port</code> "
            "(socks5/socks4/http/https). Попробуйте ещё раз или /start.")
        return
    store.set_setting("scan_proxy", value)
    runtime.set_proxy(value)
    await state.clear()
    cfg = runtime.get_config()
    sent = await message.answer(f"✅ Прокси установлен: <code>{esc(value)}</code>")
    await safe_edit_message(
        sent, _view_text(store),
        keyboards.settings_menu(value, cfg.rsf_default_only,
                                store.count_interrupted(), cfg.skip_unknown))


@router.callback_query(SettingsCB.filter(F.action == "proxy_clear"))
async def clear_proxy(query: CallbackQuery, store: Store) -> None:
    store.set_setting("scan_proxy", None)
    runtime.set_proxy(None)
    await _show(query, store)
    await query.answer("Прокси убран")


# -------------------------------------------------------------- creds mode
@router.callback_query(SettingsCB.filter(F.action == "rsf_toggle"))
async def toggle_rsf(query: CallbackQuery, store: Store) -> None:
    new_value = not runtime.get_config().rsf_default_only
    runtime.set_rsf_default_only(new_value)
    store.set_setting("rsf_default_only", "true" if new_value else "false")
    await _show(query, store)
    await query.answer("Только дефолтные" if new_value else "Включён bruteforce")


@router.callback_query(SettingsCB.filter(F.action == "skip_toggle"))
async def toggle_skip_unknown(query: CallbackQuery, store: Store) -> None:
    new_value = not runtime.get_config().skip_unknown
    runtime.set_skip_unknown(new_value)
    store.set_setting("skip_unknown", "true" if new_value else "false")
    await _show(query, store)
    await query.answer("Неизвестные пропускаются" if new_value
                       else "Неизвестные сканируются")


# ---------------------------------------------------------- resume interrupted
@router.callback_query(SettingsCB.filter(F.action == "resume"))
async def resume(query: CallbackQuery, store: Store, engine: Engine) -> None:
    jobs = engine.resume_interrupted()
    await _show(query, store)
    await query.answer(
        f"♻️ Возобновлено: {len(jobs)}" if jobs else "Прерванных сканов нет.",
        show_alert=bool(jobs))


@router.callback_query(SettingsCB.filter(F.action == "clear"))
async def clear_interrupted(query: CallbackQuery, store: Store, engine: Engine) -> None:
    n = engine.clear_interrupted()
    await _show(query, store)
    await query.answer(
        f"🗑 Очищено: {n}" if n else "Прерванных сканов нет.", show_alert=bool(n))
