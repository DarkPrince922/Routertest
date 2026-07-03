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
        f"🧵 Потоков (хостов одновременно): {esc(store.get_setting('max_concurrent', '2'))}",
        f"🛰 Сканер портов: {esc(cfg.port_scanner)}",
        f"🔎 Поиск живых: {esc(cfg.discovery_method)}",
        f"💥 Metasploit: {'вкл' if cfg.metasploit_enabled else 'выкл'}",
        f"🔬 cve_detect: {'активные проверки' if cfg.cve_active else 'safe (фингерпринт)'}",
        f"🛰 vulners (версия→CVE): {'вкл' if cfg.vulners_enabled else 'выкл'}",
        f"🧠 Выучено favicon-моделей: {store.count_favicon_models()}",
        f"🐢 Эконом-режим: {'вкл (лёгкая нагрузка)' if cfg.economy else 'выкл'}",
    ]
    if interrupted:
        lines.append(f"♻️ Прерванных сканов: <b>{interrupted}</b>")
    return "\n".join(lines)


async def _show(query: CallbackQuery, store: Store) -> None:
    cfg = runtime.get_config()
    await safe_edit(query, _view_text(store),
                    keyboards.settings_menu(cfg.proxy, cfg.rsf_default_only,
                                            store.count_interrupted(),
                                            cfg.skip_unknown, cfg.port_scanner,
                                            cfg.discovery_method, cfg.metasploit_enabled,
                                            cfg.economy, cfg.cve_active,
                                            store.count_favicon_models(),
                                            cfg.vulners_enabled,
                                            store.get_setting("max_concurrent", "2")))


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
                                store.count_interrupted(), cfg.skip_unknown,
                                cfg.port_scanner, cfg.discovery_method,
                                cfg.metasploit_enabled, cfg.economy, cfg.cve_active,
                                store.count_favicon_models(), cfg.vulners_enabled,
                                store.get_setting("max_concurrent", "2")))


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


_SCANNER_CYCLE = {"auto": "masscan", "masscan": "nmap", "nmap": "auto"}


@router.callback_query(SettingsCB.filter(F.action == "scanner_cycle"))
async def cycle_scanner(query: CallbackQuery, store: Store) -> None:
    new_value = _SCANNER_CYCLE.get(runtime.get_config().port_scanner, "auto")
    runtime.set_port_scanner(new_value)
    store.set_setting("port_scanner", new_value)
    await _show(query, store)
    await query.answer(f"Сканер портов: {new_value}")


@router.callback_query(SettingsCB.filter(F.action == "discovery_cycle"))
async def cycle_discovery(query: CallbackQuery, store: Store) -> None:
    new_value = _SCANNER_CYCLE.get(runtime.get_config().discovery_method, "auto")
    runtime.set_discovery_method(new_value)
    store.set_setting("discovery_method", new_value)
    await _show(query, store)
    await query.answer(f"Поиск живых: {new_value}")


@router.callback_query(SettingsCB.filter(F.action == "msf_toggle"))
async def toggle_metasploit(query: CallbackQuery, store: Store) -> None:
    new_value = not runtime.get_config().metasploit_enabled
    runtime.set_metasploit_enabled(new_value)
    store.set_setting("metasploit_enabled", "true" if new_value else "false")
    await _show(query, store)
    await query.answer("Metasploit включён (тяжёлый!)" if new_value
                       else "Metasploit выключен", show_alert=new_value)


@router.callback_query(SettingsCB.filter(F.action == "economy_toggle"))
async def toggle_economy(query: CallbackQuery, store: Store) -> None:
    new_value = not runtime.get_config().economy
    runtime.set_economy(new_value)
    store.set_setting("economy", "true" if new_value else "false")
    await _show(query, store)
    await query.answer(
        "🐢 Эконом-режим включён — нагрузка на CPU снижена" if new_value
        else "Эконом-режим выключен", show_alert=new_value)


@router.callback_query(SettingsCB.filter(F.action == "cve_toggle"))
async def toggle_cve_active(query: CallbackQuery, store: Store) -> None:
    new_value = not runtime.get_config().cve_active
    runtime.set_cve_active(new_value)
    store.set_setting("cve_active", "true" if new_value else "false")
    await _show(query, store)
    await query.answer(
        "🔬 Активные проверки CVE включены (неразрушающие)" if new_value
        else "cve_detect: только безопасный фингерпринт", show_alert=new_value)


_CONCURRENCY_CYCLE = [1, 2, 3, 4, 6, 8]


@router.callback_query(SettingsCB.filter(F.action == "threads_cycle"))
async def cycle_threads(query: CallbackQuery, store: Store, engine: Engine) -> None:
    cur = engine.max_concurrent
    nxt = next((v for v in _CONCURRENCY_CYCLE if v > cur), _CONCURRENCY_CYCLE[0])
    applied = engine.set_max_concurrent(nxt)
    store.set_setting("max_concurrent", str(applied))
    await _show(query, store)
    await query.answer(f"Потоков: {applied}")


@router.callback_query(SettingsCB.filter(F.action == "vulners_toggle"))
async def toggle_vulners(query: CallbackQuery, store: Store) -> None:
    new_value = not runtime.get_config().vulners_enabled
    runtime.set_vulners_enabled(new_value)
    store.set_setting("vulners_enabled", "true" if new_value else "false")
    await _show(query, store)
    await query.answer("🛰 vulners включён (нужен интернет)" if new_value
                       else "vulners выключен")


@router.callback_query(SettingsCB.filter(F.action == "favicon_clear"))
async def clear_favicon_models(query: CallbackQuery, store: Store) -> None:
    n = store.clear_favicon_models()
    await _show(query, store)
    await query.answer(
        f"🧠 Сброшено выученных favicon-моделей: {n}" if n
        else "База favicon пуста.", show_alert=bool(n))


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
