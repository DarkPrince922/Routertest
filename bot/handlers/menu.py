"""Main menu, /start and the status screen."""
from __future__ import annotations

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from engine.runner import Engine
from engine.store import Store

from .. import keyboards
from ..callbacks import MenuCB
from ..tools import tool_versions
from ..utils import safe_edit

router = Router(name="menu")

WELCOME = (
    "🛰️ <b>Router Pentest Orchestrator</b>\n\n"
    "Авторизованный пентест сетевых устройств. Управление — кнопками ниже.\n"
    "Все цели проходят проверку scope перед запуском любого инструмента."
)


@router.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(WELCOME, reply_markup=keyboards.main_menu())


@router.callback_query(MenuCB.filter(F.action == "main"))
async def show_main(query: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await safe_edit(query, WELCOME, keyboards.main_menu())
    await query.answer()


@router.callback_query(MenuCB.filter(F.action == "status"))
async def show_status(query: CallbackQuery, engine: Engine, store: Store) -> None:
    versions = await tool_versions()
    interrupted = store.count_interrupted()
    interrupted_line = (f"♻️ Прервано (для возобновления — ⚙️ Настройки): {interrupted}\n"
                        if interrupted else "")
    text = (
        "ℹ️ <b>Статус</b>\n\n"
        f"Очередь: {engine.queue_size}\n"
        f"Активных сканов: {engine.running_count} / {engine.max_concurrent}\n"
        f"Всего job в БД: {store.count_jobs()}\n"
        f"{interrupted_line}\n"
        "<b>Версии инструментов:</b>\n"
        f"  • nmap: {versions['nmap']}\n"
        f"  • nuclei: {versions['nuclei']}\n"
        f"  • routersploit: {versions['routersploit']}\n"
        f"  • masscan: {versions['masscan']} · hydra: {versions['hydra']} · "
        f"snmp: {versions['snmp']} · metasploit: {versions['metasploit']}"
    )
    await safe_edit(query, text, keyboards.back_to_menu())
    await query.answer()
