"""Read-only scope viewer."""
from __future__ import annotations

from aiogram import F, Router
from aiogram.types import CallbackQuery

from engine.scope import ScopeGate

from .. import keyboards
from ..callbacks import MenuCB
from ..render import scope_view
from ..utils import safe_edit

router = Router(name="scope")


@router.callback_query(MenuCB.filter(F.action == "scope"))
async def show_scope(query: CallbackQuery, scope_gate: ScopeGate) -> None:
    await safe_edit(query, scope_view(scope_gate.config), keyboards.back_to_menu())
    await query.answer()
