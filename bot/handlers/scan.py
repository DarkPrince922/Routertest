"""The new-scan flow: target → profile → confirm → live progress → result."""
from __future__ import annotations

import logging
import time

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from engine.models import Finding, ScanJob, ScanProfile
from engine.runner import Engine
from engine.scope import ScopeGate
from engine.store import Store

from .. import keyboards
from ..callbacks import JobCB, MenuCB, ScanCB
from ..render import PROFILE_RU, summary
from ..states import ScanFlow
from ..utils import safe_edit, safe_edit_message

log = logging.getLogger(__name__)
router = Router(name="scan")

# Minimum seconds between progress edits (Telegram rate-limit protection).
PROGRESS_MIN_INTERVAL = 2.0


def scope_targets(scope_gate: ScopeGate) -> list[str]:
    """Explicit single-host targets offered as buttons (CIDRs use manual entry)."""
    return sorted(scope_gate.config.allowed_hosts)


# ----------------------------------------------------------------- step 1: target
@router.callback_query(MenuCB.filter(F.action == "scan"))
async def start_flow(query: CallbackQuery, state: FSMContext, scope_gate: ScopeGate) -> None:
    await state.clear()
    await state.set_state(ScanFlow.choosing_target)
    targets = scope_targets(scope_gate)
    hint = "" if targets else "\n\n<i>В scope нет именованных хостов — введите цель вручную.</i>"
    await safe_edit(
        query,
        "🎯 <b>Новый скан</b>\n\nШаг 1/3 — выберите цель:" + hint,
        keyboards.target_choice(targets),
    )
    await query.answer()


@router.callback_query(ScanCB.filter((F.step == "target") & (F.value != "")),
                       ScanFlow.choosing_target)
@router.callback_query(ScanCB.filter((F.step == "target") & (F.value != "")),
                       ScanFlow.choosing_profile)
async def pick_target(query: CallbackQuery, callback_data: ScanCB,
                      state: FSMContext, scope_gate: ScopeGate) -> None:
    targets = scope_targets(scope_gate)
    try:
        target = targets[int(callback_data.value)]
    except (ValueError, IndexError):
        await query.answer("Цель недоступна, выберите заново.", show_alert=True)
        return
    await state.update_data(target=target)
    await _show_profile_step(query, state, target)


@router.callback_query(ScanCB.filter((F.step == "target") & (F.value == "")))
async def back_to_target(query: CallbackQuery, state: FSMContext,
                         scope_gate: ScopeGate) -> None:
    """◀️ Назад from the profile step."""
    await state.set_state(ScanFlow.choosing_target)
    await safe_edit(
        query,
        "🎯 <b>Новый скан</b>\n\nШаг 1/3 — выберите цель:",
        keyboards.target_choice(scope_targets(scope_gate)),
    )
    await query.answer()


# --------------------------------------------------------------- manual target entry
@router.callback_query(ScanCB.filter(F.step == "manual"))
async def ask_manual(query: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(ScanFlow.entering_manual)
    await safe_edit(
        query,
        "✏️ Введите цель (IP или хост) одним сообщением.\n"
        "Цель будет проверена по scope перед запуском.",
        keyboards.back_to_menu(),
    )
    await query.answer()


@router.message(ScanFlow.entering_manual)
async def receive_manual(message: Message, state: FSMContext,
                         scope_gate: ScopeGate) -> None:
    target = (message.text or "").strip()
    if not target:
        await message.answer("Пустая цель. Введите IP или хост.")
        return

    # Pre-check scope so the user gets immediate feedback on a rejected target.
    actor_id = message.from_user.id if message.from_user else None
    decision = scope_gate.check(target, actor_id=actor_id)
    if not decision.allowed:
        await message.answer(
            f"⛔ <b>REJECTED</b>: <code>{target}</code>\n"
            f"Причина: {decision.reason}\n\n"
            "Инструменты не запускались. Событие записано в audit.",
            reply_markup=keyboards.back_to_menu(),
        )
        await state.clear()
        return

    await state.update_data(target=target)
    sent = await message.answer("…")
    # Reuse the profile-step renderer against the freshly sent message.
    await _show_profile_step_message(sent, state, target)


# ------------------------------------------------------------- step 2: profile
async def _show_profile_step(query: CallbackQuery, state: FSMContext, target: str) -> None:
    await state.set_state(ScanFlow.choosing_profile)
    await safe_edit(
        query,
        f"🎯 Цель: <code>{target}</code>\n\nШаг 2/3 — выберите профиль:",
        keyboards.profile_choice(),
    )
    await query.answer()


async def _show_profile_step_message(message: Message, state: FSMContext, target: str) -> None:
    await state.set_state(ScanFlow.choosing_profile)
    await safe_edit_message(
        message,
        f"🎯 Цель: <code>{target}</code>\n\nШаг 2/3 — выберите профиль:",
        keyboards.profile_choice(),
    )


@router.callback_query(ScanCB.filter((F.step == "profile") & (F.value != "")),
                       ScanFlow.choosing_profile)
async def pick_profile(query: CallbackQuery, callback_data: ScanCB,
                       state: FSMContext) -> None:
    try:
        profile = ScanProfile(callback_data.value)
    except ValueError:
        await query.answer("Неизвестный профиль.", show_alert=True)
        return
    await state.update_data(profile=profile.value)
    await _show_confirm(query, state)


@router.callback_query(ScanCB.filter((F.step == "profile") & (F.value == "")))
async def back_to_profile(query: CallbackQuery, state: FSMContext) -> None:
    """◀️ Назад from the confirm step."""
    data = await state.get_data()
    target = data.get("target", "?")
    await _show_profile_step(query, state, target)


# ------------------------------------------------------------- step 3: confirm
async def _show_confirm(query: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(ScanFlow.confirming)
    data = await state.get_data()
    target = data.get("target", "?")
    profile = data.get("profile", "?")
    profile_ru = PROFILE_RU.get(profile, profile)
    await safe_edit(
        query,
        "✅ <b>Подтверждение</b>\n\n"
        f"Цель: <code>{target}</code>\n"
        f"Профиль: {profile_ru}\n\n"
        "Запустить скан?",
        keyboards.confirm(),
    )
    await query.answer()


# ------------------------------------------------------------------ run / launch
@router.callback_query(ScanCB.filter(F.step == "run"), ScanFlow.confirming)
async def run_scan(query: CallbackQuery, state: FSMContext,
                   engine: Engine) -> None:
    data = await state.get_data()
    target = data.get("target")
    profile_raw = data.get("profile")
    await state.clear()

    if not target or not profile_raw:
        await query.answer("Сессия истекла, начните заново.", show_alert=True)
        return
    profile = ScanProfile(profile_raw)
    actor_id = query.from_user.id if query.from_user else None

    await _launch(query.message, target, profile, actor_id, engine)
    await query.answer("Скан поставлен в очередь")


@router.callback_query(JobCB.filter(F.action == "repeat"))
async def repeat_scan(query: CallbackQuery, callback_data: JobCB,
                      engine: Engine, store: Store) -> None:
    job = store.get_job(callback_data.job_id)
    if job is None:
        await query.answer("Job не найден.", show_alert=True)
        return
    actor_id = query.from_user.id if query.from_user else None
    await _launch(query.message, job.target, job.profile, actor_id, engine)
    await query.answer("Повтор поставлен в очередь")


async def _launch(message: Message, target: str, profile: ScanProfile,
                  actor_id: int | None, engine: Engine) -> None:
    """Enqueue a scan and wire up live progress + result callbacks on ``message``."""
    # Mutable cell to throttle progress edits to PROGRESS_MIN_INTERVAL.
    last_edit = {"t": 0.0}

    async def on_progress(job: ScanJob, stage_name: str, idx: int, total: int) -> None:
        now = time.monotonic()
        if now - last_edit["t"] < PROGRESS_MIN_INTERVAL:
            return
        last_edit["t"] = now
        await safe_edit_message(
            message,
            f"▶️ <b>{target}</b> · скан #{job.id}\n"
            f"Этап {idx}/{total}: <b>{stage_name}</b>…",
            None,
        )

    async def on_done(job: ScanJob, findings: list[Finding]) -> None:
        await safe_edit_message(
            message,
            summary(job, findings),
            keyboards.result_actions(job.id),
        )

    job = engine.enqueue(target, profile, actor_id,
                         on_progress=on_progress, on_done=on_done)

    if job.status.value == "REJECTED":
        await safe_edit_message(
            message,
            f"⛔ <b>REJECTED</b>: <code>{target}</code>\n"
            f"Причина: {job.error}\n\nИнструменты не запускались.",
            keyboards.back_to_menu(),
        )
        return

    await safe_edit_message(
        message,
        f"⏳ Скан #{job.id} для <code>{target}</code> поставлен в очередь "
        f"(позиция в очереди: {engine.queue_size}).",
        None,
    )
