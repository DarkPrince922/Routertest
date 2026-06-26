"""The new-scan flow: target(s) → profile → confirm → live progress → result.

Targets are always carried through the FSM as a list (``targets``). A single
selection is a list of one; a TXT upload is a list of many. ``run`` dispatches to
a single live-progress launch or a batched launch with an aggregate tracker.
"""
from __future__ import annotations

import asyncio
import io
import logging
import time

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from engine.models import Finding, ScanJob, ScanProfile
from engine.runner import Engine
from engine.scope import ScopeGate
from engine.store import Store

from .. import keyboards
from ..callbacks import JobCB, MenuCB, ScanCB
from ..render import PROFILE_RU, alert_text, batch_summary, summary
from ..states import ScanFlow
from ..targets import MAX_TARGETS, parse_targets
from ..utils import safe_edit, safe_edit_message

log = logging.getLogger(__name__)
router = Router(name="scan")

# Minimum seconds between progress edits (Telegram rate-limit protection).
PROGRESS_MIN_INTERVAL = 2.0
# Reject uploads larger than this (bytes) before downloading the body.
MAX_FILE_BYTES = 1_000_000

# batch_key (aggregate message id) -> list of that batch's job ids, for stop-all.
_BATCHES: dict[int, list[int]] = {}


def _make_alert(message: Message):
    """Build an on_alert callback that pushes a notification into the chat."""
    async def on_alert(job: ScanJob, finding: Finding, device_label: str) -> None:
        try:
            await message.answer(alert_text(job, finding, device_label))
        except Exception:  # noqa: BLE001 - a failed alert must not break the scan
            log.debug("alert send failed", exc_info=True)
    return on_alert


def scope_targets(scope_gate: ScopeGate) -> list[str]:
    """Explicit single-host targets offered as buttons (CIDRs use manual entry)."""
    return sorted(scope_gate.config.allowed_hosts)


def _targets_label(targets: list[str]) -> str:
    """Human label for one or many targets, used on profile/confirm screens."""
    if len(targets) == 1:
        return f"🎯 Цель: <code>{targets[0]}</code>"
    preview = ", ".join(targets[:3])
    more = f" … (+{len(targets) - 3})" if len(targets) > 3 else ""
    return f"🎯 Целей: <b>{len(targets)}</b>\n<code>{preview}{more}</code>"


# ----------------------------------------------------------------- step 1: target
@router.callback_query(MenuCB.filter(F.action == "scan"))
async def start_flow(query: CallbackQuery, state: FSMContext, scope_gate: ScopeGate) -> None:
    await state.clear()
    await state.set_state(ScanFlow.choosing_target)
    targets = scope_targets(scope_gate)
    hint = "" if targets else "\n\n<i>В scope нет именованных хостов — введите цель вручную или пришлите TXT.</i>"
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
    await state.update_data(targets=[target])
    await _show_profile_step(query, state, [target])


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

    await state.update_data(targets=[target])
    sent = await message.answer("…")
    await _show_profile_step_message(sent, state, [target])


# ----------------------------------------------------------------- TXT batch upload
@router.callback_query(ScanCB.filter(F.step == "file"))
async def ask_file(query: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(ScanFlow.entering_file)
    await safe_edit(
        query,
        "📄 Пришлите <b>.txt</b> файл со списком целей — по одной на строку "
        "(можно через запятую/пробел). Строки с <code>#</code> игнорируются.\n\n"
        f"Максимум {MAX_TARGETS} целей. Каждая проходит проверку scope перед запуском.",
        keyboards.back_to_menu(),
    )
    await query.answer()


@router.message(ScanFlow.entering_file, F.document)
async def receive_file(message: Message, state: FSMContext, bot: Bot) -> None:
    document = message.document
    if document.file_size and document.file_size > MAX_FILE_BYTES:
        await message.answer(
            f"Файл слишком большой (>{MAX_FILE_BYTES // 1000} КБ). "
            "Пришлите список поменьше.")
        return

    buf = io.BytesIO()
    try:
        await bot.download(document, destination=buf)
    except Exception as exc:  # noqa: BLE001
        log.warning("file download failed: %s", exc)
        await message.answer("Не удалось скачать файл, попробуйте ещё раз.")
        return

    try:
        text = buf.getvalue().decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        await message.answer("Не удалось прочитать файл как текст.")
        return

    targets, skipped, truncated = parse_targets(text)
    if not targets:
        await message.answer(
            "В файле не найдено валидных целей (IP или хостов). "
            f"Пропущено строк: {skipped}.",
            reply_markup=keyboards.back_to_menu(),
        )
        await state.clear()
        return

    await state.update_data(targets=targets)
    notes = []
    if skipped:
        notes.append(f"пропущено невалидных: {skipped}")
    if truncated:
        notes.append(f"⚠️ превышен лимит {MAX_TARGETS}: отброшено {truncated} "
                     f"(будут просканированы только первые {MAX_TARGETS})")
    note = ("\n<i>" + "; ".join(notes) + "</i>") if notes else ""
    sent = await message.answer(
        f"📄 Загружено целей: <b>{len(targets)}</b>{note}")
    await _show_profile_step_message(sent, state, targets)


@router.message(ScanFlow.entering_file)
async def file_wrong_type(message: Message) -> None:
    await message.answer("Ожидается .txt файл документом. Пришлите файл или вернитесь в меню.",
                         reply_markup=keyboards.back_to_menu())


# ------------------------------------------------------------- step 2: profile
async def _show_profile_step(query: CallbackQuery, state: FSMContext,
                             targets: list[str]) -> None:
    await state.set_state(ScanFlow.choosing_profile)
    await safe_edit(
        query,
        f"{_targets_label(targets)}\n\nШаг 2/3 — выберите профиль:",
        keyboards.profile_choice(),
    )
    await query.answer()


async def _show_profile_step_message(message: Message, state: FSMContext,
                                     targets: list[str]) -> None:
    await state.set_state(ScanFlow.choosing_profile)
    await safe_edit_message(
        message,
        f"{_targets_label(targets)}\n\nШаг 2/3 — выберите профиль:",
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
    targets = data.get("targets", [])
    await _show_profile_step(query, state, targets or ["?"])


# ------------------------------------------------------------- step 3: confirm
async def _show_confirm(query: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(ScanFlow.confirming)
    data = await state.get_data()
    targets = data.get("targets", [])
    profile = data.get("profile", "?")
    profile_ru = PROFILE_RU.get(profile, profile)
    await safe_edit(
        query,
        "✅ <b>Подтверждение</b>\n\n"
        f"{_targets_label(targets)}\n"
        f"Профиль: {profile_ru}\n\n"
        "Запустить скан?",
        keyboards.confirm(),
    )
    await query.answer()


# ------------------------------------------------------------------ run / launch
@router.callback_query(ScanCB.filter(F.step == "run"), ScanFlow.confirming)
async def run_scan(query: CallbackQuery, state: FSMContext, engine: Engine) -> None:
    data = await state.get_data()
    targets = data.get("targets") or []
    profile_raw = data.get("profile")
    await state.clear()

    if not targets or not profile_raw:
        await query.answer("Сессия истекла, начните заново.", show_alert=True)
        return
    profile = ScanProfile(profile_raw)
    actor_id = query.from_user.id if query.from_user else None

    if len(targets) == 1:
        await _launch_single(query.message, targets[0], profile, actor_id, engine)
        await query.answer("Скан поставлен в очередь")
    else:
        await _launch_batch(query.message, targets, profile, actor_id, engine)
        await query.answer(f"Поставлено в очередь: {len(targets)}")


@router.callback_query(JobCB.filter(F.action == "repeat"))
async def repeat_scan(query: CallbackQuery, callback_data: JobCB,
                      engine: Engine, store: Store) -> None:
    job = store.get_job(callback_data.job_id)
    if job is None:
        await query.answer("Job не найден.", show_alert=True)
        return
    actor_id = query.from_user.id if query.from_user else None
    await _launch_single(query.message, job.target, job.profile, actor_id, engine)
    await query.answer("Повтор поставлен в очередь")


async def _launch_single(message: Message, target: str, profile: ScanProfile,
                         actor_id: int | None, engine: Engine) -> None:
    """Enqueue one scan with live per-stage progress + result summary."""
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
            keyboards.scan_running(job.id),
        )

    async def on_done(job: ScanJob, findings: list[Finding]) -> None:
        await safe_edit_message(message, summary(job, findings),
                                keyboards.result_actions(job.id))

    job = engine.enqueue(target, profile, actor_id, on_progress=on_progress,
                         on_done=on_done, on_alert=_make_alert(message))

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
        keyboards.scan_running(job.id),
    )


@router.callback_query(JobCB.filter(F.action == "stop"))
async def stop_scan(query: CallbackQuery, callback_data: JobCB, engine: Engine) -> None:
    ok = engine.request_cancel(callback_data.job_id)
    await query.answer("⏹️ Останавливаю скан…" if ok else "Скан уже завершён.",
                       show_alert=not ok)


@router.callback_query(JobCB.filter(F.action == "stopbatch"))
async def stop_batch(query: CallbackQuery, callback_data: JobCB, engine: Engine) -> None:
    job_ids = list(_BATCHES.get(callback_data.job_id, []))
    cancelled = sum(1 for jid in job_ids if engine.request_cancel(jid))
    await query.answer(
        f"⏹️ Останавливаю: {cancelled}" if cancelled else "Активных сканов нет.",
        show_alert=not cancelled)


class _BatchTracker:
    """Aggregates many jobs into one live-updating summary message."""

    def __init__(self, message: Message, profile: ScanProfile, batch_key: int) -> None:
        self._message = message
        self._profile = profile
        self._batch_key = batch_key
        self._lock = asyncio.Lock()
        self._results: list[tuple[ScanJob, list[Finding]]] = []
        self._rejected: list[tuple[str, str]] = []
        self._total: int | None = None  # accepted count, set on finalize
        self.job_ids: list[int] = []     # shared with _BATCHES for stop-all

    async def on_done(self, job: ScanJob, findings: list[Finding]) -> None:
        async with self._lock:
            self._results.append((job, findings))
            await self._render()

    async def finalize(self, accepted: int, rejected: list[tuple[str, str]]) -> None:
        async with self._lock:
            self._total = accepted
            self._rejected = rejected
            await self._render()

    async def _render(self) -> None:
        done = len(self._results)
        complete = self._total is not None and done >= self._total
        if not complete:
            total = "?" if self._total is None else self._total
            await safe_edit_message(
                self._message,
                f"📋 <b>Пакетный скан</b> · профиль: {PROFILE_RU.get(self._profile.value, self._profile.value)}\n"
                f"Готово: {done}/{total}…",
                keyboards.batch_running(self._batch_key),
            )
        else:
            _BATCHES.pop(self._batch_key, None)
            await safe_edit_message(
                self._message,
                batch_summary(self._profile, self._results, self._rejected),
                keyboards.batch_done(),
            )


async def _launch_batch(message: Message, targets: list[str], profile: ScanProfile,
                        actor_id: int | None, engine: Engine) -> None:
    """Enqueue many scans; one aggregate message tracks completion."""
    batch_key = message.message_id
    tracker = _BatchTracker(message, profile, batch_key)
    _BATCHES[batch_key] = tracker.job_ids  # same list object — fills as we enqueue
    alert = _make_alert(message)
    rejected: list[tuple[str, str]] = []
    accepted = 0

    await safe_edit_message(
        message,
        f"📋 Ставлю в очередь {len(targets)} целей…",
        keyboards.batch_running(batch_key),
    )

    for target in targets:
        job = engine.enqueue(target, profile, actor_id,
                             on_done=tracker.on_done, on_alert=alert)
        if job.status.value == "REJECTED":
            rejected.append((target, job.error or "вне scope"))
        else:
            accepted += 1
            tracker.job_ids.append(job.id)

    # Set the expected count last so completion is only declared once every
    # accepted job is queued (a fast job's on_done can fire mid-loop).
    await tracker.finalize(accepted, rejected)
