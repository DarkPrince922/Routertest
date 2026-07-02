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

from engine.discovery import subnet_host_count
from engine.models import Finding, ScanJob, ScanProfile
from engine.runner import SCANNABLE_PORTS, Engine
from engine.runtime import get_config
from engine.scope import ScopeGate
from engine.store import Store

from .. import keyboards
from ..callbacks import JobCB, MenuCB, ScanCB
from ..render import (
    PROFILE_RU,
    alert_text,
    batch_summary,
    esc,
    stage_done_lines,
    stage_start_line,
    summary,
)
from ..states import ScanFlow
from ..targets import MAX_TARGETS, is_cidr, parse_targets
from ..utils import safe_edit, safe_edit_message

log = logging.getLogger(__name__)
router = Router(name="scan")

# Reject uploads larger than this (bytes) before downloading the body.
MAX_FILE_BYTES = 10_000_000

# batch_key (aggregate message id) -> control object, for live stop-all.
_BATCHES: dict[int, "_BatchControl"] = {}


def _open_ports(findings: list[Finding]) -> list[int]:
    """Open TCP ports parsed out of the nmap stage's port findings."""
    ports: list[int] = []
    for f in findings:
        if f.stage == "nmap":
            try:
                ports.append(int(f.detail.get("port", "")))
            except (TypeError, ValueError):
                continue
    return ports


def _make_alert(message: Message):
    """Build an on_alert callback that pushes a notification into the chat."""
    async def on_alert(job: ScanJob, finding: Finding, device_label: str) -> None:
        try:
            await message.answer(alert_text(job, finding, device_label))
        except Exception:  # noqa: BLE001 - a failed alert must not break the scan
            log.debug("alert send failed", exc_info=True)
    return on_alert


def scope_targets(scope_gate: ScopeGate) -> list[str]:
    """Targets offered as buttons: named hosts + allowed CIDR subnets."""
    hosts = sorted(scope_gate.config.allowed_hosts)
    cidrs = [str(c) for c in scope_gate.config.allowed_cidrs]
    return hosts + cidrs


def _targets_label(targets: list[str]) -> str:
    """Human label for one or many targets, used on profile/confirm screens."""
    if len(targets) == 1:
        t = targets[0]
        if is_cidr(t):
            n = subnet_host_count(t)
            return f"🌐 Подсеть: <code>{t}</code> ({n} адресов)"
        return f"🎯 Цель: <code>{t}</code>"
    subnets = sum(1 for t in targets if is_cidr(t))
    hosts = len(targets) - subnets
    parts = []
    if hosts:
        parts.append(f"хостов: {hosts}")
    if subnets:
        parts.append(f"подсетей: {subnets}")
    preview = ", ".join(targets[:3])
    more = f" … (+{len(targets) - 3})" if len(targets) > 3 else ""
    return f"🎯 Целей: <b>{len(targets)}</b> ({', '.join(parts)})\n<code>{preview}{more}</code>"


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
        "✏️ Введите цель одним сообщением:\n"
        "• IP или хост — <code>192.168.1.1</code>\n"
        "• подсеть (CIDR) — <code>192.168.7.0/24</code> "
        "(найду живые хосты и просканирую их)\n\n"
        "Цель проверяется по scope перед запуском.",
        keyboards.back_to_menu(),
    )
    await query.answer()


@router.message(ScanFlow.entering_manual)
async def receive_manual(message: Message, state: FSMContext,
                         scope_gate: ScopeGate) -> None:
    raw = (message.text or "").strip()
    if not raw:
        await message.answer("Пусто. Введите IP, хост или подсеть(и) — можно несколько "
                             "через пробел/запятую/с новой строки.")
        return

    # Accept one or many tokens: hosts, IPs and CIDR subnets, mixed.
    targets, skipped, truncated = parse_targets(raw)
    if not targets:
        await message.answer("Не распознал ни одной валидной цели (IP/хост/CIDR). "
                             "Попробуйте ещё раз.")
        return

    actor_id = message.from_user.id if message.from_user else None

    # Single plain host → pre-check scope for immediate feedback.
    if len(targets) == 1 and not is_cidr(targets[0]):
        decision = scope_gate.check(targets[0], actor_id=actor_id)
        if not decision.allowed:
            await message.answer(
                f"⛔ <b>REJECTED</b>: <code>{targets[0]}</code>\n"
                f"Причина: {decision.reason}\n\nИнструменты не запускались.",
                reply_markup=keyboards.back_to_menu())
            await state.clear()
            return

    await state.update_data(targets=targets)
    note = ""
    if skipped or truncated:
        bits = []
        if skipped:
            bits.append(f"пропущено невалидных: {skipped}")
        if truncated:
            bits.append(f"обрезано по лимиту: {truncated}")
        note = "\n<i>" + "; ".join(bits) + "</i>"
    sent = await message.answer(f"Принято целей: <b>{len(targets)}</b>{note}")
    await _show_profile_step_message(sent, state, targets)


# ----------------------------------------------------------------- TXT batch upload
@router.callback_query(ScanCB.filter(F.step == "file"))
async def ask_file(query: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(ScanFlow.entering_file)
    await safe_edit(
        query,
        "📄 Пришлите <b>.txt</b> файл со списком целей — по одной на строку "
        "(можно через запятую/пробел). Поддерживаются <b>IP, хосты и подсети</b> "
        "(CIDR), вперемешку:\n"
        "<code>192.168.0.0/24\n192.168.4.0/24\n10.0.0.5  myrouter.local</code>\n\n"
        "Подсети прозваниваются, сканируются только живые хосты. Строки с "
        "<code>#</code> игнорируются. Каждая цель проходит проверку scope.",
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
async def run_scan(query: CallbackQuery, state: FSMContext, engine: Engine,
                   scope_gate: ScopeGate) -> None:
    data = await state.get_data()
    targets = data.get("targets") or []
    profile_raw = data.get("profile")
    await state.clear()

    if not targets or not profile_raw:
        await query.answer("Сессия истекла, начните заново.", show_alert=True)
        return
    profile = ScanProfile(profile_raw)
    actor_id = query.from_user.id if query.from_user else None

    if len(targets) == 1 and not is_cidr(targets[0]):
        await _launch_single(query.message, targets[0], profile, actor_id, engine)
        await query.answer("Скан поставлен в очередь")
    else:
        await query.answer("Запускаю…")
        await _launch_targets(query.message, targets, profile, actor_id, engine, scope_gate)


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


class _Narrative:
    """Builds one growing, human-readable progress message for a single scan."""

    def __init__(self, message: Message, target: str) -> None:
        self._message = message
        self._target = target
        self._job_id: int | None = None
        self._lines: list[str] = []        # finished step result lines
        self._current: str | None = None   # the in-progress "doing…" line
        self._lock = asyncio.Lock()

    def _text(self) -> str:
        head = f"🎯 <b>{esc(self._target)}</b>"
        if self._job_id is not None:
            head += f" · скан #{self._job_id}"
        parts = [head, ""]
        parts.extend(self._lines)
        if self._current:
            parts.append(self._current)
        return "\n".join(parts)

    def _kb(self):
        return keyboards.scan_running(self._job_id) if self._job_id else None

    async def queued(self, job_id: int, qsize: int) -> None:
        async with self._lock:
            self._job_id = job_id
            self._current = (f"⏳ В очереди (позиция {qsize})…" if qsize
                             else "⏳ Запускаю…")
            await safe_edit_message(self._message, self._text(), self._kb())

    async def on_progress(self, job: ScanJob, stage: str, idx: int, total: int) -> None:
        async with self._lock:
            self._job_id = job.id
            self._current = stage_start_line(stage)
            await safe_edit_message(self._message, self._text(), self._kb())

    async def on_stage_done(self, job: ScanJob, stage: str,
                            findings: list[Finding], idx: int, total: int) -> None:
        async with self._lock:
            self._current = None
            self._lines.extend(stage_done_lines(stage, findings))
            await safe_edit_message(self._message, self._text(), self._kb())


async def _launch_single(message: Message, target: str, profile: ScanProfile,
                         actor_id: int | None, engine: Engine) -> None:
    """Enqueue one scan with a live narrative + final result summary."""
    narrative = _Narrative(message, target)

    async def on_done(job: ScanJob, findings: list[Finding]) -> None:
        await safe_edit_message(message, summary(job, findings),
                                keyboards.result_actions(job.id))

    job = engine.enqueue(
        target, profile, actor_id,
        on_progress=narrative.on_progress,
        on_stage_done=narrative.on_stage_done,
        on_done=on_done,
        on_alert=_make_alert(message),
    )

    if job.status.value == "REJECTED":
        await safe_edit_message(
            message,
            f"⛔ <b>REJECTED</b>: <code>{target}</code>\n"
            f"Причина: {job.error}\n\nИнструменты не запускались.",
            keyboards.back_to_menu(),
        )
        return

    await narrative.queued(job.id, engine.queue_size)


@router.callback_query(JobCB.filter(F.action == "stop"))
async def stop_scan(query: CallbackQuery, callback_data: JobCB, engine: Engine) -> None:
    ok = engine.request_cancel(callback_data.job_id)
    await query.answer("⏹️ Останавливаю скан…" if ok else "Скан уже завершён.",
                       show_alert=not ok)


@router.callback_query(JobCB.filter(F.action == "stopbatch"))
async def stop_batch(query: CallbackQuery, callback_data: JobCB, engine: Engine) -> None:
    ctrl = _BATCHES.get(callback_data.job_id)
    if ctrl is None:
        await query.answer("Активных сканов нет.", show_alert=True)
        return
    ctrl.stopped = True
    # Stop discovery (so no new hosts get queued) and cancel everything running.
    for task in ctrl.discovery_tasks:
        task.cancel()
    cancelled = sum(1 for jid in list(ctrl.job_ids) if engine.request_cancel(jid))
    await query.answer(
        f"⏹️ Останавливаю всё ({cancelled})" if cancelled else "Останавливаю…",
        show_alert=bool(cancelled))


# Min seconds between throttled batch message edits (Telegram rate limit).
_BATCH_RENDER_INTERVAL = 2.0

# Compact "doing now" labels for the batch aggregate view.
_BATCH_DOING = {
    "nmap": "сканирую порты",
    "cve_detect": "сверяю CVE по модели",
    "vulners": "сверяю версии с CVE",
    "nuclei": "проверяю уязвимости",
    "routersploit": "проверяю креды",
    "hydra": "брутфорс логинов",
    "metasploit": "проверяю эксплойты",
    "verify": "перепроверяю CVE",
}


class _BatchControl:
    """Per-batch control: job ids (for stop-all), a stop flag, discovery tasks."""

    def __init__(self) -> None:
        self.job_ids: list[int] = []
        self.stopped: bool = False
        self.discovery_tasks: list[asyncio.Task] = []


class _BatchTracker:
    """Aggregates many jobs into one live message: progress, current targets,
    not-router notices, and a final combined summary."""

    def __init__(self, message: Message, profile: ScanProfile, batch_key: int,
                 control: _BatchControl) -> None:
        self._message = message
        self._profile = profile
        self._batch_key = batch_key
        self._control = control
        self._lock = asyncio.Lock()
        self._results: list[tuple[ScanJob, list[Finding]]] = []
        self._rejected: list[tuple[str, str]] = []
        self._total: int | None = None   # accepted count, set on finalize
        self._active: dict[int, str] = {}  # job_id -> current status line
        self._device: dict[int, str] = {}  # job_id -> detected model
        self.discovering: bool = False    # True while a subnet sweep is running
        self._last_render: float = 0.0

    @property
    def job_ids(self) -> list[int]:
        return self._control.job_ids

    async def touch(self) -> None:
        """Re-render (throttled) — used to reflect discovery progress live."""
        async with self._lock:
            await self._render()

    # ---- live per-job events -------------------------------------------------
    async def on_progress(self, job: ScanJob, stage: str, idx: int, total: int) -> None:
        async with self._lock:
            self._active[job.id] = self._line(job, _BATCH_DOING.get(stage, stage) + "…")
            await self._render()

    async def on_stage_done(self, job: ScanJob, stage: str,
                            findings: list[Finding], idx: int, total: int) -> None:
        async with self._lock:
            if stage == "nmap":
                fp = next((f for f in findings if f.stage == "fingerprint"), None)
                if fp is not None:
                    verdict = fp.detail.get("verdict", "unknown")
                    # Mirror the runner's gate: a host with any open scannable port
                    # is scanned regardless of the device-type guess, so don't show
                    # a "пропускаю" notice for it (it would contradict the scan).
                    scannable = any(p in SCANNABLE_PORTS for p in _open_ports(findings))
                    if verdict == "router":
                        self._device[job.id] = (fp.detail.get("os_name")
                                                or fp.detail.get("vendor") or "роутер")
                    elif verdict == "not_router" and not scannable:
                        self._active[job.id] = f"<code>{esc(job.target)}</code> — 🚫 не роутер, пропускаю"
                        await self._render()
                        return
                    elif (verdict == "unknown" and get_config().skip_unknown
                          and not scannable):
                        self._active[job.id] = f"<code>{esc(job.target)}</code> — ❔ тип не определён, пропускаю"
                        await self._render()
                        return
            await self._render()

    async def on_done(self, job: ScanJob, findings: list[Finding]) -> None:
        async with self._lock:
            self._active.pop(job.id, None)
            self._device.pop(job.id, None)
            self._results.append((job, findings))
            await self._render()

    async def finalize(self, accepted: int, rejected: list[tuple[str, str]]) -> None:
        async with self._lock:
            self._total = accepted
            self._rejected = rejected
            self.discovering = False
            await self._render(force=True)

    # ---- rendering -----------------------------------------------------------
    def _line(self, job: ScanJob, doing: str) -> str:
        dev = self._device.get(job.id)
        dev_tag = f" · 🧭 {esc(dev)}" if dev else ""
        return f"<code>{esc(job.target)}</code>{dev_tag} — {doing}"

    async def _render(self, force: bool = False) -> None:
        done = len(self._results)
        complete = self._total is not None and done >= self._total
        if complete:
            _BATCHES.pop(self._batch_key, None)
            await safe_edit_message(
                self._message,
                batch_summary(self._profile, self._results, self._rejected),
                keyboards.batch_done(),
            )
            return

        # Throttle intermediate edits (Telegram rate limit) — always render the
        # final/complete state above, but coalesce the noisy ones.
        now = time.monotonic()
        if not force and now - self._last_render < _BATCH_RENDER_INTERVAL:
            return
        self._last_render = now

        queued = len(self._control.job_ids)
        profile_ru = PROFILE_RU.get(self._profile.value, self._profile.value)
        lines = [f"📋 <b>Пакетный скан</b> · профиль: {profile_ru}"]
        if self.discovering:
            lines.append(f"🔎 Поиск живых хостов… найдено: <b>{queued}</b>, "
                         f"просканировано: {done}")
        else:
            total = "?" if self._total is None else self._total
            lines.append(f"Готово: {done}/{total}")
        if self._active:
            lines.append("▶️ Сейчас:")
            for status in list(self._active.values())[:5]:
                lines.append(f"  • {status}")
        await safe_edit_message(self._message, "\n".join(lines),
                                keyboards.batch_running(self._batch_key))


async def _launch_targets(message: Message, tokens: list[str], profile: ScanProfile,
                          actor_id: int | None, engine: Engine,
                          scope_gate: ScopeGate) -> None:
    """Unified batch launch for any mix of plain hosts and CIDR subnets.

    Plain hosts are queued directly; each subnet is ping-swept and its live hosts
    are queued the moment they're found. A single aggregate message tracks it all,
    and the stop button cancels discovery + every queued/running scan instantly.
    """
    batch_key = message.message_id
    control = _BatchControl()
    _BATCHES[batch_key] = control
    tracker = _BatchTracker(message, profile, batch_key, control)
    alert = _make_alert(message)
    rejected: list[tuple[str, str]] = []

    cidrs = [t for t in tokens if is_cidr(t)]
    hosts = [t for t in tokens if not is_cidr(t)]

    await safe_edit_message(
        message,
        ("🔎 Ищу живые хосты и сразу ставлю в очередь…" if cidrs
         else f"📋 Ставлю в очередь {len(hosts)} целей…"),
        keyboards.batch_running(batch_key))

    async def add(target: str) -> None:
        if control.stopped:
            return
        job = engine.enqueue(target, profile, actor_id,
                             on_progress=tracker.on_progress,
                             on_stage_done=tracker.on_stage_done,
                             on_done=tracker.on_done, on_alert=alert,
                             light=True)  # batch/subnet → skip heaviest stages
        if job.status.value == "REJECTED":
            rejected.append((target, job.error or "вне scope"))
        else:
            control.job_ids.append(job.id)
            # Reflect discovery progress live (throttled inside the tracker).
            await tracker.touch()

    # Direct hosts first.
    for host in hosts:
        if control.stopped:
            break
        await add(host)

    # Then sweep each subnet, queuing live hosts as they stream in.
    # Economy mode: scan each subnet's hosts to completion before sweeping the
    # next, so the box never juggles a discovery sweep + a full scan queue.
    economy = get_config().economy
    if cidrs:
        tracker.discovering = True
    for cidr in cidrs:
        if control.stopped:
            break
        decision = scope_gate.check_network(cidr, actor_id=actor_id)
        if not decision.allowed:
            rejected.append((cidr, decision.reason))
            continue
        before = len(control.job_ids)
        tracker.discovering = True
        await tracker.touch()
        task = asyncio.ensure_future(engine.discover_hosts_stream(cidr, add))
        control.discovery_tasks.append(task)
        try:
            await task
        except asyncio.CancelledError:
            break
        if economy and not control.stopped:
            # Drain this subnet's freshly-queued hosts before the next sweep.
            tracker.discovering = False
            await tracker.touch()
            new_ids = control.job_ids[before:]
            if new_ids:
                await engine.wait_jobs_done(new_ids)
    tracker.discovering = False

    if not control.job_ids:
        note = ("остановлено" if control.stopped
                else "живых/доступных целей не найдено")
        await safe_edit_message(
            message, f"🌐 Готово: {note}. Поставлено в очередь: 0.",
            keyboards.back_to_menu())
        _BATCHES.pop(batch_key, None)
        return

    # Declare the final expected count so the tracker renders its summary once
    # every queued host completes.
    await tracker.finalize(len(control.job_ids), rejected)
