"""History list, single-job detail with findings pagination, JSON + PDF export."""
from __future__ import annotations

import asyncio
import json
import logging

from aiogram import F, Router
from aiogram.types import BufferedInputFile, CallbackQuery

from engine.store import Store

log = logging.getLogger(__name__)

from .. import keyboards
from ..callbacks import JobCB, MenuCB, PageCB
from ..keyboards import FINDINGS_PAGE_SIZE, HISTORY_PAGE_SIZE
from ..render import findings_page, job_header
from ..utils import safe_edit

router = Router(name="history")


async def _render_history(query: CallbackQuery, store: Store, page: int) -> None:
    total = store.count_jobs()
    jobs = store.list_jobs(limit=HISTORY_PAGE_SIZE, offset=page * HISTORY_PAGE_SIZE)
    if not jobs and page == 0:
        await safe_edit(query, "📊 <b>История</b>\n\nПока нет ни одного скана.",
                        keyboards.back_to_menu())
        return
    await safe_edit(
        query,
        f"📊 <b>История</b> · всего {total}",
        keyboards.history_list(jobs, page, total),
    )


@router.callback_query(MenuCB.filter(F.action == "history"))
async def show_history(query: CallbackQuery, store: Store) -> None:
    await _render_history(query, store, page=0)
    await query.answer()


@router.callback_query(PageCB.filter(F.scope == "history"))
async def page_history(query: CallbackQuery, callback_data: PageCB, store: Store) -> None:
    await _render_history(query, store, page=callback_data.page)
    await query.answer()


@router.callback_query(JobCB.filter(F.action == "view"))
async def view_job(query: CallbackQuery, callback_data: JobCB, store: Store) -> None:
    await _render_job(query, store, callback_data.job_id, page=callback_data.page)
    await query.answer()


@router.callback_query(PageCB.filter(F.scope == "findings"))
async def page_findings(query: CallbackQuery, callback_data: PageCB, store: Store) -> None:
    await _render_job(query, store, callback_data.ref, page=callback_data.page)
    await query.answer()


async def _render_job(query: CallbackQuery, store: Store, job_id: int, page: int) -> None:
    job = store.get_job(job_id)
    if job is None:
        await safe_edit(query, "Job не найден.", keyboards.back_to_menu())
        return
    total = store.count_findings(job_id)
    breakdown = store.severity_breakdown(job_id)
    findings = store.get_findings_page(
        job_id, limit=FINDINGS_PAGE_SIZE, offset=page * FINDINGS_PAGE_SIZE)
    text = job_header(job) + "\n\n" + findings_page(findings, breakdown)
    await safe_edit(query, text, keyboards.job_detail(job_id, page, total))


@router.callback_query(JobCB.filter(F.action == "json"))
async def export_json(query: CallbackQuery, callback_data: JobCB, store: Store) -> None:
    data = store.export_job(callback_data.job_id)
    if data is None:
        await query.answer("Job не найден.", show_alert=True)
        return
    payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
    doc = BufferedInputFile(payload, filename=f"job_{callback_data.job_id}.json")
    if query.message is not None:
        await query.message.answer_document(
            doc, caption=f"📄 Полный отчёт по job #{callback_data.job_id}")
    await query.answer()


@router.callback_query(JobCB.filter(F.action == "pdf"))
async def export_pdf(query: CallbackQuery, callback_data: JobCB, store: Store) -> None:
    job = store.get_job(callback_data.job_id)
    if job is None:
        await query.answer("Job не найден.", show_alert=True)
        return
    await query.answer("📑 Готовлю PDF…")
    findings = store.get_findings(callback_data.job_id)
    try:
        # reportlab is heavy/synchronous — build off the event loop.
        from ..report_pdf import build_pdf
        payload = await asyncio.to_thread(build_pdf, job, findings)
    except ImportError:
        await query.answer(
            "PDF-движок не установлен. Обновите бота (update.sh переустановит "
            "зависимости).", show_alert=True)
        return
    except Exception:  # noqa: BLE001
        log.exception("PDF build failed for job %d", callback_data.job_id)
        await query.answer("Не удалось сформировать PDF.", show_alert=True)
        return
    doc = BufferedInputFile(payload, filename=f"report_{callback_data.job_id}.pdf")
    if query.message is not None:
        await query.message.answer_document(
            doc, caption=f"📑 Отчёт по скану #{callback_data.job_id} "
                         f"· {job.target}")
