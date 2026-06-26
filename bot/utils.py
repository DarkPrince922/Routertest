"""Telegram-side helpers: safe message editing that tolerates rate limits."""
from __future__ import annotations

import asyncio
import logging

from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.types import CallbackQuery, InlineKeyboardMarkup

log = logging.getLogger(__name__)


async def safe_edit(query: CallbackQuery, text: str,
                    markup: InlineKeyboardMarkup | None = None) -> None:
    """Edit the message behind a callback query, swallowing benign errors.

    Handles ``MessageNotModified`` (ignored) and ``TelegramRetryAfter`` (waits and
    retries once).
    """
    message = query.message
    if message is None:
        return
    try:
        await message.edit_text(text, reply_markup=markup)
    except TelegramRetryAfter as exc:
        await asyncio.sleep(exc.retry_after)
        try:
            await message.edit_text(text, reply_markup=markup)
        except TelegramBadRequest:
            pass
    except TelegramBadRequest as exc:
        # "message is not modified" is expected on no-op edits; ignore it.
        if "message is not modified" not in str(exc).lower():
            log.debug("edit_text failed: %s", exc)


async def safe_edit_message(message, text: str,
                            markup: InlineKeyboardMarkup | None = None) -> None:
    """Same as :func:`safe_edit` but for a raw Message (used by progress edits)."""
    try:
        await message.edit_text(text, reply_markup=markup)
    except TelegramRetryAfter as exc:
        await asyncio.sleep(exc.retry_after)
        try:
            await message.edit_text(text, reply_markup=markup)
        except TelegramBadRequest:
            pass
    except TelegramBadRequest as exc:
        if "message is not modified" not in str(exc).lower():
            log.debug("edit_text failed: %s", exc)
