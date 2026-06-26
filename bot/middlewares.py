"""Middlewares: admin allow-list guard and a simple anti-flood throttle.

The admin guard runs on EVERY update (messages and callback queries), not just
``/start`` — an unauthorized user is blocked at any handler and the refusal is
audited.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject, Update, User

from engine.store import Store

log = logging.getLogger(__name__)


class AdminGuardMiddleware(BaseMiddleware):
    """Reject any update from a user not in ``admin_ids``; audit the refusal."""

    def __init__(self, admin_ids: set[int], store: Store, engagement_id: str) -> None:
        self._admin_ids = admin_ids
        self._store = store
        self._engagement_id = engagement_id

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        user: User | None = data.get("event_from_user")
        if user is None and isinstance(event, Update):
            user = _user_from_update(event)

        if user is not None and user.id not in self._admin_ids:
            self._store.add_audit(
                "access_denied", actor_id=user.id, decision="DENIED",
                engagement_id=self._engagement_id,
            )
            log.warning("access denied for user_id=%s", user.id)
            await self._reject(event)
            return None
        return await handler(event, data)

    async def _reject(self, event: TelegramObject) -> None:
        text = "⛔ Доступ запрещён. Этот бот доступен только администраторам."
        inner = event.event if isinstance(event, Update) else event
        try:
            if isinstance(inner, CallbackQuery):
                await inner.answer(text, show_alert=True)
            elif isinstance(inner, Message):
                await inner.answer(text)
        except Exception:  # noqa: BLE001
            log.debug("failed to deliver rejection notice", exc_info=True)


class AntiFloodMiddleware(BaseMiddleware):
    """Per-user throttle for callback spam (button mashing)."""

    def __init__(self, rate_limit: float = 0.5) -> None:
        self._rate = rate_limit
        self._last: dict[int, float] = {}

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        if isinstance(event, CallbackQuery) and event.from_user is not None:
            now = time.monotonic()
            last = self._last.get(event.from_user.id, 0.0)
            if now - last < self._rate:
                with _suppress():
                    await event.answer("⏳ Слишком быстро, подождите…")
                return None
            self._last[event.from_user.id] = now
        return await handler(event, data)


def _user_from_update(update: Update) -> User | None:
    if update.message is not None:
        return update.message.from_user
    if update.callback_query is not None:
        return update.callback_query.from_user
    return None


class _suppress:
    def __enter__(self) -> "_suppress":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, Exception)
