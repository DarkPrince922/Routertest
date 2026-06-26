"""Bot entry point: wires settings, engine, middlewares and routers together."""
from __future__ import annotations

import asyncio
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from config import get_settings
from engine.runner import Engine
from engine.runtime import EngineConfig, configure
from engine.scope import ScopeConfig, ScopeGate
from engine.store import Store

from .handlers import history, menu, scan, scope
from .middlewares import AdminGuardMiddleware, AntiFloodMiddleware

log = logging.getLogger(__name__)


def setup_logging(level: str) -> None:
    Path("logs").mkdir(exist_ok=True)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    file_handler = RotatingFileHandler(
        "logs/app.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    handlers.append(file_handler)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )
    # aiogram is chatty at DEBUG; keep it at INFO+.
    logging.getLogger("aiogram.event").setLevel(logging.WARNING)


async def main() -> None:
    settings = get_settings()
    setup_logging(settings.log_level)

    if settings.token_is_placeholder:
        log.error("BOT_TOKEN is a placeholder — fill .env and restart. Exiting.")
        raise SystemExit(2)
    if not settings.admin_ids:
        log.warning("ADMIN_IDS is empty — NO ONE will be able to use the bot.")

    # Engine wiring (no Telegram dependency below this point).
    scope_config = ScopeConfig.load(settings.scope_path)
    store = Store(settings.db_path)
    scope_gate = ScopeGate(scope_config, store)
    engine = Engine(store, scope_gate, max_concurrent=settings.max_concurrent)

    # Engine runtime config (proxy, routersploit mode) for the stages.
    configure(EngineConfig(
        proxy=settings.scan_proxy or None,
        rsf_default_only=settings.rsf_default_only,
    ))

    bot = Bot(
        token=settings.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher(storage=MemoryStorage())

    # Inject shared dependencies into every handler that names them.
    dp["engine"] = engine
    dp["store"] = store
    dp["scope_gate"] = scope_gate

    # Middlewares: admin-guard FIRST (blocks non-admins), then anti-flood.
    admin_guard = AdminGuardMiddleware(settings.admin_ids, store, scope_config.engagement_id)
    anti_flood = AntiFloodMiddleware(rate_limit=0.5)
    for observer in (dp.message, dp.callback_query):
        observer.outer_middleware(admin_guard)
    dp.callback_query.outer_middleware(anti_flood)

    dp.include_router(menu.router)
    dp.include_router(scan.router)
    dp.include_router(history.router)
    dp.include_router(scope.router)

    engine.start()
    log.info("starting bot (engagement=%s, max_concurrent=%d)",
             scope_config.engagement_id, settings.max_concurrent)

    # Re-queue scans interrupted by a previous restart and tell the admins.
    recovered = engine.recover()
    if recovered:
        note = (f"♻️ После перезапуска возобновлено сканов: {len(recovered)}. "
                "Результаты появятся в «📊 История».")
        for admin_id in settings.admin_ids:
            try:
                await bot.send_message(admin_id, note)
            except Exception:  # noqa: BLE001 - admin may not have opened the bot
                log.debug("could not notify admin %s about recovery", admin_id)

    try:
        await dp.start_polling(bot)
    finally:
        await engine.stop()
        store.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
