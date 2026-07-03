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
from .handlers import settings as settings_handlers
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
    db_mc = store.get_setting("max_concurrent")
    max_concurrent = int(db_mc) if (db_mc and db_mc.isdigit()) else settings.max_concurrent
    engine = Engine(store, scope_gate, max_concurrent=max_concurrent)
    # Persist the effective value so the settings screen can display it.
    store.set_setting("max_concurrent", str(engine.max_concurrent))

    # Engine runtime config (proxy, routersploit mode) for the stages.
    # In-bot settings (DB) take precedence over .env defaults so they persist
    # across restarts.
    db_proxy = store.get_setting("scan_proxy", settings.scan_proxy or "")
    db_rsf = store.get_setting("rsf_default_only")
    rsf_default_only = (db_rsf == "true") if db_rsf is not None else settings.rsf_default_only
    db_skip = store.get_setting("skip_unknown")
    skip_unknown = (db_skip == "true") if db_skip is not None else settings.skip_unknown
    port_scanner = store.get_setting("port_scanner", settings.port_scanner) or "auto"
    discovery_method = store.get_setting("discovery_method", settings.discovery_method) or "auto"
    db_msf = store.get_setting("metasploit_enabled")
    metasploit_enabled = (db_msf == "true") if db_msf is not None else settings.metasploit_enabled
    db_eco = store.get_setting("economy")
    economy = (db_eco == "true") if db_eco is not None else settings.economy
    db_cve = store.get_setting("cve_active")
    cve_active = (db_cve == "true") if db_cve is not None else settings.cve_active
    db_vuln = store.get_setting("vulners_enabled")
    vulners_enabled = (db_vuln == "true") if db_vuln is not None else settings.vulners_enabled
    configure(EngineConfig(
        proxy=(db_proxy or None),
        rsf_default_only=rsf_default_only,
        skip_unknown=skip_unknown,
        port_scanner=port_scanner,
        masscan_rate=settings.masscan_rate,
        nuclei_tags=settings.nuclei_tags,
        nuclei_concurrency=settings.nuclei_concurrency,
        nmap_fast=settings.nmap_fast,
        heavy_tool_limit=settings.heavy_tool_limit,
        discovery_method=discovery_method,
        discovery_rate=settings.discovery_rate,
        hydra_pass_list=settings.hydra_pass_list,
        metasploit_enabled=metasploit_enabled,
        economy=economy,
        cve_active=cve_active,
        vulners_enabled=vulners_enabled,
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
    dp.include_router(settings_handlers.router)

    engine.start()
    log.info("starting bot (engagement=%s, max_concurrent=%d)",
             scope_config.engagement_id, settings.max_concurrent)

    # Flag scans interrupted by the previous run; the user resumes them on
    # demand from ⚙️ Настройки (nothing runs automatically).
    interrupted = engine.mark_interrupted()
    if interrupted:
        log.info("%d interrupted scan(s) await manual resume", interrupted)

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
