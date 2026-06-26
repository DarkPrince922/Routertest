"""Shared helpers for stages — primarily the async subprocess runner."""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)


class ToolNotFound(RuntimeError):
    """Raised when an external tool binary is missing from PATH."""


async def run_cmd(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """Run ``cmd`` via asyncio subprocess, killing it after ``timeout`` seconds.

    Returns ``(returncode, stdout, stderr)``. Raises :class:`ToolNotFound` if the
    binary does not exist and :class:`asyncio.TimeoutError` on timeout (after the
    process is killed).
    """
    log.debug("run_cmd: %s (timeout=%ss)", " ".join(cmd), timeout)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ToolNotFound(f"binary not found: {cmd[0]}") from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        log.warning("run_cmd timeout, killing: %s", cmd[0])
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        raise

    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout_b.decode("utf-8", errors="replace"),
        stderr_b.decode("utf-8", errors="replace"),
    )
