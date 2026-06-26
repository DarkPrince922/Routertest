"""Typed callback_data factories for all inline buttons.

Keeping every callback in one place makes the button-driven UX easy to audit and
avoids stringly-typed callback parsing scattered across handlers.
"""
from __future__ import annotations

from aiogram.filters.callback_data import CallbackData


class MenuCB(CallbackData, prefix="menu"):
    """Top-level navigation. action ∈ main/scan/history/scope/status."""

    action: str


class ScanCB(CallbackData, prefix="scan"):
    """Scan flow steps. step ∈ target/manual/profile/confirm/run.

    ``value`` carries the chosen target index, profile name, etc. (empty when
    not needed).
    """

    step: str
    value: str = ""


class JobCB(CallbackData, prefix="job"):
    """Per-job actions. action ∈ view/json/repeat."""

    action: str
    job_id: int
    page: int = 0


class PageCB(CallbackData, prefix="page"):
    """Pagination. scope ∈ history/findings; ref is the job id for findings."""

    scope: str
    page: int
    ref: int = 0
