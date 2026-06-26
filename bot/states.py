"""FSM states for the scan flow."""
from __future__ import annotations

from aiogram.fsm.state import State, StatesGroup


class ScanFlow(StatesGroup):
    """States for: choose target → (manual entry) → choose profile → confirm."""

    choosing_target = State()
    entering_manual = State()
    entering_file = State()
    choosing_profile = State()
    confirming = State()


class SettingsFlow(StatesGroup):
    """States for the settings screen."""

    entering_proxy = State()
