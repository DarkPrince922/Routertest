"""Live worker-pool resize (⚙️ Настройки → 🧵 Потоки)."""
from __future__ import annotations

import asyncio

from engine.runner import MAX_WORKERS, Engine


def _engine(n):
    # ScopeGate/Store aren't touched by the pool logic here; pass None safely
    # since we only exercise spawn/retire bookkeeping.
    eng = Engine.__new__(Engine)
    eng._store = None
    eng._scope = None
    eng._desired = n
    eng._queue = asyncio.Queue()
    eng._workers = []
    eng._worker_seq = 0
    eng._running_count = 0
    eng._started = False
    eng._cancel_requested = set()
    eng._running_stage = {}
    return eng


def test_grow_and_shrink_pool():
    async def scenario():
        eng = _engine(2)
        eng.start()
        assert eng.max_concurrent == 2
        await asyncio.sleep(0)  # let workers reach queue.get()
        live = sum(1 for w in eng._workers if not w.done())
        assert live == 2

        # grow to 5
        eng.set_max_concurrent(5)
        await asyncio.sleep(0)
        assert eng.max_concurrent == 5
        assert sum(1 for w in eng._workers if not w.done()) == 5

        # shrink to 2 — 3 retire sentinels drain idle workers
        eng.set_max_concurrent(2)
        await asyncio.sleep(0.05)
        assert eng.max_concurrent == 2
        assert sum(1 for w in eng._workers if not w.done()) == 2

        await eng.stop()

    asyncio.run(scenario())


def test_clamped_to_bounds():
    eng = _engine(2)
    assert eng.set_max_concurrent(999) == MAX_WORKERS
    assert eng.set_max_concurrent(0) == 1
