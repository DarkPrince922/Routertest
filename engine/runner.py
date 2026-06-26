"""Engine — the scan queue, worker pool and per-stage execution.

The bot enqueues a job and returns immediately; a pool of ``MAX_CONCURRENT``
workers pulls jobs off an ``asyncio.Queue`` and runs their stages. Progress is
reported back through an async callback so the chat message can live-update.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from .models import (
    Finding,
    JobStatus,
    ScanJob,
    ScanProfile,
    Severity,
)
from .scope import ScopeGate
from .stages import nmap_stage, nuclei_stage, routersploit_stage
from .store import Store

log = logging.getLogger(__name__)

# A stage is an async callable: target -> list[Finding].
Stage = Callable[[str], Awaitable[list[Finding]]]
# Progress callback: (job, stage_name, index, total) -> awaitable.
ProgressCB = Callable[[ScanJob, str, int, int], Awaitable[None]]
# Completion callback: (job, findings) -> awaitable.
DoneCB = Callable[[ScanJob, list[Finding]], Awaitable[None]]

# Stages per profile (order matters).
PROFILE_STAGES: dict[ScanProfile, list[tuple[str, Stage]]] = {
    ScanProfile.QUICK: [("nmap", nmap_stage)],
    ScanProfile.STANDARD: [("nmap", nmap_stage), ("nuclei", nuclei_stage)],
    ScanProfile.FULL: [
        ("nmap", nmap_stage),
        ("nuclei", nuclei_stage),
        ("routersploit", routersploit_stage),
    ],
    # FIRMWARE is reserved for v2 (binwalk/EMBA) and intentionally has no stages.
    ScanProfile.FIRMWARE: [],
}


class _QueueItem:
    __slots__ = ("job", "on_progress", "on_done")

    def __init__(self, job: ScanJob, on_progress: ProgressCB | None,
                 on_done: DoneCB | None) -> None:
        self.job = job
        self.on_progress = on_progress
        self.on_done = on_done


class Engine:
    """Owns the queue, the worker tasks and stage dispatch."""

    def __init__(self, store: Store, scope_gate: ScopeGate, max_concurrent: int = 2) -> None:
        self._store = store
        self._scope = scope_gate
        self._max_concurrent = max(1, max_concurrent)
        self._queue: asyncio.Queue[_QueueItem] = asyncio.Queue()
        self._workers: list[asyncio.Task] = []
        self._running_count = 0
        self._started = False

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Spawn the worker pool (idempotent)."""
        if self._started:
            return
        self._started = True
        for i in range(self._max_concurrent):
            self._workers.append(asyncio.create_task(self._worker(i), name=f"scan-worker-{i}"))
        log.info("engine started with %d workers", self._max_concurrent)

    async def stop(self) -> None:
        for task in self._workers:
            task.cancel()
        for task in self._workers:
            with _suppress_cancel():
                await task
        self._workers.clear()
        self._started = False

    # --------------------------------------------------------------- enqueue
    def enqueue(self, target: str, profile: ScanProfile, actor_id: int | None,
                on_progress: ProgressCB | None = None,
                on_done: DoneCB | None = None) -> ScanJob:
        """Scope-check, create the job and enqueue it (or reject).

        Returns the created :class:`ScanJob`. A rejected target is persisted with
        status ``REJECTED`` and never enqueued — no tool is ever launched.
        """
        decision = self._scope.check(target, actor_id=actor_id)
        engagement_id = self._scope.engagement_id

        if not decision.allowed:
            job = self._store.create_job(target, profile, engagement_id,
                                         status=JobStatus.REJECTED)
            self._store.update_status(job.id, JobStatus.REJECTED,
                                      error=decision.reason, finished=True)
            self._store.add_findings(job.id, [
                Finding("scope", Severity.INFO, "Target rejected by ScopeGate",
                        {"reason": decision.reason, "resolved_ip": decision.resolved_ip})
            ])
            job.status = JobStatus.REJECTED
            job.error = decision.reason
            self._store.add_audit("job_rejected", actor_id=actor_id, target=target,
                                  resolved_ip=decision.resolved_ip, decision="REJECTED",
                                  engagement_id=engagement_id)
            return job

        job = self._store.create_job(target, profile, engagement_id,
                                     status=JobStatus.QUEUED)
        self._store.add_audit("job_queued", actor_id=actor_id, target=target,
                              resolved_ip=decision.resolved_ip, decision="QUEUED",
                              engagement_id=engagement_id)
        self._queue.put_nowait(_QueueItem(job, on_progress, on_done))
        return job

    # ---------------------------------------------------------------- status
    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def running_count(self) -> int:
        return self._running_count

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    # ---------------------------------------------------------------- worker
    async def _worker(self, worker_id: int) -> None:
        while True:
            item = await self._queue.get()
            self._running_count += 1
            try:
                await self._run_job(item)
            except Exception:  # noqa: BLE001 - a worker must never die
                log.exception("worker %d crashed handling job %d", worker_id, item.job.id)
            finally:
                self._running_count -= 1
                self._queue.task_done()

    async def _run_job(self, item: _QueueItem) -> None:
        job = item.job
        stages = PROFILE_STAGES.get(job.profile, [])
        total = len(stages)

        self._store.update_status(job.id, JobStatus.RUNNING)
        job.status = JobStatus.RUNNING
        self._store.add_audit("job_started", target=job.target,
                              decision="RUNNING", engagement_id=job.engagement_id)
        log.info("job %d started target=%s profile=%s", job.id, job.target, job.profile.value)

        all_findings: list[Finding] = []
        try:
            for idx, (name, stage) in enumerate(stages, start=1):
                if item.on_progress is not None:
                    await _safe(item.on_progress(job, name, idx, total))
                findings = await self._run_stage(name, stage, job.target)
                self._store.add_findings(job.id, findings)
                all_findings.extend(findings)

            self._store.update_status(job.id, JobStatus.DONE, finished=True)
            job.status = JobStatus.DONE
            log.info("job %d done: %d findings", job.id, len(all_findings))
        except Exception as exc:  # noqa: BLE001
            self._store.update_status(job.id, JobStatus.ERROR, error=str(exc), finished=True)
            job.status = JobStatus.ERROR
            job.error = str(exc)
            log.exception("job %d errored", job.id)

        self._store.add_audit("job_finished", target=job.target,
                              decision=job.status.value, engagement_id=job.engagement_id)
        if item.on_done is not None:
            await _safe(item.on_done(job, all_findings))

    async def _run_stage(self, name: str, stage: Stage, target: str) -> list[Finding]:
        """Run one stage; a failing stage yields an info Finding, never raises."""
        try:
            return await stage(target)
        except Exception as exc:  # noqa: BLE001 - one stage must not abort the scan
            log.exception("stage %s failed", name)
            return [Finding(name, Severity.INFO, f"stage {name} failed",
                            {"error": str(exc)})]


async def _safe(awaitable: Awaitable[None]) -> None:
    """Run a callback, swallowing/logging its errors (UI must not break a scan)."""
    try:
        await awaitable
    except Exception:  # noqa: BLE001
        log.exception("progress/done callback failed")


class _suppress_cancel:
    def __enter__(self) -> "_suppress_cancel":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is asyncio.CancelledError
