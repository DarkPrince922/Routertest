"""Engine — the scan queue, worker pool and per-stage execution.

The bot enqueues a job and returns immediately; a pool of ``MAX_CONCURRENT``
workers pulls jobs off an ``asyncio.Queue`` and runs their stages. Progress is
reported back through async callbacks so the chat message can live-update.

Extra behaviours layered on the basic pipeline:
  * after nmap, the device-type verdict decides whether to skip the deeper
    router-oriented stages on a non-router target (status ``SKIPPED``);
  * a scan can be cancelled mid-flight (``request_cancel`` → status ``CANCELLED``);
  * high/critical findings trigger an immediate ``on_alert`` callback.
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
    severity_rank,
)
from .discovery import discover_hosts, discover_hosts_stream
from .runtime import get_config
from .scope import ScopeGate
from .stages import (
    cve_detect_stage,
    hydra_stage,
    metasploit_stage,
    nmap_stage,
    nuclei_stage,
    routersploit_stage,
    snmp_stage,
    verify_stage,
)
from .stages.nmap_stage import router_verdict
from .store import Store

log = logging.getLogger(__name__)

# A stage is an async callable: (target, shared_context) -> list[Finding].
# The context dict is threaded through a job's stages so later stages can use
# what earlier ones learned (e.g. routersploit reads the detected vendor).
Stage = Callable[[str, dict], Awaitable[list[Finding]]]
# Progress callback (a stage is about to run): (job, stage_name, index, total).
ProgressCB = Callable[[ScanJob, str, int, int], Awaitable[None]]
# Stage-done callback (a stage just finished): (job, stage_name, findings, idx, total).
StageDoneCB = Callable[[ScanJob, str, list[Finding], int, int], Awaitable[None]]
# Completion callback: (job, findings) -> awaitable.
DoneCB = Callable[[ScanJob, list[Finding]], Awaitable[None]]
# Alert callback for a high/critical finding: (job, finding, device_label).
AlertCB = Callable[[ScanJob, Finding, str], Awaitable[None]]

# Findings at or above this severity raise an immediate alert.
ALERT_THRESHOLD = severity_rank(Severity.HIGH)

# Hard backstop per stage — no single tool can hang a worker longer than this.
STAGE_TIMEOUT = 600.0

# Open ports that, by themselves, make a host worth scanning regardless of the
# nmap device-type guess (web UIs, login services, router-mgmt protocols). If any
# of these is open, the router gate never skips the host.
SCANNABLE_PORTS = {
    21, 22, 23, 53, 80, 81, 88, 443, 2000, 2222, 4433, 5000, 7547, 8000, 8080,
    8081, 8088, 8291, 8443, 8728, 8729, 8888, 9000, 9999, 10000, 49152, 52869,
}

# Stages per profile (order matters).
PROFILE_STAGES: dict[ScanProfile, list[tuple[str, Stage]]] = {
    ScanProfile.QUICK: [("nmap", nmap_stage)],
    ScanProfile.STANDARD: [
        ("nmap", nmap_stage),
        ("snmp", snmp_stage),
        ("cve_detect", cve_detect_stage),
        ("nuclei", nuclei_stage),
        ("verify", verify_stage),
    ],
    ScanProfile.FULL: [
        ("nmap", nmap_stage),
        ("snmp", snmp_stage),
        ("cve_detect", cve_detect_stage),
        ("nuclei", nuclei_stage),
        ("routersploit", routersploit_stage),
        ("hydra", hydra_stage),
        ("metasploit", metasploit_stage),
        ("verify", verify_stage),
    ],
    # FIRMWARE is reserved for v2 (binwalk/EMBA) and intentionally has no stages.
    ScanProfile.FIRMWARE: [],
}


class _QueueItem:
    __slots__ = ("job", "on_progress", "on_stage_done", "on_done", "on_alert", "light")

    def __init__(self, job: ScanJob, on_progress: ProgressCB | None,
                 on_stage_done: StageDoneCB | None,
                 on_done: DoneCB | None, on_alert: AlertCB | None,
                 light: bool = False) -> None:
        self.job = job
        self.on_progress = on_progress
        self.on_stage_done = on_stage_done
        self.on_done = on_done
        self.on_alert = on_alert
        self.light = light  # batch/subnet scans skip the heaviest stages


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
        # Cancellation bookkeeping.
        self._cancel_requested: set[int] = set()
        self._running_stage: dict[int, asyncio.Task] = {}

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Spawn the worker pool (idempotent)."""
        if self._started:
            return
        self._started = True
        for i in range(self._max_concurrent):
            self._workers.append(asyncio.create_task(self._worker(i), name=f"scan-worker-{i}"))
        log.info("engine started with %d workers", self._max_concurrent)

    async def discover_hosts(self, cidr: str) -> tuple[list[str], int, str | None]:
        """Ping-sweep a subnet → (live_hosts, total_hosts, error)."""
        return await discover_hosts(cidr)

    async def discover_hosts_stream(self, cidr: str, on_host) -> tuple[int, str | None]:
        """Ping-sweep a subnet, invoking ``on_host(ip)`` per live host as found."""
        return await discover_hosts_stream(cidr, on_host)

    async def wait_jobs_done(self, job_ids: list[int], poll: float = 1.0) -> None:
        """Block until every job in ``job_ids`` reaches a terminal state.

        A job that was deleted (cancelled scans are removed from history) counts
        as done. Used by economy mode to scan subnets strictly one at a time.
        """
        terminal = {JobStatus.DONE, JobStatus.ERROR, JobStatus.SKIPPED,
                    JobStatus.REJECTED, JobStatus.CANCELLED}
        pending = list(job_ids)
        while pending:
            still: list[int] = []
            for jid in pending:
                job = self._store.get_job(jid)
                if job is not None and job.status not in terminal:
                    still.append(jid)
            if not still:
                return
            pending = still
            await asyncio.sleep(poll)

    def mark_interrupted(self) -> int:
        """At startup: flag scans left unfinished by the previous run.

        Nothing runs automatically — the user resumes them on demand via the bot.
        """
        n = self._store.mark_unfinished_interrupted()
        if n:
            log.info("flagged %d interrupted job(s) from a previous run", n)
        return n

    def clear_interrupted(self) -> int:
        """Discard all INTERRUPTED jobs without running them. Returns the count."""
        n = self._store.delete_interrupted()
        if n:
            self._store.add_audit("interrupted_cleared", decision=str(n),
                                  engagement_id=self._scope.engagement_id)
            log.info("cleared %d interrupted job(s)", n)
        return n

    def resume_interrupted(self) -> list[ScanJob]:
        """Re-queue all INTERRUPTED jobs (fresh run, no live UI callbacks)."""
        jobs = self._store.list_interrupted()
        for job in jobs:
            self._store.reset_job_for_retry(job.id)  # -> QUEUED, drops partials
            fresh = self._store.get_job(job.id)
            if fresh is None:
                continue
            self._store.add_audit("job_resumed", target=fresh.target,
                                  decision="QUEUED", engagement_id=fresh.engagement_id)
            self._queue.put_nowait(_QueueItem(fresh, None, None, None, None))
        if jobs:
            log.info("resumed %d interrupted job(s)", len(jobs))
        return jobs

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
                on_stage_done: StageDoneCB | None = None,
                on_done: DoneCB | None = None,
                on_alert: AlertCB | None = None,
                light: bool = False) -> ScanJob:
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
        self._queue.put_nowait(
            _QueueItem(job, on_progress, on_stage_done, on_done, on_alert, light))
        return job

    # ------------------------------------------------------------ cancellation
    def request_cancel(self, job_id: int) -> bool:
        """Ask a queued/running job to stop. Returns False if it's already done."""
        job = self._store.get_job(job_id)
        if job is None or job.status not in (JobStatus.QUEUED, JobStatus.RUNNING):
            return False
        self._cancel_requested.add(job_id)
        task = self._running_stage.get(job_id)
        if task is not None and not task.done():
            task.cancel()
        log.info("cancel requested for job %d", job_id)
        return True

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

        # Cancelled while still queued — never start any tool, leave no history.
        if job.id in self._cancel_requested:
            self._cancel_cleanup(job)
            if item.on_done is not None:
                await _safe(item.on_done(job, []))
            return

        self._store.update_status(job.id, JobStatus.RUNNING)
        job.status = JobStatus.RUNNING
        self._store.add_audit("job_started", target=job.target,
                              decision="RUNNING", engagement_id=job.engagement_id)
        log.info("job %d started target=%s profile=%s", job.id, job.target, job.profile.value)

        all_findings: list[Finding] = []
        device_label = ""
        final_status = JobStatus.DONE
        ctx: dict = {"light": item.light}  # shared across this job's stages
        # Defense-in-depth: let network-touching stages (cve_detect) re-check
        # scope per request without re-auditing every call.
        ctx["_scope_allows"] = self._scope.allows
        # Self-learning favicon→model memory (cve_detect fingerprinting).
        ctx["_favicon_lookup"] = self._store.get_favicon_model
        ctx["_favicon_learn"] = self._store.learn_favicon_model
        try:
            for idx, (name, stage) in enumerate(stages, start=1):
                if job.id in self._cancel_requested:
                    final_status = JobStatus.CANCELLED
                    break
                if item.on_progress is not None:
                    await _safe(item.on_progress(job, name, idx, total))

                findings = await self._run_stage(name, stage, job.target, job.id, ctx)
                self._store.add_findings(job.id, findings)
                all_findings.extend(findings)

                if item.on_stage_done is not None:
                    await _safe(item.on_stage_done(job, name, findings, idx, total))

                # Immediate alert for high/critical findings.
                if item.on_alert is not None:
                    for f in findings:
                        if severity_rank(f.severity) >= ALERT_THRESHOLD:
                            await _safe(item.on_alert(job, f, device_label))

                # Router gate: after nmap decide whether to keep going.
                if name == "nmap":
                    verdict, device_label = router_verdict(findings)
                    skip_unknown = get_config().skip_unknown
                    # A host exposing a web/admin/router-mgmt port is worth scanning
                    # regardless of nmap's device-type guess (nmap mislabels many
                    # embedded routers). Never skip those — only skip when there is
                    # nothing scannable open.
                    scannable = any(p in SCANNABLE_PORTS
                                    for p in (ctx.get("open_ports") or []))
                    should_skip = (not scannable) and (
                        verdict == "not_router"
                        or (verdict == "unknown" and skip_unknown))
                    if should_skip and idx < total:
                        reason = ("Тип устройства не определён — дальнейшие стадии пропущены"
                                  if verdict == "unknown"
                                  else "Цель не похожа на роутер — дальнейшие стадии пропущены")
                        self._store.add_findings(job.id, [Finding(
                            "fingerprint", Severity.INFO, reason,
                            {"verdict": verdict, "label": device_label})])
                        final_status = JobStatus.SKIPPED
                        break
            else:
                final_status = JobStatus.DONE

        except asyncio.CancelledError:
            final_status = JobStatus.CANCELLED
            log.info("job %d cancelled mid-stage", job.id)
        except Exception as exc:  # noqa: BLE001
            self._store.update_status(job.id, JobStatus.ERROR, error=str(exc), finished=True)
            job.status = JobStatus.ERROR
            job.error = str(exc)
            log.exception("job %d errored", job.id)
            self._cancel_requested.discard(job.id)
            self._store.add_audit("job_finished", target=job.target,
                                  decision=job.status.value, engagement_id=job.engagement_id)
            if item.on_done is not None:
                await _safe(item.on_done(job, all_findings))
            return

        # A cancelled scan leaves nothing in history (partial results are dropped).
        if final_status == JobStatus.CANCELLED:
            self._cancel_cleanup(job)
            if item.on_done is not None:
                await _safe(item.on_done(job, all_findings))
            return

        self._finish(job, final_status)
        log.info("job %d %s: %d findings", job.id, final_status.value, len(all_findings))
        if item.on_done is not None:
            await _safe(item.on_done(job, all_findings))

    def _cancel_cleanup(self, job: ScanJob) -> None:
        """Drop a cancelled job (and its partial findings) from history; audit it."""
        self._cancel_requested.discard(job.id)
        self._store.delete_job(job.id)
        job.status = JobStatus.CANCELLED
        job.finished_at = None
        self._store.add_audit("job_cancelled", target=job.target,
                              decision="CANCELLED", engagement_id=job.engagement_id)
        log.info("job %d cancelled — removed from history", job.id)

    def _finish(self, job: ScanJob, status: JobStatus) -> None:
        self._cancel_requested.discard(job.id)
        self._store.update_status(job.id, status, finished=True)
        job.status = status
        self._store.add_audit("job_finished", target=job.target,
                              decision=status.value, engagement_id=job.engagement_id)

    async def _run_stage(self, name: str, stage: Stage, target: str,
                         job_id: int, ctx: dict) -> list[Finding]:
        """Run one stage as a cancellable, hard-time-bounded task.

        A failing stage yields an info Finding (never aborts the scan); a cancelled
        stage re-raises ``CancelledError`` so the job is marked CANCELLED. A
        backstop timeout guarantees a stuck stage can never hang a worker forever
        (kills its subprocess and moves on) — without it, one hung tool stalls the
        whole queue at high concurrency.
        """
        task: asyncio.Task = asyncio.ensure_future(stage(target, ctx))
        self._running_stage[job_id] = task
        try:
            return await asyncio.wait_for(task, timeout=STAGE_TIMEOUT)
        except asyncio.TimeoutError:
            log.warning("stage %s timed out (>%ss) on job %d — killed",
                        name, STAGE_TIMEOUT, job_id)
            return [Finding(name, Severity.INFO,
                            f"stage {name} timed out (>{int(STAGE_TIMEOUT)}s)", {})]
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - one stage must not abort the scan
            log.exception("stage %s failed", name)
            return [Finding(name, Severity.INFO, f"stage {name} failed",
                            {"error": str(exc)})]
        finally:
            self._running_stage.pop(job_id, None)


async def _safe(awaitable: Awaitable[None]) -> None:
    """Run a callback, swallowing/logging its errors (UI must not break a scan)."""
    try:
        await awaitable
    except Exception:  # noqa: BLE001
        log.exception("progress/done/alert callback failed")


class _suppress_cancel:
    def __enter__(self) -> "_suppress_cancel":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is asyncio.CancelledError
