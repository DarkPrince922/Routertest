"""SQLite persistence for jobs, findings and the audit trail.

Uses the stdlib ``sqlite3`` module. A single connection is guarded by a lock so
it is safe to call from the asyncio event loop and worker threads; calls are
short (no long transactions), so contention is negligible for this workload.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .models import (
    Finding,
    JobStatus,
    ScanJob,
    ScanProfile,
    Severity,
    normalize_severity,
    utcnow,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    profile       TEXT    NOT NULL,
    status        TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    finished_at   TEXT,
    error         TEXT,
    engagement_id TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES jobs(id),
    stage       TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    detail_json TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);

CREATE TABLE IF NOT EXISTS audit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    actor_id      INTEGER,
    action        TEXT    NOT NULL,
    target        TEXT,
    resolved_ip   TEXT,
    decision      TEXT,
    engagement_id TEXT
);
"""


class Store:
    """Thin data-access layer over a single SQLite database file."""

    def __init__(self, db_path: Path | str) -> None:
        self._path = str(db_path)
        # check_same_thread=False because rsf stages run in worker threads; we
        # serialize all access through _lock ourselves.
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ jobs
    def create_job(self, target: str, profile: ScanProfile, engagement_id: str,
                   status: JobStatus = JobStatus.QUEUED) -> ScanJob:
        created = utcnow()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO jobs(target, profile, status, created_at, engagement_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (target, profile.value, status.value, created.isoformat(), engagement_id),
            )
            self._conn.commit()
            job_id = int(cur.lastrowid)
        return ScanJob(
            id=job_id,
            target=target,
            profile=profile,
            status=status,
            engagement_id=engagement_id,
            created_at=created,
        )

    def update_status(self, job_id: int, status: JobStatus,
                      error: str | None = None, finished: bool = False) -> None:
        finished_at = utcnow().isoformat() if finished else None
        with self._lock:
            if finished:
                self._conn.execute(
                    "UPDATE jobs SET status=?, error=?, finished_at=? WHERE id=?",
                    (status.value, error, finished_at, job_id),
                )
            else:
                self._conn.execute(
                    "UPDATE jobs SET status=?, error=? WHERE id=?",
                    (status.value, error, job_id),
                )
            self._conn.commit()

    def add_findings(self, job_id: int, findings: list[Finding]) -> None:
        if not findings:
            return
        rows = [
            (job_id, f.stage, f.severity.value, f.title, json.dumps(f.detail, default=str))
            for f in findings
        ]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO findings(job_id, stage, severity, title, detail_json) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )
            self._conn.commit()

    def get_job(self, job_id: int) -> ScanJob | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return _row_to_job(row) if row else None

    def list_jobs(self, limit: int, offset: int) -> list[ScanJob]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM jobs ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [_row_to_job(r) for r in rows]

    def count_jobs(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM jobs").fetchone()
        return int(row["c"])

    def count_active(self) -> int:
        """Number of jobs currently QUEUED or RUNNING."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM jobs WHERE status IN (?, ?)",
                (JobStatus.QUEUED.value, JobStatus.RUNNING.value),
            ).fetchone()
        return int(row["c"])

    # -------------------------------------------------------------- findings
    def get_findings(self, job_id: int) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT stage, severity, title, detail_json FROM findings "
                "WHERE job_id=? ORDER BY id ASC",
                (job_id,),
            ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def get_findings_page(self, job_id: int, limit: int, offset: int) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT stage, severity, title, detail_json FROM findings "
                "WHERE job_id=? ORDER BY id ASC LIMIT ? OFFSET ?",
                (job_id, limit, offset),
            ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def count_findings(self, job_id: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE job_id=?", (job_id,)
            ).fetchone()
        return int(row["c"])

    def severity_breakdown(self, job_id: int) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings WHERE job_id=? "
                "GROUP BY severity",
                (job_id,),
            ).fetchall()
        return {r["severity"]: int(r["c"]) for r in rows}

    # ----------------------------------------------------------------- audit
    def add_audit(self, action: str, *, actor_id: int | None = None,
                  target: str | None = None, resolved_ip: str | None = None,
                  decision: str | None = None, engagement_id: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit(ts, actor_id, action, target, resolved_ip, "
                "decision, engagement_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (utcnow().isoformat(), actor_id, action, target, resolved_ip,
                 decision, engagement_id),
            )
            self._conn.commit()

    # ---------------------------------------------------------------- export
    def export_job(self, job_id: int) -> dict | None:
        """Full job + findings as a dict (DefectDojo generic-import friendly)."""
        job = self.get_job(job_id)
        if job is None:
            return None
        findings = self.get_findings(job_id)
        return {
            "job": job.to_dict(),
            "findings": [f.to_dict() for f in findings],
        }


def _row_to_job(row: sqlite3.Row) -> ScanJob:
    from datetime import datetime

    return ScanJob(
        id=int(row["id"]),
        target=row["target"],
        profile=ScanProfile(row["profile"]),
        status=JobStatus(row["status"]),
        engagement_id=row["engagement_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
        error=row["error"],
    )


def _row_to_finding(row: sqlite3.Row) -> Finding:
    sev: Severity = normalize_severity(row["severity"])
    try:
        detail = json.loads(row["detail_json"])
    except (json.JSONDecodeError, TypeError):
        detail = {}
    return Finding(stage=row["stage"], severity=sev, title=row["title"], detail=detail)
