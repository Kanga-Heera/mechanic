"""SQLite-backed durability for GUI job state (Task 8 hardening pass).

Before this module existed, every `Job` lived only in the `_JOBS` in-memory
dict in `mechanic/gui/server.py` - a server restart (a crash, an update, a
laptop sleep that kills the process) silently discarded every job's status
and result. The existing "load from report" feature (`/api/load-from-
report`) already let a user manually reload a PREVIOUSLY EXPORTED `mechanic
triage --json` file, but that only helps for a report someone thought to
export - it does nothing for a job that was simply running in the GUI when
the process died.

This module is intentionally thin: a single `jobs` table, keyed by job id,
storing exactly what `Job.status_dict()`/`.report` already expose - no new
concepts, no schema beyond what the in-memory dataclass already tracks.
SQLite (stdlib `sqlite3`, no new dependency) because this is a local,
single-operator tool - the same "no new infrastructure" principle that
keeps Stage 3's repair experiment quarantined from the core applies here:
Postgres/Redis/anything requiring its own running service would be a
disproportionate answer to "remember what happened across a restart" on
one machine.

What this does NOT do: persist `Job.all_facts` (the mined git commit-fact
list) - it can be arbitrarily large for a big repo, and it's already
disk-cached elsewhere, keyed to the repo's current HEAD
(`churn.mine_commits_cached`'s own `.mechanic_cache/` - see churn.py). A
restored "done" job re-populates `all_facts` via `_mine_for_history_async`
(a cache HIT in the common case: the repo hasn't moved since), not by
storing a second copy of the same data here. It also does not persist
fine-grained progress ticks (`done`/`total` mid-stage) - only status
TRANSITIONS are written (see `server.py`'s `_run_job`), so a job's progress
bar does not survive a restart mid-computation, but its outcome does: any
job that was still running when the process died is reclassified as
`interrupted` at the next startup (`mark_interrupted`), never silently
reported as done, error, or still-in-progress.

One more disclosed trade-off: a `done` job's report is stored as its
already-serialized `.to_dict()` JSON (with `to_dict()`'s own default
ordering baked in), not as a live `TriageReport` object - so after a
restart, `/api/jobs/{id}/result`'s `ordering`/`top_n` query params stop
being re-applied server-side for that job, exactly like the pre-existing
`/api/load-from-report` jobs already behave (see server.py's `job_result`).
This never affects what the actual GUI shows: the frontend re-sorts/
filters every row client-side regardless of what order a fetch arrived in
(see app.js) - it only affects a raw API client requesting a specific
`ordering=` on a job that happens to have survived a restart.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

# The real default for actual `mechanic gui` usage - a fixed, well-known
# per-user location, analogous to `.mechanic_cache/` living inside a mined
# repo. Tests always pass an explicit `db_path` (see tests/test_gui.py) so
# they never read or write this real location.
DEFAULT_DB_PATH = Path.home() / ".mechanic" / "gui_jobs.sqlite3"

# Every status a Job can durably end up in. Anything NOT in this set found
# at startup means the process died while that job was still running.
TERMINAL_STATUSES = ("done", "error", "cancelled", "interrupted")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    fmt TEXT NOT NULL,
    subdir TEXT,
    mechanical_threshold REAL NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    error TEXT,
    report_json TEXT,
    created_at REAL NOT NULL,
    finished_at REAL
)
"""

# sqlite3 connections are not safe to share across threads by default
# (`check_same_thread=False` below relaxes only the "same object" check,
# not actual concurrent-write safety) - every job runs on its own
# background thread (see server.py), so writes are serialized through this
# one lock rather than trusting SQLite's own locking under concurrent
# `Job` threads plus the FastAPI request thread.
_lock = threading.Lock()


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    with _lock:
        conn.execute(_SCHEMA)
        conn.commit()
    return conn


def save_job(conn: sqlite3.Connection, job: Any) -> None:
    """Upsert one job's current, terminal-or-not state. Called at job
    creation and at every STATUS TRANSITION (not every progress tick - see
    module docstring) from `server.py`."""
    report_json: Optional[str] = None
    if job.report is not None:
        report = job.report if isinstance(job.report, dict) else job.report.to_dict()
        report_json = json.dumps(report)
    with _lock:
        conn.execute(
            """
            INSERT INTO jobs (id, path, fmt, subdir, mechanical_threshold, status, detail, error, report_json, created_at, finished_at)
            VALUES (:id, :path, :fmt, :subdir, :mechanical_threshold, :status, :detail, :error, :report_json, :created_at, :finished_at)
            ON CONFLICT(id) DO UPDATE SET
                status=excluded.status,
                detail=excluded.detail,
                error=excluded.error,
                report_json=excluded.report_json,
                finished_at=excluded.finished_at
            """,
            {
                "id": job.id,
                "path": job.path,
                "fmt": job.fmt,
                "subdir": job.subdir,
                "mechanical_threshold": job.mechanical_threshold,
                "status": job.status,
                "detail": job.detail,
                "error": job.error,
                "report_json": report_json,
                "created_at": job.created_at,
                "finished_at": job.finished_at,
            },
        )
        conn.commit()


def load_all_jobs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every persisted job, newest first, as plain dicts (not `Job`
    instances - `server.py` reconstructs those, since it owns the dataclass
    and the in-memory-only fields like `cancel_requested`)."""
    with _lock:
        cur = conn.execute(
            "SELECT id, path, fmt, subdir, mechanical_threshold, status, detail, error, report_json, "
            "created_at, finished_at FROM jobs ORDER BY created_at DESC"
        )
        rows = cur.fetchall()
    jobs = []
    for id_, path, fmt, subdir, mech, status, detail, error, report_json, created_at, finished_at in rows:
        jobs.append(
            {
                "id": id_,
                "path": path,
                "fmt": fmt,
                "subdir": subdir,
                "mechanical_threshold": mech,
                "status": status,
                "detail": detail,
                "error": error,
                "report": json.loads(report_json) if report_json else None,
                "created_at": created_at,
                "finished_at": finished_at,
            }
        )
    return jobs


def mark_interrupted(conn: sqlite3.Connection) -> list[str]:
    """Call once, at server startup, before restoring jobs into memory: any
    job whose persisted status is NOT terminal means the process died while
    it was still running (mining/staleness/semantic_diff/classifying, or
    even `pending` if it died before its thread got scheduled at all) -
    reclassify it as `interrupted` rather than leaving it looking like it's
    still progressing, or worse, letting some other code path mistake a
    stale non-terminal status for "still fine, just slow."

    Returns the ids that were reclassified, purely for startup logging.
    """
    placeholders = ",".join("?" * len(TERMINAL_STATUSES))
    with _lock:
        cur = conn.execute(f"SELECT id FROM jobs WHERE status NOT IN ({placeholders})", TERMINAL_STATUSES)
        ids = [row[0] for row in cur.fetchall()]
        if ids:
            # finished_at is stamped "now" (restart time), not left NULL -
            # NULL would make status_dict()'s elapsed_seconds keep counting
            # up forever against the current time, as if still running.
            conn.execute(
                f"UPDATE jobs SET status='interrupted', finished_at=? WHERE status NOT IN ({placeholders})",
                (time.time(), *TERMINAL_STATUSES),
            )
            conn.commit()
    return ids
