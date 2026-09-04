"""FastAPI backend for `mechanic gui` - a VIEW over the core engine.

Every JSON shape this module returns is produced by calling straight into
`mechanic.priority`/`mechanic.churn` (the same functions the CLI uses) and
serializing their own `.to_dict()` - nothing here recomputes, estimates, or
reshapes an analysis result. The only "logic" that lives in this file is
job bookkeeping (a background thread per repo-load, so a slow mine/classify
pass doesn't block the HTTP server) and error translation (turning a
`churn.ChurnError` into a clear JSON error the frontend can render as a
message, not a stack trace).

Offline by construction: this app makes no outbound network calls, and the
static frontend it serves loads no CDN script, font, or stylesheet - open
`mechanic/gui/static/index.html` and check for yourself, or see
tests/test_gui_offline.py.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from mechanic import churn, priority
from mechanic.gui import job_store

STATIC_DIR = Path(__file__).parent / "static"

# Set by `create_app()` - the sqlite3 connection every job-mutating endpoint
# and `_run_job`/`_mine_for_history_async` persist through. A module-level
# global, same pattern as `_JOBS`/`_JOBS_LOCK` below (this file already
# shares those across repeated `create_app()` calls - e.g. one per test -
# so `_DB_CONN` follows the same convention rather than introducing a new
# one). `None` until the first `create_app()` call.
_DB_CONN = None


class JobCancelled(Exception):
    """Raised from inside a Job's `progress_cb` when its Stop button has
    been clicked - not a core concept, purely a GUI-level signal. Raising
    it from the callback is enough: `compute_triage`/`compute_semantic_diff`
    do nothing special with it, the exception just propagates up and aborts
    the computation at the next checkpoint, same as any other error would."""


# ---------------------------------------------------------------------------
# Job bookkeeping - a background thread per repo load, polled by the
# frontend. No analysis happens here; this only tracks progress and stores
# the finished TriageReport for later rule-detail lookups.
# ---------------------------------------------------------------------------


@dataclass
class Job:
    id: str
    path: str
    fmt: str
    subdir: Optional[str]
    mechanical_threshold: float
    # pending|mining|staleness|semantic_diff|classifying|done|cancelled|error|interrupted
    # ("interrupted" is never set by _run_job itself - only by job_store.
    # mark_interrupted at server startup, for a job that was in any
    # non-terminal state when the process previously died.)
    status: str = "pending"
    done: int = 0
    total: int = 0
    detail: str = ""  # e.g. the file currently being diffed/classified
    error: Optional[str] = None
    cancel_requested: threading.Event = field(default_factory=threading.Event)
    # A live-computed job's report is a TriageReport (its own .to_dict()
    # does the ordering/top_n work below). A job loaded verbatim from a
    # previously-exported `--json` file (see /api/load-from-report) stores
    # the parsed dict directly instead - already exactly that same shape,
    # nothing left to compute.
    report: Optional[Any] = None
    all_facts: Optional[list] = None  # kept only for the rule-history endpoint below
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def status_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "status": self.status,
            "done": self.done,
            "total": self.total,
            "detail": self.detail,
            "error": self.error,
            "path": self.path,
            "elapsed_seconds": round((self.finished_at or time.time()) - self.created_at, 1),
        }


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def _persist(job: Job) -> None:
    """Best-effort durability write - see job_store.py. Never raises into a
    job thread or a request handler: a persistence failure (disk full, a
    locked file) must degrade to "this job won't survive a restart", never
    to "this job's actual analysis crashed."."""
    if _DB_CONN is None:
        return
    try:
        job_store.save_job(_DB_CONN, job)
    except Exception:  # noqa: BLE001 - durability is best-effort, never fatal
        pass


def _run_job(job: Job) -> None:
    last_persisted_status = job.status

    def progress_cb(stage: str, done: int, total: int, detail: str = "") -> None:
        nonlocal last_persisted_status
        if job.cancel_requested.is_set():
            raise JobCancelled()
        with _JOBS_LOCK:
            job.status = "mining" if stage in ("mining", "cache_hit") else stage
            job.done = done
            job.total = total
            job.detail = detail
        # Persisted on STAGE TRANSITIONS only, not every done/total tick -
        # the dominant semantic_diff stage alone can fire this hundreds of
        # times a second on a big repo; writing SQLite that often would
        # turn durability into a real performance regression for no
        # benefit an "interrupted" catch-all status doesn't already cover.
        if job.status != last_persisted_status:
            last_persisted_status = job.status
            _persist(job)

    try:
        root = Path(job.path)
        # Mined here (not left to compute_triage's own internal call) purely
        # so the facts can be kept on the Job afterward for the rule-history
        # endpoint below - same cache-aware churn.mine_commits_cached call
        # `compute_triage` would make internally either way, not a second
        # mining pass, not a new analysis.
        all_facts = churn.mine_commits_cached(
            root,
            job.fmt,
            subdir=job.subdir,
            progress_cb=lambda stage, n: progress_cb(stage, n, 0),
            timeout=churn.DEFAULT_MINING_TIMEOUT_SECONDS,
        )
        report = priority.compute_triage(
            root,
            job.fmt,
            job.mechanical_threshold,
            subdir=job.subdir,
            all_facts=all_facts,
            progress_cb=progress_cb,
        )
        with _JOBS_LOCK:
            job.report = report
            job.all_facts = all_facts
            job.status = "done"
            job.finished_at = time.time()
        _persist(job)
    except JobCancelled:
        with _JOBS_LOCK:
            job.status = "cancelled"
            job.finished_at = time.time()
        _persist(job)
    except priority.UnsupportedFormatError as e:
        # Belt-and-suspenders: /api/load already rejects a non-sigma `fmt`
        # before a job is created at all (see that endpoint) - this only
        # matters if _run_job is ever reached some other way (e.g. a
        # restored job from an old, pre-scoping persisted database row).
        with _JOBS_LOCK:
            job.error = str(e)
            job.status = "error"
            job.finished_at = time.time()
        _persist(job)
    except churn.ChurnError as e:
        # The core's own LOUD failure (no .git, shallow clone, etc.) -
        # surfaced verbatim, not swallowed or turned into an empty result.
        with _JOBS_LOCK:
            job.error = str(e)
            job.status = "error"
            job.finished_at = time.time()
        _persist(job)
    except Exception as e:  # noqa: BLE001 - a job thread must never die silently
        with _JOBS_LOCK:
            job.error = f"{type(e).__name__}: {e}"
            job.status = "error"
            job.finished_at = time.time()
        _persist(job)


def _commit_history_for_file(all_facts: list, file_rel: str, limit: int = 50) -> list[dict[str, Any]]:
    """Every organic-or-not commit that touched `file_rel` (under any of its
    past names, resolved through the same rename map `priority.compute_
    triage` already builds internally) - real, already-mined commit facts,
    filtered per file. Not a new analysis: no classification, no staleness
    math, just a list of (hash, date, subject) a human can read."""
    renamed_to = churn._build_renamed_to(all_facts)
    history = []
    for f in all_facts:
        for touched in f.rule_paths_touched:
            canonical = churn._resolve_canonical(touched, renamed_to)
            if canonical == file_rel:
                history.append(
                    {
                        "hash": f.hash,
                        "short_hash": f.hash[:10],
                        "subject": f.subject,
                        "author": f.author_key,
                        "date": f.author_date.isoformat(),
                        "is_merge": f.is_merge,
                    }
                )
                break
    history.sort(key=lambda h: h["date"], reverse=True)
    return history[:limit]


def _safe_resolve_under_root(root: Path, rel: str) -> Path:
    """Resolves `rel` under `root` and refuses to return anything outside
    it - `rel` comes from a query param, and while this is a local,
    single-operator tool (same trust model as the CLI reading any path you
    hand it), a `../../` path-traversal attempt into the rule-source
    endpoint is still refused rather than silently followed."""
    candidate = (root / rel).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise HTTPException(403, "path escapes the loaded repository root")
    return candidate


class LoadRequest(BaseModel):
    path: str
    fmt: str = "sigma"
    subdir: Optional[str] = None
    mechanical_threshold: float = churn.DEFAULT_THRESHOLD
    refresh: bool = False


class LoadFromReportRequest(BaseModel):
    report_path: str
    subdir: Optional[str] = None


def _mine_for_history_async(job: Job, root: Path) -> None:
    """Best-effort, off the request thread: populate `job.all_facts` so
    the rule-history tab works for a job loaded from a saved report (see
    /api/load-from-report). Same disk-cache-aware call `compute_triage`
    itself would make - a cache HIT when the repo hasn't moved since the
    report was produced (the expected case), not a fresh mine. Failure
    here is non-fatal: rule-history just reports "not finished yet"
    forever for this job, same as any other job whose mining is still in
    flight - Overview and Source stay fully available either way."""
    try:
        facts = churn.mine_commits_cached(root, job.fmt, subdir=job.subdir)
        with _JOBS_LOCK:
            job.all_facts = facts
    except Exception:  # noqa: BLE001 - best-effort only, never crashes the server
        pass


def _restore_jobs_from_disk() -> None:
    """Called once, from `create_app()`, before serving any request:
    reclassifies any non-terminal persisted job as `interrupted` (the
    process died while it was running - see job_store.mark_interrupted),
    then loads every persisted job back into `_JOBS` so `/api/jobs/{id}`
    and friends work immediately after a restart, no reload required.

    Restored jobs never carry `all_facts` (not persisted - see job_store.py's
    module docstring) or a live `cancel_requested` thread - a restored job
    is never "running" in this process, cancel-ability is meaningless for
    it. A restored `done` job kicks off `_mine_for_history_async` in the
    background so its rule-history tab recovers too (a cache HIT in the
    common case), same as a job loaded via /api/load-from-report."""
    if _DB_CONN is None:
        return
    ids = job_store.mark_interrupted(_DB_CONN)
    if ids:
        print(f"[mechanic-gui] {len(ids)} job(s) were still running at last shutdown - marked interrupted: {ids}", flush=True)
    for row in job_store.load_all_jobs(_DB_CONN):
        job = Job(
            id=row["id"],
            path=row["path"],
            fmt=row["fmt"],
            subdir=row["subdir"],
            mechanical_threshold=row["mechanical_threshold"],
            status=row["status"],
            error=row["error"],
            report=row["report"],
            created_at=row["created_at"],
            finished_at=row["finished_at"],
        )
        with _JOBS_LOCK:
            _JOBS[job.id] = job
        if job.status == "done" and job.report is not None:
            threading.Thread(target=_mine_for_history_async, args=(job, Path(job.path)), daemon=True).start()


def create_app(db_path: Optional[Path] = None) -> FastAPI:
    """`db_path`, if given, overrides where job state is persisted
    (job_store.DEFAULT_DB_PATH otherwise) - tests always pass a `tmp_path`
    location so they never touch a real user's `~/.mechanic/`. Every
    `create_app()` call (re)connects and restores from THAT path, following
    this module's existing convention of sharing `_JOBS`/`_JOBS_LOCK` as
    module-level state across repeated calls (one real call per `mechanic
    gui` process; one per test)."""
    global _DB_CONN
    _DB_CONN = job_store.connect(db_path or job_store.DEFAULT_DB_PATH)
    _restore_jobs_from_disk()

    app = FastAPI(title="mechanic GUI", docs_url=None, redoc_url=None)

    @app.post("/api/load")
    def load_repo(req: LoadRequest) -> dict[str, Any]:
        root = Path(req.path)
        if not root.exists() or not root.is_dir():
            raise HTTPException(400, f"Not a directory: {req.path}")
        if req.fmt != "sigma":
            # Fragility/tiering/priority are Sigma-only in the core (see
            # docs/core-vs-experiment.md) - refused here, before a
            # background job is even created, rather than discovered later
            # as a job "error" after mining has already run. The static
            # frontend no longer offers any other option in its Format
            # select, so this only matters for a direct API call.
            raise HTTPException(400, priority.SIGMA_ONLY_FRAGILITY_MESSAGE)
        job = Job(
            id=uuid.uuid4().hex[:12],
            path=str(root),
            fmt=req.fmt,
            subdir=req.subdir,
            mechanical_threshold=req.mechanical_threshold,
        )
        with _JOBS_LOCK:
            _JOBS[job.id] = job
        _persist(job)
        thread = threading.Thread(target=_run_job, args=(job,), daemon=True)
        thread.start()
        return {"job_id": job.id}

    @app.post("/api/load-from-report")
    def load_from_report(req: LoadFromReportRequest) -> dict[str, Any]:
        """Load a report file previously produced by `mechanic triage
        --json` (this same core engine) VERBATIM - for a corpus already
        computed once (e.g. from the CLI, or by hand outside this tab).
        No recomputation: the file's own JSON becomes the job's result
        unmodified. Only the rule-history tab needs anything beyond that
        file's content, and it's filled in the background, non-blocking
        (see `_mine_for_history_async`)."""
        report_file = Path(req.report_path)
        if not report_file.is_file():
            raise HTTPException(400, f"Not a file: {req.report_path}")
        try:
            data = json.loads(report_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise HTTPException(400, f"Could not read/parse report file: {e}")
        if not isinstance(data, dict) or "rules" not in data or "root" not in data:
            raise HTTPException(400, "Not a mechanic triage report (missing 'root'/'rules').")
        root = Path(data["root"])
        job = Job(
            id=uuid.uuid4().hex[:12],
            path=str(root),
            fmt=data.get("fmt", "sigma"),
            subdir=req.subdir,
            mechanical_threshold=data.get("mechanical_threshold", churn.DEFAULT_THRESHOLD),
            status="done",
            report=data,
            finished_at=time.time(),
        )
        with _JOBS_LOCK:
            _JOBS[job.id] = job
        _persist(job)
        threading.Thread(target=_mine_for_history_async, args=(job, root), daemon=True).start()
        return {"job_id": job.id}

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: str) -> dict[str, Any]:
        """Ask a running job to stop. Cooperative, not instant: the job
        thread only notices at its next `progress_cb` checkpoint (see
        `JobCancelled` above) - during the dominant semantic-diff stage
        that's before the next file is diffed, so in practice this is
        responsive; during the (fast) staleness stage it can lag up to
        that stage's own few seconds. A job already
        done/errored/cancelled/interrupted is left alone - this can't undo
        a finished (or already-dead) result."""
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                raise HTTPException(404, "unknown job_id")
            if job.status in job_store.TERMINAL_STATUSES:
                return job.status_dict()
            job.cancel_requested.set()
        return job.status_dict()

    @app.get("/api/jobs/{job_id}")
    def job_status(job_id: str) -> dict[str, Any]:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                raise HTTPException(404, "unknown job_id")
            return job.status_dict()

    @app.get("/api/jobs/{job_id}/result")
    def job_result(
        job_id: str,
        ordering: str = Query("priority_first"),
        top_n: Optional[int] = Query(None),
    ) -> dict[str, Any]:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                raise HTTPException(404, "unknown job_id")
            if job.status == "error":
                raise HTTPException(422, job.error or "job failed")
            if job.status == "cancelled":
                raise HTTPException(422, "cancelled by user")
            if job.status == "interrupted":
                raise HTTPException(
                    409, "this job was still running when the server was last restarted, so it never finished - reload this repo to compute it again"
                )
            if job.status != "done" or job.report is None:
                raise HTTPException(425, f"job not finished yet (status={job.status})")
            if isinstance(job.report, dict):
                # Loaded verbatim from a file - already this exact shape.
                # `ordering`/`top_n` aren't re-applied server-side (no
                # TriageReport object to ask); the frontend already
                # re-sorts/filters every row client-side regardless of
                # what order a fetch arrived in, so this only affects
                # which order rows are logically listed in, never a value.
                return job.report
            return job.report.to_dict(top_n=top_n, ordering=ordering)

    @app.get("/api/jobs/{job_id}/rule")
    def rule_detail(job_id: str, file: str = Query(...)) -> dict[str, Any]:
        """One rule's full detail - looked up in the ALREADY-COMPUTED
        report for this job, never recomputed."""
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                raise HTTPException(404, "unknown job_id")
            if job.status != "done" or job.report is None:
                raise HTTPException(425, f"job not finished yet (status={job.status})")
            report = job.report
        if isinstance(report, dict):
            match = next((r for r in report["rules"] + report["unscoreable"] if r["file"] == file), None)
        else:
            found = next((r for r in report.scoreable + report.unscoreable if r.file == file), None)
            match = found.to_dict() if found is not None else None
        if match is None:
            raise HTTPException(404, f"rule not found in this job's report: {file}")
        return match

    @app.get("/api/jobs/{job_id}/rule-source")
    def rule_source(job_id: str, file: str = Query(...)) -> dict[str, Any]:
        """The rule's raw file content, verbatim - not part of any
        analysis, just a read of the same file `triage`/`explain` already
        parsed. Confined to the loaded repository root (see
        `_safe_resolve_under_root`)."""
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                raise HTTPException(404, "unknown job_id")
            job_path = job.path
        full_path = _safe_resolve_under_root(Path(job_path), file)
        if not full_path.is_file():
            raise HTTPException(404, f"file not found: {file}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise HTTPException(500, f"could not read file: {e}")
        return {"file": file, "content": content}

    @app.get("/api/jobs/{job_id}/rule-history")
    def rule_history(job_id: str, file: str = Query(...)) -> dict[str, Any]:
        """Every mined commit that touched this file (under any past
        rename), newest first - filtered from the SAME all_facts this
        job's report was already built from, not re-mined."""
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job is None:
                raise HTTPException(404, "unknown job_id")
            if job.status != "done" or job.all_facts is None:
                raise HTTPException(425, f"job not finished yet (status={job.status})")
            all_facts = job.all_facts
        return {"file": file, "commits": _commit_history_for_file(all_facts, file)}

    @app.get("/api/priority-legend")
    def priority_legend() -> dict[str, Any]:
        return priority.priority_matrix_schema()

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "offline": True}

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(str(STATIC_DIR / "index.html"))

    return app


def run_server(host: str = "127.0.0.1", port: int = 8642, open_browser: bool = True) -> None:
    """Blocking call - starts uvicorn, optionally opening a browser tab
    shortly after (uvicorn.run() itself blocks, so the browser-open is
    scheduled on a short timer beforehand rather than sequenced after).

    `create_app()` is called HERE, not at module import time (it used to be
    a module-level `app = create_app()`, kept only for `uvicorn.run(app,
    ...)`'s convenience) - `create_app()` now does real I/O (connects to
    the job-persistence sqlite3 database and restores jobs from it, see
    job_store.py), which must never happen as a side effect of merely
    importing this module. Importing `mechanic.gui.server` (e.g. to reuse
    `Job`/`_run_job` in a test, or via mechanic.cli's lazy import) must stay
    inert - this is exactly the same "no surprise side effects from an
    import" principle `docs/core-vs-experiment.md` enforces for the
    repair experiment, applied to this module's own database connection."""
    import uvicorn

    url = f"http://{host}:{port}/"
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"[mechanic-gui] serving at {url} (offline, no network calls made by this process)")
    uvicorn.run(create_app(), host=host, port=port, log_level="warning")
