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

STATIC_DIR = Path(__file__).parent / "static"


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
    status: str = "pending"  # pending|mining|staleness|semantic_diff|classifying|done|error
    done: int = 0
    total: int = 0
    error: Optional[str] = None
    report: Optional[priority.TriageReport] = None
    all_facts: Optional[list] = None  # kept only for the rule-history endpoint below
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    def status_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "status": self.status,
            "done": self.done,
            "total": self.total,
            "error": self.error,
            "path": self.path,
            "elapsed_seconds": round((self.finished_at or time.time()) - self.created_at, 1),
        }


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def _run_job(job: Job) -> None:
    def progress_cb(stage: str, done: int, total: int) -> None:
        with _JOBS_LOCK:
            job.status = "mining" if stage in ("mining", "cache_hit") else stage
            job.done = done
            job.total = total

    try:
        root = Path(job.path)
        # Mined here (not left to compute_triage's own internal call) purely
        # so the facts can be kept on the Job afterward for the rule-history
        # endpoint below - same cache-aware churn.mine_commits_cached call
        # `compute_triage` would make internally either way, not a second
        # mining pass, not a new analysis.
        all_facts = churn.mine_commits_cached(
            root, job.fmt, subdir=job.subdir, progress_cb=lambda stage, n: progress_cb(stage, n, 0)
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
    except churn.ChurnError as e:
        # The core's own LOUD failure (no .git, shallow clone, etc.) -
        # surfaced verbatim, not swallowed or turned into an empty result.
        with _JOBS_LOCK:
            job.error = str(e)
            job.status = "error"
            job.finished_at = time.time()
    except Exception as e:  # noqa: BLE001 - a job thread must never die silently
        with _JOBS_LOCK:
            job.error = f"{type(e).__name__}: {e}"
            job.status = "error"
            job.finished_at = time.time()


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


def create_app() -> FastAPI:
    app = FastAPI(title="mechanic GUI", docs_url=None, redoc_url=None)

    @app.post("/api/load")
    def load_repo(req: LoadRequest) -> dict[str, Any]:
        root = Path(req.path)
        if not root.exists() or not root.is_dir():
            raise HTTPException(400, f"Not a directory: {req.path}")
        job = Job(
            id=uuid.uuid4().hex[:12],
            path=str(root),
            fmt=req.fmt,
            subdir=req.subdir,
            mechanical_threshold=req.mechanical_threshold,
        )
        with _JOBS_LOCK:
            _JOBS[job.id] = job
        thread = threading.Thread(target=_run_job, args=(job,), daemon=True)
        thread.start()
        return {"job_id": job.id}

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
            if job.status != "done" or job.report is None:
                raise HTTPException(425, f"job not finished yet (status={job.status})")
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
        match = next((r for r in report.scoreable + report.unscoreable if r.file == file), None)
        if match is None:
            raise HTTPException(404, f"rule not found in this job's report: {file}")
        return match.to_dict()

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


app = create_app()


def run_server(host: str = "127.0.0.1", port: int = 8642, open_browser: bool = True) -> None:
    """Blocking call - starts uvicorn, optionally opening a browser tab
    shortly after (uvicorn.run() itself blocks, so the browser-open is
    scheduled on a short timer beforehand rather than sequenced after)."""
    import uvicorn

    url = f"http://{host}:{port}/"
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    print(f"[mechanic-gui] serving at {url} (offline, no network calls made by this process)")
    uvicorn.run(app, host=host, port=port, log_level="warning")
