"""The GUI (`mechanic gui`) is a VIEW over the core engine only - never the
Stage 3 repair experiment, never a recomputation of any analysis. These
tests prove both properties directly, plus the offline/no-CDN constraint
and the actual HTTP surface end to end (load -> poll -> result -> detail).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="GUI tests need the optional `gui`/dev extras (fastapi, httpx)")
pytest.importorskip("httpx", reason="GUI tests need httpx for FastAPI's TestClient")

from fastapi.testclient import TestClient  # noqa: E402

from mechanic import priority  # noqa: E402
from mechanic.gui.server import STATIC_DIR, Job, _run_job, create_app  # noqa: E402

GUI_DIR = Path(__file__).parent.parent / "mechanic" / "gui"

EXPERIMENT_MODULE_LEAVES = [
    "verify",
    "gate",
    "evasion",
    "synthetic_benign",
    "llm_client",
    "repair_generator",
    "repair_outcome",
    "cli_repair",
]


# --- Part 0: the GUI never touches the repair experiment -------------------


def test_gui_source_imports_nothing_from_experiment():
    """Same discipline as tests/test_core_isolation.py, applied to the new
    GUI package - source-scan every .py file under mechanic/gui/ for an
    import of any experiment module."""
    py_files = list(GUI_DIR.glob("*.py"))
    assert py_files, "expected at least server.py/__init__.py under mechanic/gui/"
    for path in py_files:
        src = path.read_text(encoding="utf-8")
        import_lines = [ln for ln in src.splitlines() if ln.strip().startswith(("import ", "from "))]
        for ln in import_lines:
            for leaf in EXPERIMENT_MODULE_LEAVES:
                assert leaf not in ln, f"{path.name} imports experiment module via: {ln!r}"


def test_gui_has_no_repair_endpoints(tmp_path: Path):
    """The API surface itself must never expose repair/verify/gate - not
    just "no import," but no route path suggesting it either."""
    app = create_app(db_path=tmp_path / "gui_jobs.sqlite3")
    paths = [route.path for route in app.routes]
    for p in paths:
        for leaf in ["verify", "gate", "evasion", "repair", "llm"]:
            assert leaf not in p.lower(), f"GUI route unexpectedly references '{leaf}': {p}"


def test_core_isolation_test_still_passes():
    """Explicit re-confirmation the hardening pass's own boundary test is
    unaffected by adding the GUI (Part 0's stated requirement) - runs it
    as a real subprocess, exactly as it runs standalone."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_core_isolation.py", "-q"],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --- offline / no-CDN --------------------------------------------------


def test_static_frontend_has_no_external_network_references():
    forbidden_substrings = ["http://", "https://", "//cdn.", "googleapis", "gstatic", "unpkg", "jsdelivr"]
    for fname in ["index.html", "app.js", "style.css"]:
        text = (STATIC_DIR / fname).read_text(encoding="utf-8")
        for forbidden in forbidden_substrings:
            assert forbidden not in text, f"{fname} references external network resource: {forbidden!r}"


def test_gui_server_module_makes_no_requests_import():
    """Belt-and-suspenders: the server itself must not import an HTTP
    client library (it has no reason to make outbound calls at all)."""
    src = (GUI_DIR / "server.py").read_text(encoding="utf-8")
    assert "import requests" not in src
    assert "urllib.request" not in src


# --- HTTP surface: load -> poll -> result -> detail -------------------


def _git(repo: Path, *args: str, env: dict | None = None) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, env=env)


@pytest.fixture
def small_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "A")
    (repo / "rules" / "good.yml").write_text(
        "title: Suspicious Certutil Download\n"
        "id: 11111111-1111-1111-1111-111111111111\nstatus: test\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: '\\certutil.exe'\n"
        "    CommandLine|contains: '-urlcache'\n  condition: selection\n"
    )
    (repo / "rules" / "broken.yml").write_text("id: 12345\ntitle: [not valid\n")
    env = {**os.environ, "GIT_AUTHOR_DATE": "2020-01-01T00:00:00", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00"}
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "add rules"], cwd=repo, check=True, capture_output=True, env=env)
    return repo


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    # Always an explicit tmp_path db - never job_store.DEFAULT_DB_PATH, so
    # tests never read or write the real user's ~/.mechanic/gui_jobs.sqlite3.
    return TestClient(create_app(db_path=tmp_path / "gui_jobs.sqlite3"))


def _load_and_wait(client: TestClient, repo: Path, subdir: str = "rules", timeout: float = 30.0) -> str:
    resp = client.post("/api/load", json={"path": str(repo), "fmt": "sigma", "subdir": subdir})
    assert resp.status_code == 200, resp.text
    job_id = resp.json()["job_id"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(f"/api/jobs/{job_id}").json()
        if status["status"] in ("done", "error"):
            return job_id
        time.sleep(0.1)
    raise TimeoutError("job did not finish in time")


def test_health(client: TestClient):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["offline"] is True


def test_index_serves_html(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "mechanic" in resp.text.lower()


def test_static_files_served(client: TestClient):
    resp = client.get("/static/app.js")
    assert resp.status_code == 200
    resp2 = client.get("/static/style.css")
    assert resp2.status_code == 200


def test_load_nonexistent_path_rejected(client: TestClient):
    resp = client.post("/api/load", json={"path": "Z:\\definitely\\not\\a\\real\\path"})
    assert resp.status_code == 400


def test_unknown_job_id_404(client: TestClient):
    assert client.get("/api/jobs/does-not-exist").status_code == 404
    assert client.get("/api/jobs/does-not-exist/result").status_code == 404


def test_load_and_poll_and_result_matches_core_directly(client: TestClient, small_repo: Path):
    """The load-bearing test: the GUI's HTTP response for a loaded repo
    must be BYTE-IDENTICAL (as parsed JSON) to calling
    priority.compute_triage(...).to_dict() directly - proof this is a
    passthrough, not a reimplementation."""
    job_id = _load_and_wait(client, small_repo)
    status = client.get(f"/api/jobs/{job_id}").json()
    assert status["status"] == "done", status

    gui_result = client.get(f"/api/jobs/{job_id}/result?ordering=tier_first").json()
    direct_result = priority.compute_triage(small_repo, "sigma", subdir="rules").to_dict(ordering="tier_first")

    # `root` embeds the same path either way; everything else must match
    # exactly, including every rule's priority/narrative/fragility detail.
    assert gui_result == direct_result


def test_rule_detail_endpoint_matches_row_in_result(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    result = client.get(f"/api/jobs/{job_id}/result").json()
    a_rule = (result["rules"] + result["unscoreable"])[0]
    detail = client.get(f"/api/jobs/{job_id}/rule", params={"file": a_rule["file"]}).json()
    assert detail == a_rule


def test_rule_detail_unknown_file_404(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    resp = client.get(f"/api/jobs/{job_id}/rule", params={"file": "rules/does_not_exist.yml"})
    assert resp.status_code == 404


def test_result_before_done_returns_425(client: TestClient, small_repo: Path):
    resp = client.post("/api/load", json={"path": str(small_repo), "fmt": "sigma", "subdir": "rules"})
    job_id = resp.json()["job_id"]
    # race-y by nature (job may finish instantly on a tiny repo) - only
    # assert the shape IS one of the two legitimate outcomes.
    result_resp = client.get(f"/api/jobs/{job_id}/result")
    assert result_resp.status_code in (200, 425)


def test_priority_legend_endpoint_matches_core_schema(client: TestClient):
    resp = client.get("/api/priority-legend")
    assert resp.status_code == 200
    assert resp.json() == priority.priority_matrix_schema()


# --- rule source + git history -----------------------------------------


def test_rule_source_returns_verbatim_file_content(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    resp = client.get(f"/api/jobs/{job_id}/rule-source", params={"file": "rules/good.yml"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["file"] == "rules/good.yml"
    assert data["content"] == (small_repo / "rules" / "good.yml").read_text(encoding="utf-8")


def test_rule_source_unknown_file_404(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    resp = client.get(f"/api/jobs/{job_id}/rule-source", params={"file": "rules/nope.yml"})
    assert resp.status_code == 404


def test_rule_source_refuses_path_traversal(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    resp = client.get(f"/api/jobs/{job_id}/rule-source", params={"file": "../../../../etc/passwd"})
    assert resp.status_code == 403


def test_rule_history_lists_real_mined_commits(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    resp = client.get(f"/api/jobs/{job_id}/rule-history", params={"file": "rules/good.yml"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["file"] == "rules/good.yml"
    assert len(data["commits"]) >= 1
    commit = data["commits"][0]
    for key in ["hash", "short_hash", "subject", "author", "date", "is_merge"]:
        assert key in commit
    assert commit["subject"] == "add rules"


def test_rule_history_unrelated_file_empty_not_error(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    resp = client.get(f"/api/jobs/{job_id}/rule-history", params={"file": "rules/never_existed.yml"})
    assert resp.status_code == 200
    assert resp.json()["commits"] == []


# --- edge states: no crash, a clear message ---------------------------


def test_no_git_history_surfaces_loud_core_error(client: TestClient, tmp_path: Path):
    """No .git directory at all - churn.ChurnError, not a crash, not a
    blank/frozen result."""
    no_git = tmp_path / "no_git_repo"
    (no_git / "rules").mkdir(parents=True)
    (no_git / "rules" / "a.yml").write_text("title: a\ndetection:\n  x: 1\n  condition: x\n")
    job_id = _load_and_wait(client, no_git, subdir="rules")
    status = client.get(f"/api/jobs/{job_id}").json()
    assert status["status"] == "error"
    assert status["error"]  # the core's own ChurnError message, not swallowed
    result_resp = client.get(f"/api/jobs/{job_id}/result")
    assert result_resp.status_code == 422
    assert result_resp.json()["detail"] == status["error"]


def test_mining_timeout_surfaces_as_clean_job_error(client: TestClient, small_repo: Path, monkeypatch: pytest.MonkeyPatch):
    """`MiningTimeoutError` is a `churn.ChurnError` subclass - `_run_job`'s
    existing ChurnError handler must catch it exactly like NoGitHistoryError,
    surfacing a clean job error rather than an uncaught exception or a
    silently-hung job."""
    from mechanic import churn
    from mechanic.gui import server as gui_server

    def _timeout(*args, **kwargs):
        raise churn.MiningTimeoutError(small_repo, churn.DEFAULT_MINING_TIMEOUT_SECONDS)

    monkeypatch.setattr(gui_server.churn, "mine_commits_cached", _timeout)
    job_id = _load_and_wait(client, small_repo)
    status = client.get(f"/api/jobs/{job_id}").json()
    assert status["status"] == "error"
    assert "timeout" in status["error"].lower() or "exceeded" in status["error"].lower()


def test_zero_rules_directory_does_not_crash(client: TestClient, tmp_path: Path):
    repo = tmp_path / "empty_repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "A")
    (repo / ".gitkeep").write_text("")
    env = {**os.environ, "GIT_AUTHOR_DATE": "2020-01-01T00:00:00", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00"}
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True, capture_output=True, env=env)

    job_id = _load_and_wait(client, repo, subdir="rules")
    status = client.get(f"/api/jobs/{job_id}").json()
    assert status["status"] in ("done", "error")  # never hangs, never crashes the server


# --- Stop button: cancellation, and the live "detail" field ---------------


def test_job_status_dict_includes_detail_field(client: TestClient, small_repo: Path):
    job_id = _load_and_wait(client, small_repo)
    status = client.get(f"/api/jobs/{job_id}").json()
    assert "detail" in status  # present even once done (empty by then is fine)


def test_run_job_stops_immediately_when_cancel_already_requested(small_repo: Path):
    """Unit-level, no threading/HTTP races: pre-set the cancel flag, run
    the job function directly, and check it lands on "cancelled" rather
    than running compute_triage to completion or dying as a generic
    "error". This is what `POST /api/jobs/{id}/cancel` relies on - it
    just sets this same flag on a job already running in its own thread."""
    job = Job(id="t1", path=str(small_repo), fmt="sigma", subdir="rules", mechanical_threshold=0.10)
    job.cancel_requested.set()
    _run_job(job)
    assert job.status == "cancelled"
    assert job.report is None
    assert job.finished_at is not None


def test_cancel_endpoint_unknown_job_404(client: TestClient):
    assert client.post("/api/jobs/does-not-exist/cancel").status_code == 404


def test_cancel_endpoint_on_finished_job_is_a_safe_noop(client: TestClient, small_repo: Path):
    """Cancelling a job that already finished can't un-finish it - the
    endpoint just returns its (unchanged) terminal status rather than
    erroring or corrupting the result."""
    job_id = _load_and_wait(client, small_repo)
    before = client.get(f"/api/jobs/{job_id}").json()
    assert before["status"] == "done"
    resp = client.post(f"/api/jobs/{job_id}/cancel")
    assert resp.status_code == 200
    assert resp.json()["status"] == "done"
    # The already-fetched result is still there, untouched.
    assert client.get(f"/api/jobs/{job_id}/result").status_code == 200


def test_result_after_cancel_returns_422_not_425_forever(client: TestClient, small_repo: Path):
    job = Job(id="t2", path=str(small_repo), fmt="sigma", subdir="rules", mechanical_threshold=0.10)
    job.cancel_requested.set()
    _run_job(job)
    from mechanic.gui import server as server_module

    with server_module._JOBS_LOCK:
        server_module._JOBS[job.id] = job
    resp = client.get(f"/api/jobs/{job.id}/result")
    assert resp.status_code == 422
    assert "cancel" in resp.json()["detail"].lower()


def test_cancel_via_http_reaches_a_terminal_state(client: TestClient, small_repo: Path):
    """Best-effort end-to-end smoke test through the real HTTP + threading
    stack (racy by nature on a tiny/fast repo, same style as
    test_result_before_done_returns_425): whichever of the two legitimate
    outcomes wins the race, the server must not hang or 500."""
    resp = client.post("/api/load", json={"path": str(small_repo), "fmt": "sigma", "subdir": "rules"})
    job_id = resp.json()["job_id"]
    client.post(f"/api/jobs/{job_id}/cancel")
    deadline = time.time() + 10.0
    status = "pending"
    while time.time() < deadline:
        status = client.get(f"/api/jobs/{job_id}").json()["status"]
        if status in ("done", "cancelled", "error"):
            break
        time.sleep(0.05)
    assert status in ("done", "cancelled", "error")


# --- Task 8: job persistence across a server restart -----------------------


def test_job_survives_a_simulated_restart(tmp_path: Path, small_repo: Path):
    """A finished job, looked up via a BRAND NEW create_app() call against
    the same db_path (simulating the server process dying and restarting),
    must still be there with its real result - not silently lost."""
    from mechanic.gui import job_store

    db_path = tmp_path / "gui_jobs.sqlite3"
    client1 = TestClient(create_app(db_path=db_path))
    job_id = _load_and_wait(client1, small_repo)
    result_before = client1.get(f"/api/jobs/{job_id}/result", params={"ordering": "tier_first"}).json()

    # Simulate a restart: a fresh app instance, same db_path, no shared
    # Python state carried over on purpose (re-imports would be a stronger
    # simulation than this process allows, but a fresh create_app() call
    # re-reading from disk is exactly the code path an actual restart runs).
    client2 = TestClient(create_app(db_path=db_path))
    status_after = client2.get(f"/api/jobs/{job_id}").json()
    assert status_after["status"] == "done"
    # A restored job's report is persisted as a plain dict (see
    # job_store.save_job), so - same as the pre-existing "load from report"
    # behavior this deliberately matches - `ordering`/`top_n` query params
    # are no longer re-applied server-side; the persisted JSON is already
    # baked with TriageReport.to_dict()'s own default ordering
    # ("tier_first"), so that's what's requested here for a fair comparison.
    result_after = client2.get(f"/api/jobs/{job_id}/result", params={"ordering": "tier_first"}).json()
    assert result_after == result_before


def test_running_job_marked_interrupted_after_restart(tmp_path: Path):
    """A job that was NOT in a terminal state when persisted (simulating
    the process dying mid-computation) must come back as `interrupted` at
    the next startup - never silently `done`, and never left looking like
    it's still in progress forever."""
    from mechanic.gui import job_store

    db_path = tmp_path / "gui_jobs.sqlite3"
    conn = job_store.connect(db_path)
    fake_job = Job(id="was-running", path="/some/repo", fmt="sigma", subdir="rules", mechanical_threshold=0.10)
    fake_job.status = "semantic_diff"  # mid-flight when "the process died"
    job_store.save_job(conn, fake_job)
    conn.close()

    client = TestClient(create_app(db_path=db_path))
    status = client.get("/api/jobs/was-running").json()
    assert status["status"] == "interrupted"


def test_interrupted_job_result_is_409_not_a_fake_success(tmp_path: Path):
    from mechanic.gui import job_store

    db_path = tmp_path / "gui_jobs.sqlite3"
    conn = job_store.connect(db_path)
    fake_job = Job(id="was-running2", path="/some/repo", fmt="sigma", subdir="rules", mechanical_threshold=0.10)
    fake_job.status = "classifying"
    job_store.save_job(conn, fake_job)
    conn.close()

    client = TestClient(create_app(db_path=db_path))
    resp = client.get("/api/jobs/was-running2/result")
    assert resp.status_code == 409


def test_interrupted_job_cancel_is_a_safe_noop(tmp_path: Path):
    from mechanic.gui import job_store

    db_path = tmp_path / "gui_jobs.sqlite3"
    conn = job_store.connect(db_path)
    fake_job = Job(id="was-running3", path="/some/repo", fmt="sigma", subdir="rules", mechanical_threshold=0.10)
    fake_job.status = "mining"
    job_store.save_job(conn, fake_job)
    conn.close()

    client = TestClient(create_app(db_path=db_path))
    resp = client.post("/api/jobs/was-running3/cancel")
    assert resp.status_code == 200
    assert resp.json()["status"] == "interrupted"


def test_failed_job_survives_restart_with_its_error(tmp_path: Path):
    """A `done`/`error`/`cancelled` job is a genuinely terminal, correctly
    persisted state - NOT reclassified as interrupted on restart."""
    from mechanic.gui import job_store

    db_path = tmp_path / "gui_jobs.sqlite3"
    conn = job_store.connect(db_path)
    fake_job = Job(id="failed-job", path="/no/such/repo", fmt="sigma", subdir="rules", mechanical_threshold=0.10)
    fake_job.status = "error"
    fake_job.error = "no git history"
    fake_job.finished_at = time.time()
    job_store.save_job(conn, fake_job)
    conn.close()

    client = TestClient(create_app(db_path=db_path))
    status = client.get("/api/jobs/failed-job").json()
    assert status["status"] == "error"
    assert status["error"] == "no git history"


def test_restored_done_job_repopulates_rule_history(tmp_path: Path, small_repo: Path):
    """A restored `done` job's rule-history tab must recover (via
    `_mine_for_history_async`, a disk-cache HIT since the repo hasn't moved)
    rather than staying permanently unavailable just because `all_facts`
    itself is never persisted."""
    db_path = tmp_path / "gui_jobs.sqlite3"
    client1 = TestClient(create_app(db_path=db_path))
    job_id = _load_and_wait(client1, small_repo)

    client2 = TestClient(create_app(db_path=db_path))
    deadline = time.time() + 15.0
    history = None
    while time.time() < deadline:
        resp = client2.get(f"/api/jobs/{job_id}/rule-history", params={"file": "good.yml"})
        if resp.status_code == 200:
            history = resp.json()
            break
        time.sleep(0.1)
    assert history is not None, "rule-history never recovered after simulated restart"


def test_progress_ticks_are_not_persisted_on_every_call(tmp_path: Path, small_repo: Path, monkeypatch):
    """Durability writes happen on STAGE TRANSITIONS, not every done/total
    tick - `_run_job`'s real `progress_cb`, exercised directly, firing many
    times within the SAME stage must not turn into that many SQLite
    writes."""
    from mechanic.gui import job_store, server as server_module

    db_path = tmp_path / "gui_jobs.sqlite3"
    conn = job_store.connect(db_path)
    server_module._DB_CONN = conn

    write_count = {"n": 0}
    real_save = job_store.save_job

    def _counting_save(conn_, job_):
        write_count["n"] += 1
        return real_save(conn_, job_)

    monkeypatch.setattr(job_store, "save_job", _counting_save)

    def _fake_compute_triage(root, fmt, mechanical_threshold, subdir=None, all_facts=None, progress_cb=None, **kwargs):
        # One real stage transition ("classifying"), then 50 ticks WITHIN
        # that same stage - exactly the shape the dominant real stages
        # (semantic_diff/classifying) actually produce on a big repo.
        for i in range(50):
            progress_cb("classifying", i, 50, f"rule{i}.yml")
        return priority.TriageReport(
            root=str(root), fmt=fmt, mechanical_threshold=mechanical_threshold,
            rule_count=0, scoreable=[], unscoreable=[], disclosure="",
        )

    monkeypatch.setattr(server_module.churn, "mine_commits_cached", lambda *a, **k: [])
    monkeypatch.setattr(server_module.priority, "compute_triage", _fake_compute_triage)

    job = Job(id="tick-test", path=str(small_repo), fmt="sigma", subdir="rules", mechanical_threshold=0.10)
    server_module._run_job(job)

    conn.close()
    # One write for the mining->classifying transition, one for the final
    # "done" terminal state - never anywhere near the 50 progress ticks.
    assert write_count["n"] <= 2
