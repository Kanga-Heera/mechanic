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
from mechanic.gui.server import STATIC_DIR, create_app  # noqa: E402

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


def test_gui_has_no_repair_endpoints():
    """The API surface itself must never expose repair/verify/gate - not
    just "no import," but no route path suggesting it either."""
    app = create_app()
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
def client() -> TestClient:
    return TestClient(create_app())


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
