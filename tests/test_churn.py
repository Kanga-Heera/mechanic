"""Churn/staleness tests against a small synthetic git repo built with real
`git` commands in a tmp_path fixture (test-setup only - mechanic's own git
access, exercised below, goes exclusively through PyDriller)."""

import subprocess
from datetime import date
from pathlib import Path

import pytest

from mechanic import churn


def _git(repo: Path, *args: str, env: dict | None = None) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, env=env)


def _write_rule(repo: Path, name: str, title: str) -> Path:
    p = repo / "rules" / name
    p.write_text(f"title: {title}\ndetection:\n  selection:\n    Image: x\n  condition: selection\n")
    return p


@pytest.fixture
def synthetic_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")

    def commit(msg: str, date: str):
        env = {
            **__import__("os").environ,
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_DATE": date,
        }
        _git(repo, "add", "-A")
        subprocess.run(
            ["git", "commit", "-q", "-m", msg], cwd=repo, check=True, capture_output=True, env=env
        )

    # 1 organic creation
    _write_rule(repo, "rule1.yml", "Rule One")
    commit("add rule1", "2023-01-01T00:00:00")

    # A mass mechanical commit: 10 more files added at once (rule_count becomes 11,
    # so this commit touches 10/11 = 90.9% >= any reasonable threshold).
    for i in range(2, 12):
        _write_rule(repo, f"rule{i}.yml", f"Rule {i}")
    commit("bulk import 10 rules", "2023-02-01T00:00:00")

    # Organic revision of rule2.
    (repo / "rules" / "rule2.yml").write_text(
        "title: Rule 2 Updated\ndetection:\n  selection:\n    Image: y\n  condition: selection\n"
    )
    commit("tune rule2", "2023-06-01T00:00:00")

    return repo


def test_mechanical_commit_excluded_and_reported(synthetic_repo: Path):
    report = churn.compute_staleness(synthetic_repo, fmt="sigma", mechanical_threshold=0.10)
    assert report.rule_count == 11
    subjects = {c.subject for c in report.excluded_commits}
    assert "bulk import 10 rules" in subjects
    assert "add rule1" not in subjects
    assert "tune rule2" not in subjects


def test_organic_counts_correct_after_exclusion(synthetic_repo: Path):
    report = churn.compute_staleness(synthetic_repo, fmt="sigma", mechanical_threshold=0.10)
    by_file = {r.file: r for r in report.rules}

    rule1 = by_file["rules/rule1.yml"]
    assert rule1.organic_commit_count == 1
    assert rule1.ever_revised is False
    assert rule1.ever_revised_basis == "single_commit_creation"

    rule2 = by_file["rules/rule2.yml"]
    assert rule2.organic_commit_count == 1  # its creation was folded into the excluded bulk commit
    assert rule2.last_organic_commit_date.isoformat() == "2023-06-01"
    # rule2's ONE organic commit is a MODIFY of a file that already existed
    # (created inside the excluded bulk-import commit) - resolvably TRUE,
    # not the naive "one commit == never revised" reading.
    assert rule2.ever_revised is True
    assert rule2.ever_revised_basis == "single_commit_modification"

    # rule3..rule11 were only ever touched by the excluded mechanical commit.
    rule5 = by_file["rules/rule5.yml"]
    assert rule5.organic_commit_count == 0
    assert rule5.last_organic_commit_date is None
    assert rule5.days_since is None
    # Zero organic touches means zero signal - UNKNOWN, not a silent False.
    assert rule5.ever_revised is None
    assert rule5.ever_revised_basis == "no_organic_history"


def test_sensitivity_reports_all_three_thresholds(synthetic_repo: Path):
    report = churn.compute_staleness(synthetic_repo, fmt="sigma", mechanical_threshold=0.10)
    thresholds = {s.threshold for s in report.sensitivity}
    assert {0.05, 0.10, 0.20}.issubset(thresholds)


def test_summary_percentages(synthetic_repo: Path):
    report = churn.compute_staleness(synthetic_repo, fmt="sigma", mechanical_threshold=0.10)
    summary = report.summary()
    assert summary["rule_count"] == 11
    assert summary["rules_with_no_organic_history"] == 9  # rule3..rule11 minus rule2's later edit
    assert 0.0 <= summary["pct_ever_revised"] <= 100.0


def test_ever_revised_no_touches_is_unknown_not_false():
    result, basis = churn._ever_revised([])
    assert result is None
    assert basis == "no_organic_history"


def test_ever_revised_single_add_is_confidently_false():
    result, basis = churn._ever_revised([(date(2023, 1, 1), "ADD")])
    assert result is False
    assert basis == "single_commit_creation"


@pytest.mark.parametrize("change_type", ["MODIFY", "RENAME"])
def test_ever_revised_single_modify_or_rename_is_confidently_true(change_type):
    """The core fix: a lone organic commit is NOT automatically 'never
    revised' - if git's own change_type says the file already existed
    before this commit, a revision genuinely happened, even though its
    creation isn't itself visible in the organic set (e.g. it happened in
    an excluded mechanical bulk-import commit)."""
    result, basis = churn._ever_revised([(date(2023, 1, 1), change_type)])
    assert result is True
    assert basis == "single_commit_modification"


def test_ever_revised_multiple_touches_is_true_regardless_of_change_type():
    touches = [(date(2023, 1, 1), "ADD"), (date(2023, 6, 1), "MODIFY")]
    result, basis = churn._ever_revised(touches)
    assert result is True
    assert basis == "multiple_organic_commits"


def test_mine_with_timeout_none_is_a_pure_passthrough():
    """The default (timeout=None) must behave exactly as before this
    parameter existed - no thread, no wrapping, same return value."""
    calls = []

    def fn():
        calls.append(1)
        return ["result"]

    result = churn._mine_with_timeout(fn, Path("."), None)
    assert result == ["result"]
    assert len(calls) == 1


def test_mine_with_timeout_returns_normally_when_fast_enough():
    result = churn._mine_with_timeout(lambda: ["fact1", "fact2"], Path("."), timeout=5)
    assert result == ["fact1", "fact2"]


def test_mine_with_timeout_raises_mining_timeout_error_when_exceeded():
    import time

    def slow():
        time.sleep(2)
        return []

    with pytest.raises(churn.MiningTimeoutError):
        churn._mine_with_timeout(slow, Path("some/repo"), timeout=0.1)


def test_mine_with_timeout_reraises_the_real_exception_not_swallowed():
    """A genuine failure inside the mining thread must propagate as itself,
    not be reported as a timeout or silently swallowed into an empty/fake
    result."""

    def failing():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        churn._mine_with_timeout(failing, Path("."), timeout=5)


def test_compute_staleness_timeout_surfaces_as_mining_timeout_error(synthetic_repo: Path, monkeypatch):
    """A repo that legitimately hangs during mining must never produce a
    result at all (fabricated or otherwise) - it must raise, cleanly and
    quickly (bounded by `timeout`, not by however long the hang actually
    lasts)."""
    import time

    def _hanging_mine_commits(root, fmt, subdir_prefix, progress_cb=None):
        time.sleep(2)
        return []

    monkeypatch.setattr(churn, "_mine_commits", _hanging_mine_commits)
    with pytest.raises(churn.MiningTimeoutError):
        churn.compute_staleness(synthetic_repo, fmt="sigma", timeout=0.1)


def test_no_git_history_fails_clearly(tmp_path: Path):
    root = tmp_path / "no_git"
    (root / "rules").mkdir(parents=True)
    (root / "rules" / "a.yml").write_text("title: a\n")
    with pytest.raises(churn.NoGitHistoryError):
        churn.compute_staleness(root, fmt="sigma")


def test_shallow_clone_fails_clearly(synthetic_repo: Path):
    (synthetic_repo / ".git" / "shallow").write_text("")
    with pytest.raises(churn.ShallowRepositoryError):
        churn.compute_staleness(synthetic_repo, fmt="sigma")


def test_history_health_degraded_for_thin_history(synthetic_repo: Path):
    """`synthetic_repo` has exactly 3 total commits - below
    DEGRADED_HISTORY_MIN_COMMITS (5), so it should be flagged, not silently
    reported as if its percentages were statistically meaningful."""
    report = churn.compute_staleness(synthetic_repo, fmt="sigma", mechanical_threshold=0.10)
    assert report.history_health == "degraded"
    assert "insufficient_total_commits" in report.history_health_reasons


@pytest.fixture
def single_bulk_commit_repo(tmp_path: Path) -> Path:
    """Every rule is added in ONE commit - that commit necessarily touches
    100% of rule_count, so it is excluded as mechanical at any reasonable
    threshold and every rule ends up with organic_commit_count == 0. This is
    the shape `mechanical_threshold_excluded_all_history` exists to flag."""
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")
    for i in range(1, 6):
        _write_rule(repo, f"rule{i}.yml", f"Rule {i}")
    env = {**__import__("os").environ, "GIT_AUTHOR_DATE": "2023-01-01T00:00:00", "GIT_COMMITTER_DATE": "2023-01-01T00:00:00"}
    _git(repo, "add", "-A")
    subprocess.run(["git", "commit", "-q", "-m", "bulk import all rules"], cwd=repo, check=True, capture_output=True, env=env)
    return repo


def test_history_health_degraded_when_mechanical_filter_excludes_everything(single_bulk_commit_repo: Path):
    report = churn.compute_staleness(single_bulk_commit_repo, fmt="sigma", mechanical_threshold=0.10)
    assert all(r.organic_commit_count == 0 for r in report.rules)
    assert report.history_health == "degraded"
    assert "mechanical_threshold_excluded_all_history" in report.history_health_reasons
    # Every rule's ever_revised is honestly UNKNOWN here, not a silent False.
    assert all(r.ever_revised is None for r in report.rules)


def test_mine_commits_cached_hit_avoids_remining(synthetic_repo: Path, monkeypatch):
    calls = []
    real_mine_commits = churn.mine_commits

    def _counting_mine_commits(root, fmt="sigma", subdir=None, **kwargs):
        calls.append(1)
        return real_mine_commits(root, fmt, subdir=subdir)

    monkeypatch.setattr(churn, "mine_commits", _counting_mine_commits)

    first = churn.mine_commits_cached(synthetic_repo, fmt="sigma")
    assert len(calls) == 1
    assert (synthetic_repo / ".mechanic_cache").exists()

    second = churn.mine_commits_cached(synthetic_repo, fmt="sigma")
    assert len(calls) == 1  # no second mining pass - served from cache
    assert [f.hash for f in second] == [f.hash for f in first]


def test_mine_commits_cached_refresh_forces_remine(synthetic_repo: Path, monkeypatch):
    calls = []
    real_mine_commits = churn.mine_commits

    def _counting_mine_commits(root, fmt="sigma", subdir=None, **kwargs):
        calls.append(1)
        return real_mine_commits(root, fmt, subdir=subdir)

    monkeypatch.setattr(churn, "mine_commits", _counting_mine_commits)

    churn.mine_commits_cached(synthetic_repo, fmt="sigma")
    churn.mine_commits_cached(synthetic_repo, fmt="sigma", refresh=True)
    assert len(calls) == 2


def test_mine_commits_cached_detects_new_commits_as_stale(synthetic_repo: Path, monkeypatch):
    calls = []
    real_mine_commits = churn.mine_commits

    def _counting_mine_commits(root, fmt="sigma", subdir=None, **kwargs):
        calls.append(1)
        return real_mine_commits(root, fmt, subdir=subdir)

    monkeypatch.setattr(churn, "mine_commits", _counting_mine_commits)

    first = churn.mine_commits_cached(synthetic_repo, fmt="sigma")
    assert len(calls) == 1

    # Repo moves forward - a new commit lands after the cache was written.
    _write_rule(synthetic_repo, "rule12.yml", "Rule 12")
    _git(synthetic_repo, "add", "-A")
    subprocess.run(["git", "commit", "-q", "-m", "add rule12"], cwd=synthetic_repo, check=True, capture_output=True)

    second = churn.mine_commits_cached(synthetic_repo, fmt="sigma")
    assert len(calls) == 2  # stale cache detected, re-mined rather than silently reused
    assert len(second) == len(first) + 1
