"""Churn/staleness tests against a small synthetic git repo built with real
`git` commands in a tmp_path fixture (test-setup only - mechanic's own git
access, exercised below, goes exclusively through PyDriller)."""

import subprocess
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

    rule2 = by_file["rules/rule2.yml"]
    assert rule2.organic_commit_count == 1  # its creation was folded into the excluded bulk commit
    assert rule2.last_organic_commit_date.isoformat() == "2023-06-01"

    # rule3..rule11 were only ever touched by the excluded mechanical commit.
    rule5 = by_file["rules/rule5.yml"]
    assert rule5.organic_commit_count == 0
    assert rule5.last_organic_commit_date is None
    assert rule5.days_since is None


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


def test_mine_commits_cached_hit_avoids_remining(synthetic_repo: Path, monkeypatch):
    calls = []
    real_mine_commits = churn.mine_commits

    def _counting_mine_commits(root, fmt="sigma", subdir=None):
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

    def _counting_mine_commits(root, fmt="sigma", subdir=None):
        calls.append(1)
        return real_mine_commits(root, fmt, subdir=subdir)

    monkeypatch.setattr(churn, "mine_commits", _counting_mine_commits)

    churn.mine_commits_cached(synthetic_repo, fmt="sigma")
    churn.mine_commits_cached(synthetic_repo, fmt="sigma", refresh=True)
    assert len(calls) == 2


def test_mine_commits_cached_detects_new_commits_as_stale(synthetic_repo: Path, monkeypatch):
    calls = []
    real_mine_commits = churn.mine_commits

    def _counting_mine_commits(root, fmt="sigma", subdir=None):
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
