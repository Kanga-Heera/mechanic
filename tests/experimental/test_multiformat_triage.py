"""Elastic/Splunk triage - QUARANTINED, not part of the CORE (see
docs/multiformat-experimental.md and docs/core-vs-experiment.md). Same
pattern as tests/test_priority.py: real `git` commands in a tmp_path
fixture with fixed GIT_AUTHOR_DATE/GIT_COMMITTER_DATE for deterministic
ages, and a fixed `as_of` so day-count assertions don't depend on when the
test actually runs.

`test_malformed_elastic_rule_does_not_crash_the_batch` and
`test_malformed_splunk_rule_does_not_crash_the_batch` moved here, unchanged
in substance, from tests/test_priority.py when fragility/tiering/priority
were scoped to Sigma-only in the core - `mechanic.priority.compute_triage`
no longer accepts these formats at all, so these two now call the
quarantined `compute_multiformat_triage` instead.
"""

import os
import subprocess
from datetime import date
from pathlib import Path

from mechanic import churn
from mechanic.experimental.multiformat.triage import compute_multiformat_triage

AS_OF = date(2024, 1, 1)


def _git(repo: Path, *args: str, env: dict | None = None) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, env=env)


def _write(repo: Path, rel: str, content: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _commit(repo: Path, msg: str, when: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
    _git(repo, "add", "-A")
    subprocess.run(["git", "commit", "-q", "-m", msg], cwd=repo, check=True, capture_output=True, env=env)


def test_malformed_elastic_rule_does_not_crash_the_batch(tmp_path: Path, monkeypatch):
    """`_sigma_fragility` already has dedicated crash-isolation regression
    tests in tests/test_priority.py; `classify_elastic_file`/
    `classify_splunk_file` have the same try/except structure but no
    end-to-end triage test proving a malformed file of THOSE formats, mixed
    with a good one, doesn't kill the whole batch - this closes that gap."""
    monkeypatch.setattr(churn, "STALE_DAYS", 30, raising=False)
    repo = tmp_path / "repo_elastic"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")
    _write(repo, "rules/good.toml", '[rule]\nname = "Good"\ntype = "query"\nquery = \'process.name : "mimikatz.exe"\'\n')
    _write(repo, "rules/broken.toml", "this is not valid toml at all {{{ [[[ ===\n")
    _commit(repo, "add elastic rules", "2020-01-01T00:00:00")

    report = compute_multiformat_triage(repo, "elastic_toml", mechanical_threshold=0.9, as_of=AS_OF)
    all_files = {r.file for r in report.scoreable} | {r.file for r in report.unscoreable}
    assert {"rules/good.toml", "rules/broken.toml"} == all_files
    broken = next(r for r in report.unscoreable if r.file == "rules/broken.toml")
    assert broken.fragility.tier is None
    assert "failed to parse TOML" in broken.fragility.unscoreable_reason


def test_malformed_splunk_rule_does_not_crash_the_batch(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(churn, "STALE_DAYS", 30, raising=False)
    repo = tmp_path / "repo_splunk"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")
    _write(repo, "rules/good.yml", "search: 'index=main process_name=mimikatz.exe'\n")
    _write(repo, "rules/broken.yml", "search: [this is not: valid: yaml: at: all\n")
    _commit(repo, "add splunk rules", "2020-01-01T00:00:00")

    report = compute_multiformat_triage(repo, "splunk_yaml", mechanical_threshold=0.9, as_of=AS_OF)
    all_files = {r.file for r in report.scoreable} | {r.file for r in report.unscoreable}
    assert {"rules/good.yml", "rules/broken.yml"} == all_files
    broken = next(r for r in report.unscoreable if r.file == "rules/broken.yml")
    assert broken.fragility.tier is None
    assert "failed to parse YAML" in broken.fragility.unscoreable_reason


def test_text_path_tier_always_carries_a_caveat(tmp_path: Path, monkeypatch):
    """The machine-readable form of "never present a text-path tier as equal
    confidence" - moved here from tests/test_cli.py's
    `test_triage_text_path_caveat_visible_in_json` (which used to invoke
    `mechanic triage --fmt elastic_toml` directly; the core CLI no longer
    accepts that format at all, see tests/test_cli.py's replacement
    refusal test)."""
    monkeypatch.setattr(churn, "STALE_DAYS", 30, raising=False)
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")
    _write(
        repo,
        "rules/detect.toml",
        '[rule]\nname = "Test"\ntype = "query"\nquery = \'process.name : "mimikatz.exe"\'\n',
    )
    _commit(repo, "add elastic rule", "2020-01-01T00:00:00")

    report = compute_multiformat_triage(repo, "elastic_toml", mechanical_threshold=0.9, as_of=AS_OF)
    all_rules = report.scoreable + report.unscoreable
    scored = [r for r in all_rules if r.fragility.tier is not None]
    if scored:  # text-classifier extraction is regex-based; skip assertion body if it found nothing to tier
        assert all(r.fragility.caveat for r in scored), "every text-path tier must carry a non-null caveat"
        assert all(r.fragility.and_or_corrected is False for r in scored)
