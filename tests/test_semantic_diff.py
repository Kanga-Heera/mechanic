"""Semantic diff (Part 1) tests.

Two layers, matching the module's own (a)/(b)/(c) waterfall:
  - Direct `classify_change()` unit tests against raw YAML text - fast,
    exercise each classification tier and bucket precisely.
  - One synthetic git repo (same real-`git`-commands style as
    test_churn.py's `synthetic_repo` fixture) with one commit per bucket
    type, run through the full Pass 1 -> Pass 2 pipeline
    (`semantic_diff.compute_semantic_diff`), per the Stage 2 spec's explicit
    requirement.
"""

import os
import subprocess
from pathlib import Path

import pytest

from mechanic import churn, semantic_diff

VALID_RULE = """title: {title}
id: 11111111-1111-1111-1111-111111111111
status: {status}
description: {description}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '{image}'
  condition: selection
level: {level}
"""


def _rule_text(title="T", status="experimental", description="d", image="\\cmd.exe", level="medium") -> str:
    return VALID_RULE.format(title=title, status=status, description=description, image=image, level=level)


# ---------------------------------------------------------------------------
# Direct classify_change unit tests
# ---------------------------------------------------------------------------


def test_cosmetic_title_and_description_only():
    before = _rule_text(title="Old Title", description="old description")
    after = _rule_text(title="New Title", description="new description")
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.bucket == "cosmetic"
    assert result.method == "ast"
    assert result.confidence == "high"


def test_behavioral_detection_change():
    before = _rule_text(image="\\cmd.exe")
    after = _rule_text(image="\\powershell.exe")
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.bucket == "behavioral"
    assert result.method == "ast"


def test_behavioral_logsource_change():
    before = _rule_text()
    after = before.replace("product: windows", "product: linux")
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.bucket == "behavioral"


def test_semantic_metadata_level_change():
    before = _rule_text(level="low")
    after = _rule_text(level="high")
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.bucket == "semantic_metadata"
    assert result.method == "ast"


def test_semantic_metadata_status_change():
    before = _rule_text(status="experimental")
    after = _rule_text(status="stable")
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.bucket == "semantic_metadata"


def test_identical_content_is_cosmetic():
    text = _rule_text()
    result = semantic_diff.classify_change(text, text, Path("x.yml"))
    assert result.bucket == "cosmetic"
    assert result.detail == "byte-identical content"


def test_yaml_key_fallback_when_one_side_broken():
    before = _rule_text()
    # 'after' is broken (bare-int id crashes SigmaRule construction) but still
    # valid YAML, so this must fall back to (b), not (c).
    after = before.replace(
        "id: 11111111-1111-1111-1111-111111111111", "id: 12345"
    ).replace("Image|endswith: '\\cmd.exe'", "Image|endswith: '\\powershell.exe'")
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.method == "yaml_key"
    assert result.confidence == "medium"
    assert result.bucket == "behavioral"  # detection: block differs


def test_elastic_toml_query_change_is_behavioral():
    before = 'name = "T"\n[rule]\nname = "T"\nquery = "process.name : \\"cmd.exe\\""\nlanguage = "kuery"\n'
    after = 'name = "T"\n[rule]\nname = "T"\nquery = "process.name : \\"powershell.exe\\""\nlanguage = "kuery"\n'
    result = semantic_diff.classify_change(before, after, Path("x.toml"), fmt="elastic_toml")
    assert result.bucket == "behavioral"
    assert result.confidence == "medium"


def test_elastic_toml_description_change_is_cosmetic():
    before = '[rule]\nname = "T"\ndescription = "old desc"\nquery = "process.name : \\"cmd.exe\\""\n'
    after = '[rule]\nname = "T"\ndescription = "new desc"\nquery = "process.name : \\"cmd.exe\\""\n'
    result = semantic_diff.classify_change(before, after, Path("x.toml"), fmt="elastic_toml")
    assert result.bucket == "cosmetic"


def test_splunk_yaml_search_change_is_behavioral_not_cosmetic():
    """Without format-awareness, Splunk's `search:` key isn't in Sigma's
    BEHAVIORAL_KEYS at all - this would silently misclassify as cosmetic."""
    before = "name: T\nsearch: '`sysmon` EventCode=1 Image=*cmd.exe'\ndescription: d\n"
    after = "name: T\nsearch: '`sysmon` EventCode=1 Image=*powershell.exe'\ndescription: d\n"
    result = semantic_diff.classify_change(before, after, Path("x.yml"), fmt="splunk_yaml")
    assert result.bucket == "behavioral"
    assert result.confidence == "medium"


def test_splunk_yaml_description_change_is_cosmetic():
    before = "name: T\nsearch: '`sysmon` EventCode=1'\ndescription: old\n"
    after = "name: T\nsearch: '`sysmon` EventCode=1'\ndescription: new\n"
    result = semantic_diff.classify_change(before, after, Path("x.yml"), fmt="splunk_yaml")
    assert result.bucket == "cosmetic"


def test_raw_text_fallback_when_neither_side_is_yaml():
    before = "this is not { yaml at all : ["
    after = "this is not { yaml at all : [ still broken but different"
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.confidence == "low"
    # No recognizable top-level `key:` structure in either garbled version.
    assert result.bucket is None
    assert result.method == "unknown"


def test_raw_text_fallback_detects_behavioral_section():
    before = "detection:\n  selection:\n    Image: a\n  condition: selection\ntitle: not: valid: yaml: here"
    after = "detection:\n  selection:\n    Image: b\n  condition: selection\ntitle: not: valid: yaml: here"
    result = semantic_diff.classify_change(before, after, Path("x.yml"))
    assert result.confidence == "low"
    assert result.bucket == "behavioral"
    assert result.method == "raw_text_section"


# ---------------------------------------------------------------------------
# Full pipeline: synthetic git repo, one commit per bucket
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _write(repo: Path, name: str, text: str) -> None:
    (repo / "rules" / name).write_text(text)


def _commit(repo: Path, msg: str, date: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    _git(repo, "add", "-A")
    subprocess.run(["git", "commit", "-q", "-m", msg], cwd=repo, check=True, capture_output=True, env=env)


@pytest.fixture
def bucket_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")

    # Creation commit for the file every later commit will edit.
    _write(repo, "target.yml", _rule_text(title="Target", description="d0", level="low"))
    _commit(repo, "add target", "2023-01-01T00:00:00")

    # Bulk mechanical commit so target.yml's creation-companions don't distort
    # rule_count-relative percentages (mirrors test_churn.py's synthetic_repo).
    for i in range(2, 12):
        _write(repo, f"rule{i}.yml", _rule_text(title=f"Rule {i}"))
    _commit(repo, "bulk import 10 rules", "2023-02-01T00:00:00")

    # cosmetic: title/description only
    _write(repo, "target.yml", _rule_text(title="Target Renamed", description="d1", level="low"))
    _commit(repo, "cosmetic: reword title", "2023-03-01T00:00:00")

    # semantic_metadata: level only
    _write(repo, "target.yml", _rule_text(title="Target Renamed", description="d1", level="high"))
    _commit(repo, "bump severity", "2023-04-01T00:00:00")

    # behavioral: detection change
    _write(
        repo,
        "target.yml",
        _rule_text(title="Target Renamed", description="d1", level="high", image="\\rundll32.exe"),
    )
    _commit(repo, "widen detection", "2023-05-01T00:00:00")

    # creation: a brand new rule added organically (not part of the bulk commit)
    _write(repo, "new_rule.yml", _rule_text(title="New Rule"))
    _commit(repo, "add new rule organically", "2023-06-01T00:00:00")

    return repo


def test_full_pipeline_one_commit_per_bucket(bucket_repo: Path):
    staleness = churn.compute_staleness(bucket_repo, fmt="sigma", mechanical_threshold=0.10)
    report = semantic_diff.compute_semantic_diff(bucket_repo, fmt="sigma", staleness_report=staleness)

    by_file = {r.file: r for r in report.staleness.rules}
    target = by_file["rules/target.yml"]
    assert target.behavioral_commit_count == 1
    assert target.semantic_metadata_commit_count == 1
    assert target.cosmetic_commit_count == 1
    assert target.classification_confidence == "high"
    assert target.last_behavioral_change.isoformat() == "2023-05-01"

    new_rule = by_file["rules/new_rule.yml"]
    assert new_rule.behavioral_commit_count == 0
    assert new_rule.cosmetic_commit_count == 0
    assert new_rule.semantic_metadata_commit_count == 0
    # Its only organic commit was its own creation - correctly excluded from
    # every bucket, not silently counted as e.g. cosmetic.

    assert report.creation_touches == 2  # target.yml + new_rule.yml
    assert report.classified_touches == 3  # cosmetic + semantic_metadata + behavioral on target.yml
    assert report.method_counts.get("ast") == 3


def test_behavioral_staleness_summary_matches_convention(bucket_repo: Path):
    staleness = churn.compute_staleness(bucket_repo, fmt="sigma", mechanical_threshold=0.10)
    report = semantic_diff.compute_semantic_diff(bucket_repo, fmt="sigma", staleness_report=staleness)
    summary = semantic_diff.behavioral_summary(report.staleness)
    assert summary["rule_count"] == 12
    # 10 bulk rules (never behaviorally touched) + new_rule.yml (only created) = 11
    assert summary["rules_with_no_behavioral_history"] == 11
