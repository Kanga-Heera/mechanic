"""Priority/triage tests (Part 3) against a small synthetic git repo, same
pattern as test_churn.py: real `git` commands in a tmp_path fixture with
fixed GIT_AUTHOR_DATE/GIT_COMMITTER_DATE for deterministic ages, and a fixed
`as_of` passed to `compute_triage` so day-count assertions don't depend on
when the test actually runs."""

import os
import subprocess
from datetime import date
from pathlib import Path

import pytest

from mechanic import churn, priority

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


_FRAGILE_RULE = """title: Suspicious Named Pipe Value
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName: '\\testpipe'
    condition: selection
level: medium
"""

_TOOL_RULE = """title: Mimikatz Execution
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\mimikatz.exe'
    condition: selection
level: high
"""

_NEVER_REVISED_OLD_RULE = """title: Old Untouched Rule
id: 33333333-3333-3333-3333-333333333333
status: test
logsource:
    category: pipe_created
    product: windows
detection:
    selection:
        PipeName: '\\oldpipe'
    condition: selection
level: medium
"""


@pytest.fixture
def repo_with_history(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setattr(churn, "STALE_DAYS", 30, raising=False)
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")

    # Mechanical bulk-import commit (3 files at once, well above any
    # reasonable mechanical threshold for a 3-rule corpus).
    _write(repo, "rules/fragile.yml", _FRAGILE_RULE)
    _write(repo, "rules/tool.yml", _TOOL_RULE)
    _write(repo, "rules/old_untouched.yml", _NEVER_REVISED_OLD_RULE)
    _commit(repo, "bulk import 3 rules", "2020-01-01T00:00:00")

    # Organic revision of fragile.yml only - a real behavioral change.
    _write(
        repo,
        "rules/fragile.yml",
        _FRAGILE_RULE.replace("testpipe", "testpipe2"),
    )
    _commit(repo, "widen fragile.yml pipe match", "2020-06-01T00:00:00")

    return repo


def test_no_combined_score_field(repo_with_history: Path):
    """Task 7 found no association reliable enough to fuse the two axes -
    the report/record shape must not expose anything resembling a single
    FUSED priority number. `priority` itself is legitimate (added later,
    a transparent matrix LOOKUP over the two axes - see
    tests/test_priority_matrix.py) precisely because it always carries
    both axis values (`tier`, `staleness_band`) alongside the label,
    never collapsing them into one opaque number - that's what's asserted
    here, not the field's absence."""
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    d = report.to_dict()
    assert "priority_score" not in d
    for r in report.scoreable:
        rd = r.to_dict()
        assert "score" not in rd
        assert isinstance(rd["priority"], dict), "priority must be a {label, tier, staleness_band, ...} record"
        assert "score" not in rd["priority"]
        assert "priority_score" not in rd["priority"]
        # the two axes that produced the label must always be present, not
        # collapsible to just a bare label
        assert set(rd["priority"]) >= {"label", "tier", "staleness_band", "uncertain"}


def test_never_revised_flagged_distinctly_not_as_large_number(repo_with_history: Path):
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    by_file = {r.file: r for r in report.scoreable}
    assert by_file["rules/old_untouched.yml"].never_revised is True
    assert by_file["rules/old_untouched.yml"].days_since_behavioral_change is None
    assert by_file["rules/fragile.yml"].never_revised is False
    assert by_file["rules/fragile.yml"].days_since_behavioral_change is not None


def test_fragile_and_revised_gets_likely_repairable_hypothesis(repo_with_history: Path):
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    by_file = {r.file: r for r in report.scoreable}
    fragile = by_file["rules/fragile.yml"]
    assert fragile.fragility.tier in priority.FRAGILE_TIERS
    assert "likely-repairable" in fragile.triage_hypotheses


def test_old_never_revised_gets_telemetry_check_hypothesis(repo_with_history: Path):
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    by_file = {r.file: r for r in report.scoreable}
    old_rule = by_file["rules/old_untouched.yml"]
    assert old_rule.never_revised is True
    assert old_rule.age_days is not None and old_rule.age_days > churn.STALE_DAYS
    assert "likely-needs-telemetry-check" in old_rule.triage_hypotheses


def test_confidence_propagates_high_for_sigma_ast_path(repo_with_history: Path):
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    for r in report.scoreable:
        assert r.fragility.confidence == "high"
        assert r.fragility.and_or_corrected is True
        assert r.fragility.caveat is None


def test_sorted_scoreable_orders_by_tier_rank_first(repo_with_history: Path):
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    ordered = report.sorted_scoreable()
    ranks = [r.tier_rank for r in ordered if r.tier_rank is not None]
    assert ranks == sorted(ranks)


def test_unscoreable_never_defaulted(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(churn, "STALE_DAYS", 30, raising=False)
    repo = tmp_path / "repo2"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")
    # Missing logsource (required by pySigma) - fails to load, must land in
    # `unscoreable` with a reason, never a guessed tier.
    _write(
        repo,
        "rules/broken.yml",
        "title: Broken rule, no logsource\nid: 44444444-4444-4444-4444-444444444444\nstatus: test\n"
        "detection:\n    selection:\n        Image: notreal\n    condition: selection\n"
        "level: low\n",
    )
    _commit(repo, "add broken rule", "2020-01-01T00:00:00")

    report = priority.compute_triage(repo, "sigma", mechanical_threshold=0.9, as_of=AS_OF)
    files_unscoreable = {r.file for r in report.unscoreable}
    assert "rules/broken.yml" in files_unscoreable
    assert not any(r.file == "rules/broken.yml" for r in report.scoreable)
    match = next(r for r in report.unscoreable if r.file == "rules/broken.yml")
    assert match.fragility.tier is None
    assert match.fragility.unscoreable_reason is not None


def test_narrative_is_prose_and_mentions_key_facts(repo_with_history: Path):
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    by_file = {r.file: r for r in report.scoreable}
    fragile = by_file["rules/fragile.yml"]
    narrative = fragile.narrative
    assert isinstance(narrative, str)
    assert narrative.count(".") >= 3  # multiple real sentences, not a single fragment
    assert fragile.fragility.tier in narrative
    assert "Review this" in narrative
    assert "verdict" in narrative.lower()


def test_narrative_surfaces_and_or_caveat_for_text_path_tiers():
    """The AND/OR-correction caveat must render in the narrative ITSELF
    (what a user reading `mechanic explain` actually sees), not only in
    docs or a separate JSON field a reader could skip past."""
    frag = priority.FragilitySignal(
        tier="Tool",
        confidence="medium",
        and_or_corrected=False,
        unscoreable=False,
        unscoreable_reason=None,
        structural_findings=[],
        structural_detail={},
        atoms=[{"field": "process.name", "value": "mimikatz.exe", "negated": False}],
        caveat=priority._AND_OR_CAVEAT,
    )
    sig = priority.RuleSignals(
        file="rules/text_path_example.yml",
        behavioral_commit_count=0,
        never_revised=True,
        days_since_behavioral_change=None,
        age_days=940,
        staleness_classification_confidence=None,
        fragility=frag,
        triage_hypotheses=[],
    )
    narrative = sig.narrative
    assert "AND/OR" in narrative
    assert "does NOT use" in narrative or "does not use" in narrative.lower()
    assert "STP" in narrative


def test_narrative_omits_and_or_caveat_for_sigma_ast_path(repo_with_history: Path):
    report = priority.compute_triage(repo_with_history, "sigma", mechanical_threshold=0.5, as_of=AS_OF)
    for r in report.scoreable:
        assert "does NOT use" not in r.narrative


def test_deprecated_pipe_syntax_is_unscoreable_not_a_crash(tmp_path: Path):
    """Regression test for a real crash hit running triage against the full
    SigmaHQ corpus: a rule using the deprecated `condition: selection |
    count() by X > N` pipe syntax loads fine (valid YAML, valid SigmaRule
    construction) but pySigma's condition parser raises SigmaConditionError
    when the AST is actually built - which happened OUTSIDE
    `_sigma_fragility`'s original try/except, crashing triage for the whole
    corpus over one rule. One malformed rule must never do that - Stage 1's
    entire premise was exactly this kind of fault isolation."""
    repo = tmp_path / "repo3"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")
    _write(
        repo,
        "rules/pipe_syntax.yml",
        "title: Pipe syntax test\nid: 55555555-5555-5555-5555-555555555555\nstatus: test\n"
        "logsource:\n    category: process_creation\n    product: windows\n"
        "detection:\n    selection:\n        Image|endswith: '\\cmd.exe'\n"
        "    condition: selection | count() by ComputerName > 5\nlevel: low\n",
    )
    _commit(repo, "add pipe-syntax rule", "2020-01-01T00:00:00")

    report = priority.compute_triage(repo, "sigma", mechanical_threshold=0.9, as_of=AS_OF)
    files_unscoreable = {r.file for r in report.unscoreable}
    assert "rules/pipe_syntax.yml" in files_unscoreable
    match = next(r for r in report.unscoreable if r.file == "rules/pipe_syntax.yml")
    assert match.fragility.tier is None
    assert "AST build/classify failed" in match.fragility.unscoreable_reason


def test_malformed_elastic_rule_does_not_crash_the_batch(tmp_path: Path, monkeypatch):
    """`_sigma_fragility` already had dedicated crash-isolation regression
    tests (above); `_elastic_fragility`/`_splunk_fragility` had the same
    try/except structure but no end-to-end `compute_triage` test proving a
    malformed file of THOSE formats, mixed with a good one, doesn't kill the
    whole batch - this closes that gap."""
    monkeypatch.setattr(churn, "STALE_DAYS", 30, raising=False)
    repo = tmp_path / "repo_elastic"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")
    _write(repo, "rules/good.toml", '[rule]\nname = "Good"\ntype = "query"\nquery = \'process.name : "mimikatz.exe"\'\n')
    _write(repo, "rules/broken.toml", "this is not valid toml at all {{{ [[[ ===\n")
    _commit(repo, "add elastic rules", "2020-01-01T00:00:00")

    report = priority.compute_triage(repo, "elastic_toml", mechanical_threshold=0.9, as_of=AS_OF)
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

    report = priority.compute_triage(repo, "splunk_yaml", mechanical_threshold=0.9, as_of=AS_OF)
    all_files = {r.file for r in report.scoreable} | {r.file for r in report.unscoreable}
    assert {"rules/good.yml", "rules/broken.yml"} == all_files
    broken = next(r for r in report.unscoreable if r.file == "rules/broken.yml")
    assert broken.fragility.tier is None
    assert "failed to parse YAML" in broken.fragility.unscoreable_reason
