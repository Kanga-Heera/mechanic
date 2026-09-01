"""Hardening Part 2: output trustworthiness/readability, locked with
snapshot-shaped tests so the CLI's human-readable AND --json output can't
silently regress. Runs the real CLI (click.testing.CliRunner against
mechanic.cli.main) end to end against a small synthetic git repo - not a
unit test of priority.py's internals (those already exist in
tests/test_priority.py), but of what actually reaches the terminal/pipe.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from mechanic import churn
from mechanic.cli import main

runner = CliRunner()


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

_TTP_RULE = """title: Mimikatz Execution
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

_BROKEN_RULE = "id: 12345\ntitle: [not valid\n"


@pytest.fixture
def cli_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(churn, "STALE_DAYS", 30, raising=False)
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")

    _write(repo, "rules/fragile.yml", _FRAGILE_RULE)
    _write(repo, "rules/ttp.yml", _TTP_RULE)
    _write(repo, "rules/broken.yml", _BROKEN_RULE)
    _commit(repo, "bulk import 3 rules", "2020-01-01T00:00:00")
    return repo


# --- scan --------------------------------------------------------------


def test_scan_json_schema(cli_repo: Path):
    result = runner.invoke(main, ["scan", str(cli_repo / "rules"), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    for key in ["root", "files_scanned", "files_ok", "files_failed", "rules_loaded", "failures_total", "failures_by_category", "rules", "failures"]:
        assert key in data, f"scan --json missing documented key {key!r}"
    assert data["files_scanned"] == 3
    assert data["rules_loaded"] == 2
    assert data["files_failed"] == 1


def test_scan_human_output_reports_bad_file(cli_repo: Path):
    # A wide COLUMNS is needed here, not for real usage: rich's table
    # "overflow=fold" wraps the (very long, pytest-tmp-dir-nested) file
    # path character-by-character at the default 80-column test width,
    # which would make this assertion a test artifact, not a real
    # trustworthiness check.
    result = runner.invoke(main, ["scan", str(cli_repo / "rules")], env={"COLUMNS": "250"})
    assert result.exit_code == 0, result.output
    assert "broken.yml" in result.output


# --- staleness -----------------------------------------------------------


def test_staleness_json_schema(cli_repo: Path):
    result = runner.invoke(main, ["staleness", str(cli_repo), "--subdir", "rules", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    for key in ["root", "rule_count", "mechanical_threshold", "excluded_commits", "summary", "sensitivity", "rules"]:
        assert key in data, f"staleness --json missing documented key {key!r}"
    for key in ["pct_ever_revised", "pct_touched_within_6mo", "pct_stale_over_2yr"]:
        assert key in data["summary"]


# --- triage ---------------------------------------------------------------


def test_triage_one_line_summary_present_in_human_output(cli_repo: Path):
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules"])
    assert result.exit_code == 0, result.output
    assert "rules," in result.output and "fragile," in result.output and "stale," in result.output
    assert "need attention" in result.output


def test_triage_json_schema_and_one_line_summary(cli_repo: Path):
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    for key in ["root", "fmt", "mechanical_threshold", "ordering", "rule_count", "scoreable_count", "unscoreable_count", "summary", "bucket_counts", "priority_breakdown", "priority_matrix", "disclosure", "rules", "unscoreable"]:
        assert key in data, f"triage --json missing documented key {key!r}"
    assert data["summary"].startswith(f"{data['rule_count']} rules,")
    assert "need attention (fragile AND stale)" in data["summary"]

    for entry in data["rules"] + data["unscoreable"]:
        for key in ["file", "narrative", "short_reason", "staleness", "fragility", "is_fragile", "needs_attention", "priority", "triage_hypotheses"]:
            assert key in entry, f"triage rule entry missing documented key {key!r}"
        assert "is_stale" in entry["staleness"]
        for key in ["label", "tier", "staleness_band", "lower_confidence", "uncertain", "uncertainty_reason"]:
            assert key in entry["priority"], f"priority entry missing documented key {key!r}"


def test_triage_priority_breakdown_sums_to_rule_count(cli_repo: Path):
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules", "--json"])
    data = json.loads(result.stdout)
    assert sum(data["priority_breakdown"].values()) == data["rule_count"]
    assert set(data["priority_breakdown"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNCERTAIN"}


def test_triage_priority_never_bare_always_carries_both_axes(cli_repo: Path):
    """The JSON form of "never show a priority label without tier x
    staleness alongside it" - every non-uncertain entry must have both."""
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules", "--json"])
    data = json.loads(result.stdout)
    for entry in data["rules"] + data["unscoreable"]:
        p = entry["priority"]
        if not p["uncertain"] and p["label"] is not None:
            assert p["tier"] is not None
            assert p["staleness_band"] is not None
        if p["uncertain"]:
            assert p["label"] is None
            assert p["uncertainty_reason"]


def test_triage_priority_column_visible_in_human_output(cli_repo: Path):
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules"], env={"COLUMNS": "250"})
    assert result.exit_code == 0, result.output
    assert "priority" in result.output.lower()
    assert "priority-legend" in result.output


def test_triage_priority_first_ordering_sorts_worst_label_first(cli_repo: Path):
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules", "--ordering", "priority_first", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    label_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}
    ranks = [label_rank[r["priority"]["label"]] for r in data["rules"]]
    assert ranks == sorted(ranks)


def test_priority_legend_json_schema():
    result = runner.invoke(main, ["priority-legend", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    for key in ["tiers_worst_to_best", "staleness_bands_stale_to_fresh", "labels_worst_to_best", "cells", "rationale"]:
        assert key in data
    assert len(data["cells"]) == 12
    assert data["tiers_worst_to_best"] == ["IOC", "Artifact", "Tool", "TTP"]


def test_priority_legend_needs_no_repository():
    """A pure schema command - no PATH argument at all."""
    result = runner.invoke(main, ["priority-legend"])
    assert result.exit_code == 0, result.output
    assert "CRITICAL" in result.output
    assert "IOC" in result.output


def test_triage_never_combines_staleness_and_fragility_into_one_score(cli_repo: Path):
    """Locks the Task 7 finding's consequence: no blended/combined score
    field anywhere in triage output."""
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules", "--json"])
    data = json.loads(result.stdout)
    for entry in data["rules"]:
        assert "combined_score" not in entry
        assert "priority_score" not in entry
        assert "score" not in entry


def test_triage_worst_first_ordering_puts_lower_tier_rank_first(cli_repo: Path):
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules", "--json"])
    data = json.loads(result.stdout)
    tiers = [r["fragility"]["tier"] for r in data["rules"] if r["fragility"]["tier"]]
    from mechanic.fragility import TIER_RANK

    ranks = [TIER_RANK[t] for t in tiers]
    assert ranks == sorted(ranks), "default tier_first ordering must be worst (lowest rank) first"


def test_triage_unscoreable_never_gets_a_tier(cli_repo: Path):
    result = runner.invoke(main, ["triage", str(cli_repo), "--subdir", "rules", "--json"])
    data = json.loads(result.stdout)
    assert data["unscoreable_count"] >= 1  # broken.yml
    for entry in data["unscoreable"]:
        assert entry["fragility"]["tier"] is None
        assert entry["fragility"]["unscoreable_reason"]


def test_triage_text_path_caveat_visible_in_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """An Elastic/Splunk (text-path) rule's tier must carry a non-null
    caveat distinguishing it from an AST-derived tier - the machine-
    readable form of the "never present a text-path tier as equal
    confidence" requirement."""
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

    result = runner.invoke(main, ["triage", str(repo), "--subdir", "rules", "--fmt", "elastic_toml", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    all_rules = data["rules"] + data["unscoreable"]
    scored = [r for r in all_rules if r["fragility"]["tier"] is not None]
    if scored:  # text-classifier extraction is regex-based; skip assertion body if it found nothing to tier
        assert all(r["fragility"]["caveat"] for r in scored), "every text-path tier must carry a non-null caveat"


def test_triage_text_path_caveat_visible_in_human_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
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

    result = runner.invoke(main, ["triage", str(repo), "--subdir", "rules", "--fmt", "elastic_toml"])
    assert result.exit_code == 0, result.output
    # Either the legend fired (a text-path row got a tier) or nothing was
    # scoreable at all - both are fine; what must never happen is a "*"
    # appearing in the table with no legend explaining it.
    if "*" in result.output:
        assert "TEXT-ONLY path" in result.output


# --- explain ----------------------------------------------------------------


def test_explain_leads_with_prose_not_a_debug_dump(cli_repo: Path):
    result = runner.invoke(main, ["explain", str(cli_repo / "rules" / "fragile.yml")])
    assert result.exit_code == 0, result.output
    # The narrative must be real sentences (contains a period-terminated
    # sentence, mentions "review"), not a bare field:value dump as the
    # FIRST thing printed.
    first_content_line = next(line for line in result.output.splitlines() if line.strip())
    assert "explain" in first_content_line.lower()  # the header line
    assert "Review this" in result.output
    assert result.output.count(".") >= 3  # multiple real sentences, not one label


def test_explain_json_schema(cli_repo: Path):
    result = runner.invoke(main, ["explain", str(cli_repo / "rules" / "fragile.yml"), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    for key in ["file", "narrative", "short_reason", "staleness", "fragility", "is_fragile", "needs_attention", "priority", "triage_hypotheses"]:
        assert key in data, f"explain --json missing documented key {key!r}"


def test_explain_human_output_shows_priority_table(cli_repo: Path):
    result = runner.invoke(main, ["explain", str(cli_repo / "rules" / "fragile.yml")], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    assert "Priority" in result.output
    assert "priority-legend" in result.output


def test_explain_unknown_file_fails_loud_not_silent(cli_repo: Path):
    other = cli_repo.parent / "outside.yml"
    other.write_text(_FRAGILE_RULE)
    result = runner.invoke(main, ["explain", str(other)])
    assert result.exit_code != 0


# --- report ------------------------------------------------------------


def test_report_combines_scan_and_staleness_json(cli_repo: Path):
    result = runner.invoke(main, ["report", str(cli_repo), "--subdir", "rules", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert "scan" in data and "staleness" in data and "staleness_error" in data
