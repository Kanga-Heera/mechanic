"""Priority-as-matrix (not a blended score): regression-locks the fixed
(tier, staleness band) -> label table itself, and the discipline that
uncertainty is always surfaced rather than folded into a confident-looking
label. See mechanic/priority.py's "Priority: an explicit 2-axis MATRIX"
section for the table and its documented rationale.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from mechanic import priority
from mechanic.priority import (
    PRIORITY_MATRIX,
    STALENESS_BANDS,
    FragilitySignal,
    RuleSignals,
    compute_priority,
    priority_matrix_schema,
    staleness_band,
)

TIERS_WORST_TO_BEST = ["IOC", "Artifact", "Tool", "TTP"]


def _sig(
    *,
    tier: str | None,
    days: int | None,
    never_revised: bool = False,
    unscoreable: bool = False,
    caveat: str | None = None,
) -> RuleSignals:
    frag = FragilitySignal(
        tier=tier,
        confidence="high" if caveat is None else "medium",
        and_or_corrected=caveat is None,
        unscoreable=unscoreable,
        unscoreable_reason="synthetic unscoreable" if unscoreable else None,
        structural_findings=[],
        structural_detail={},
        atoms=[],
        caveat=caveat,
    )
    return RuleSignals(
        file="rules/x.yml",
        behavioral_commit_count=0 if never_revised else 1,
        never_revised=never_revised,
        days_since_behavioral_change=None if never_revised else days,
        age_days=days if never_revised else (days + 100 if days is not None else None),
        staleness_classification_confidence="high",
        fragility=frag,
    )


# --- the matrix table itself, locked cell by cell --------------------------

_EXPECTED_CELLS = {
    ("IOC", "stale_over_2yr"): "CRITICAL",
    ("IOC", "aging_6mo_to_2yr"): "HIGH",
    ("IOC", "fresh_under_6mo"): "MEDIUM",
    ("Artifact", "stale_over_2yr"): "CRITICAL",
    ("Artifact", "aging_6mo_to_2yr"): "HIGH",
    ("Artifact", "fresh_under_6mo"): "MEDIUM",
    ("Tool", "stale_over_2yr"): "HIGH",
    ("Tool", "aging_6mo_to_2yr"): "MEDIUM",
    ("Tool", "fresh_under_6mo"): "LOW",
    ("TTP", "stale_over_2yr"): "MEDIUM",
    ("TTP", "aging_6mo_to_2yr"): "LOW",
    ("TTP", "fresh_under_6mo"): "LOW",
}


def test_matrix_has_exactly_twelve_cells_all_four_labels_used():
    assert PRIORITY_MATRIX == _EXPECTED_CELLS
    assert len(PRIORITY_MATRIX) == 12
    assert set(PRIORITY_MATRIX.values()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


@pytest.mark.parametrize("tier,band,expected", [(t, b, lbl) for (t, b), lbl in _EXPECTED_CELLS.items()])
def test_matrix_cell_locked(tier: str, band: str, expected: str):
    """Fixed (tier, band) -> label, so the mapping can't drift silently."""
    assert PRIORITY_MATRIX[(tier, band)] == expected


def test_worse_tier_never_gets_a_better_priority_than_a_more_durable_tier_at_the_same_staleness():
    """IOC (worst/least durable) must never rank BETTER than a more durable
    tier at the same staleness band - this is the correctness property the
    row ordering exists to guarantee (mechanic's own tier semantics: IOC is
    "the least durable kind of match possible", TTP "the most durable" -
    see RuleSignals.narrative's tier_meaning, and the STP external
    validation, RESULTS.md, confirming this direction)."""
    label_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    for band in STALENESS_BANDS:
        ranks = [label_rank[PRIORITY_MATRIX[(tier, band)]] for tier in TIERS_WORST_TO_BEST]
        assert ranks == sorted(ranks, reverse=True), (
            f"priority must be non-increasing from IOC->TTP at band={band!r}, got {ranks}"
        )


def test_more_stale_never_gets_a_better_priority_than_less_stale_at_the_same_tier():
    label_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    stale_to_fresh = ["stale_over_2yr", "aging_6mo_to_2yr", "fresh_under_6mo"]
    for tier in TIERS_WORST_TO_BEST:
        ranks = [label_rank[PRIORITY_MATRIX[(tier, band)]] for band in stale_to_fresh]
        assert ranks == sorted(ranks, reverse=True), (
            f"priority must be non-increasing from stale->fresh at tier={tier!r}, got {ranks}"
        )


# --- staleness_band() ------------------------------------------------------


def test_staleness_band_boundaries():
    assert staleness_band(_sig(tier="TTP", days=731)) == "stale_over_2yr"
    assert staleness_band(_sig(tier="TTP", days=730)) == "aging_6mo_to_2yr"  # boundary: NOT yet over 2yr
    assert staleness_band(_sig(tier="TTP", days=182)) == "aging_6mo_to_2yr"  # boundary: NOT yet under 6mo
    assert staleness_band(_sig(tier="TTP", days=181)) == "fresh_under_6mo"
    assert staleness_band(_sig(tier="TTP", days=None)) is None


def test_staleness_band_never_revised_uses_age_days():
    sig = _sig(tier="TTP", days=800, never_revised=True)
    assert sig.age_days == 800
    assert staleness_band(sig) == "stale_over_2yr"


# --- compute_priority(): uncertainty is always surfaced, never hidden ------


def test_unscoreable_rule_gets_no_confident_label():
    sig = _sig(tier=None, days=1000, unscoreable=True)
    p = compute_priority(sig)
    assert p.label is None
    assert p.uncertain is True
    assert p.uncertainty_reason


def test_unknown_staleness_gets_no_confident_label_even_with_a_tier():
    sig = _sig(tier="IOC", days=None)
    p = compute_priority(sig)
    assert p.label is None
    assert p.tier == "IOC"  # the known axis is still reported
    assert p.uncertain is True
    assert "staleness" in p.uncertainty_reason.lower()


def test_text_path_caveat_marks_priority_lower_confidence_not_uncertain():
    """A text-path (Elastic/Splunk) tier IS still confident enough to
    produce a label - it's lower-confidence, tagged as such, not withheld
    the way a genuinely unscoreable/unknown-band case is."""
    sig = _sig(tier="Tool", days=1000, caveat="text-only path caveat text")
    p = compute_priority(sig)
    assert p.label == "HIGH"
    assert p.lower_confidence is True
    assert p.uncertain is False


def test_normal_case_produces_label_with_both_axes_present():
    sig = _sig(tier="IOC", days=1000)
    p = compute_priority(sig)
    assert p.label == "CRITICAL"
    assert p.tier == "IOC"
    assert p.staleness_band == "stale_over_2yr"
    assert p.uncertain is False
    assert p.lower_confidence is False


def test_priority_to_dict_never_a_bare_label():
    """The JSON shape itself must always carry both axes - this is the
    machine-readable form of "never show CRITICAL without tier×band"."""
    sig = _sig(tier="Artifact", days=400)
    d = compute_priority(sig).to_dict()
    assert set(d) == {"label", "tier", "staleness_band", "lower_confidence", "uncertain", "uncertainty_reason"}
    assert d["label"] == "HIGH"
    assert d["tier"] == "Artifact"
    assert d["staleness_band"] == "aging_6mo_to_2yr"


# --- priority_matrix_schema(): the GUI/CLI legend source -------------------


def test_priority_matrix_schema_shape():
    schema = priority_matrix_schema()
    assert schema["tiers_worst_to_best"] == TIERS_WORST_TO_BEST
    assert schema["staleness_bands_stale_to_fresh"] == list(STALENESS_BANDS)
    assert len(schema["cells"]) == 12
    for cell in schema["cells"]:
        assert cell["label"] == PRIORITY_MATRIX[(cell["tier"], cell["staleness_band"])]
    assert "Task 7" in schema["rationale"]
    assert "STP" in schema["rationale"] or "0.361" in schema["rationale"]


def test_priority_matrix_schema_is_pure_no_inputs():
    """The legend needs no repository, no rule, nothing computed - a pure
    constant, safe to call before any repo is loaded (the GUI's legend
    panel, `mechanic priority-legend` with no arguments)."""
    a = priority_matrix_schema()
    b = priority_matrix_schema()
    assert a == b


def test_priority_matrix_schema_has_a_plain_language_rationale_too():
    """The GUI legend modal shows `rationale_plain`, not `rationale` (see
    app.js's renderLegend) - it must exist, differ from the technical
    version, and actually be jargon-free (not just a shorter copy of the
    same sentences)."""
    schema = priority_matrix_schema()
    assert schema["rationale_plain"]
    assert schema["rationale_plain"] != schema["rationale"]
    for jargon in ("Task 7", "STP", "Kendall", "0.361", "RESULTS.md"):
        assert jargon not in schema["rationale_plain"], jargon


# --- compute_triage()'s progress_cb: the "detail" 4th arg -------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _commit(repo: Path, msg: str, date: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    _git(repo, "add", "-A")
    subprocess.run(["git", "commit", "-q", "-m", msg], cwd=repo, check=True, capture_output=True, env=env)


@pytest.fixture
def revised_repo(tmp_path: Path) -> Path:
    """One rule, created then behaviorally revised once, plus enough
    filler rules that the revision commit (1 file touched) stays under
    the default 10% mechanical-commit threshold - a single-rule repo's
    revision commit would touch 100% of the current rule count and get
    excluded as "mechanical" (a real, documented quirk of that filter at
    small corpus scale, not a bug). Needed so compute_triage's
    semantic_diff stage has a real (non-creation) touch to report
    progress on."""
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "A")
    rule = (
        "title: Suspicious Certutil Download\n"
        "id: 11111111-1111-1111-1111-111111111111\nstatus: test\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: '\\certutil.exe'\n"
        "  condition: selection\n"
    )
    (repo / "rules" / "target.yml").write_text(rule)
    for i in range(10):
        (repo / "rules" / f"filler{i}.yml").write_text(
            f"title: Filler {i}\nid: 2222222{i}-2222-2222-2222-222222222222\nstatus: test\n"
            "logsource:\n  category: process_creation\n  product: windows\n"
            "detection:\n  selection:\n    Image|endswith: '\\filler.exe'\n  condition: selection\n"
        )
    _commit(repo, "add rules", "2023-01-01T00:00:00")
    (repo / "rules" / "target.yml").write_text(
        rule.replace("condition: selection", "condition: selection2\n  selection2:\n    CommandLine|contains: '-urlcache'")
    )
    _commit(repo, "widen detection", "2023-06-01T00:00:00")
    return repo


def test_compute_triage_progress_cb_reports_detail_for_semantic_diff_and_classifying(revised_repo: Path):
    """`detail` (the 4th positional arg) is what the GUI's live "-> currently
    analyzing <file>" line reads - proves compute_triage actually bridges
    semantic_diff's per-touch callback and the per-rule classifying loop
    into its own (stage, done, total, detail) contract, not just the 3
    original positional args."""
    calls: list[tuple[str, int, int, str]] = []
    priority.compute_triage(
        revised_repo,
        "sigma",
        subdir="rules",
        progress_cb=lambda stage, done, total, detail="": calls.append((stage, done, total, detail)),
    )
    semantic_diff_calls = [c for c in calls if c[0] == "semantic_diff" and c[3]]
    classifying_calls = [c for c in calls if c[0] == "classifying" and c[3]]
    assert semantic_diff_calls, "expected at least one semantic_diff call carrying a non-empty detail"
    assert semantic_diff_calls[0][3] == "rules/target.yml"
    assert classifying_calls, "expected at least one classifying call carrying a non-empty detail"
    # Every rule gets a callback (total_rules=11 is small enough that the
    # "every 20th" throttle never skips one) - real per-item detail, not a
    # static placeholder, so target.yml must show up among them somewhere.
    assert "rules/target.yml" in {c[3] for c in classifying_calls}
    assert len({c[3] for c in classifying_calls}) > 1
    # Every call must be exactly (stage, done, total, detail) - a 3-arg-only
    # callback (the pre-existing contract) would already have raised
    # inside compute_triage if this ever regressed to fewer/more args.


def test_compute_triage_surfaces_degraded_history_health(revised_repo: Path):
    """`revised_repo` has exactly 2 total commits - below
    DEGRADED_HISTORY_MIN_COMMITS. `triage` (not just plain `staleness`)
    must surface that caveat too, since it's the primary command most
    users run and its never-revised/staleness-band signals come from the
    same thin history."""
    report = priority.compute_triage(revised_repo, "sigma", subdir="rules")
    assert report.history_health == "degraded"
    assert "insufficient_total_commits" in report.history_health_reasons
    d = report.to_dict()
    assert d["history_health"] == "degraded"
    assert "insufficient_total_commits" in d["history_health_reasons"]


def test_compute_triage_progress_cb_raising_aborts_the_whole_computation(revised_repo: Path):
    """Same exception-propagation contract as compute_semantic_diff's own
    progress_cb (see test_semantic_diff.py) - this is what the GUI's Stop
    button relies on end to end, through compute_triage's bridging too."""

    class _Stop(Exception):
        pass

    def cb(stage: str, done: int, total: int, detail: str = "") -> None:
        if stage == "semantic_diff" and detail:
            raise _Stop()

    with pytest.raises(_Stop):
        priority.compute_triage(revised_repo, "sigma", subdir="rules", progress_cb=cb)
