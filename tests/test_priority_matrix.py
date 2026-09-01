"""Priority-as-matrix (not a blended score): regression-locks the fixed
(tier, staleness band) -> label table itself, and the discipline that
uncertainty is always surfaced rather than folded into a confident-looking
label. See mechanic/priority.py's "Priority: an explicit 2-axis MATRIX"
section for the table and its documented rationale.
"""

from __future__ import annotations

from dataclasses import replace

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
