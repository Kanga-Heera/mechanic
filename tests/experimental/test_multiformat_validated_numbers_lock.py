"""The historical COMBINED (SigmaHQ + Elastic + Splunk) STP correlation
lock - Kendall's tau-b = 0.3523 (p = 0.0013), Spearman's rho = 0.3784
(p = 0.0010), mapped quadratic-weighted kappa = 0.3077, n = 72 -
RESULTS.md's "The AND/OR fix, implemented, and everything re-run".

This is EXACTLY `tests/test_validated_numbers_lock.py`'s STP section before
the Sigma-only scoping pass, moved here unchanged because reproducing it
needs the quarantined text-path classifier for the 1 Elastic + 1 Splunk row
in the 72-row sample (see docs/multiformat-experimental.md for the full
accounting). It is not superseded by the core's new Sigma-only lock
(tests/test_validated_numbers_lock.py::test_stp_rank_correlation_sigma_only_locked)
- both numbers are real, both are locked, they measure different (if
99%-overlapping) populations. Nothing here was recomputed to make this
number look better or worse; it is the same frozen fixture and the same
classification code (now living under mechanic.experimental.multiformat)
that always produced it.

RE-PINNED TWICE, both times by a confirmed classification-bug fix, never by
chasing the number:

  1. The script-content fragility fix (RESULTS.md, "Bug fix: script-content
     field durability inversion") - was tau-b=0.361/rho=0.392/kappa=0.316
     before. 3 of the 70 SigmaHQ rows in this 72-row sample (all
     ScriptBlockText-based PowerShell rules, all previously Tool tier,
     MITRE score 2) moved to Artifact tier - see RESULTS.md Part 4. The
     correlation DROPPED (tau 0.361 -> 0.3449) as a real, investigated
     consequence, not reverted to protect the old number.
  2. The field-semantics registry fix (RESULTS.md, "Field-aware literal
     classification" / docs/field-semantics.md) - was tau-b=0.3449/
     rho=0.3740/kappa=0.2653 before. Exactly ONE row in this 72-row sample
     moved: the Splunk rule "Detect Credential Dumping through LSASS
     access" (MITRE score 4, mechanic Tool -> TTP) - a GrantedAccess-style
     access-mask field, previously scored as an ordinary unrecognized
     literal (Artifact-pulling-the-rule-to-Tool via its weaker co-atoms),
     now correctly treated as a durable functional constraint. This time
     the correlation IMPROVED (tau 0.3449 -> 0.3523, kappa 0.2653 -> 0.3077)
     - reported plainly, same as the drop was, because the brief's rule is
     "report honestly," not "report only improvements."

Zero SigmaHQ rows in the 70-row Sigma-only sample changed tier from fix #2
(see tests/test_validated_numbers_lock.py's own note) - only the ONE
Splunk row (reached exclusively through the quarantined text-path
classifier this file exists to lock) exercises the FUNCTIONAL_CONSTRAINT
path in either external-validation sample.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("scipy", reason="STP regression-lock test needs scipy for Kendall's tau-b / Spearman's rho")
pytest.importorskip("numpy", reason="STP regression-lock test needs numpy for the mapped-kappa contingency table")

import numpy as np  # noqa: E402
from scipy import stats  # noqa: E402

from mechanic import ast_repr, fragility, loader  # noqa: E402
from mechanic.experimental.multiformat import splunk_macros, text_fragility  # noqa: E402
from mechanic.fragility import TIER_RANK  # noqa: E402

FIXTURES = Path(__file__).parent.parent / "fixtures"

_MAPPING_A = {1: None, 2: "Tool", 3: "Tool", 4: "TTP", 5: "TTP"}


def _classify_sigma(text: str, path_hint: str) -> str | None:
    rules, failures = loader.parse_text(text, Path(path_hint))
    if failures or not rules:
        return None
    tree = ast_repr.build_ast(rules[0].rule)
    result = fragility.classify_rule(tree)
    return None if result.unscoreable else result.tier


def _classify_elastic(text: str) -> str | None:
    import tomllib

    try:
        doc = tomllib.loads(text)
    except Exception:
        return None
    rule = doc.get("rule", {})
    if rule.get("type") == "threat_match":
        return "IOC"
    query = rule.get("query")
    if not query:
        return None
    atoms, ok = text_fragility.extract_elastic_atoms(query)
    if not ok:
        return None
    result = text_fragility.classify_text_rule(atoms, ok)
    return None if (result.unscoreable or result.tier is None) else result.tier


def _classify_splunk(text: str) -> str | None:
    import yaml

    try:
        doc = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    search = doc.get("search", "")
    resolved, *_ = splunk_macros.resolve_macros(search)
    atoms, ok = text_fragility.extract_splunk_atoms(resolved)
    if not ok:
        return None
    result = text_fragility.classify_text_rule(atoms, ok, raw_text=resolved, pre_resolution_text=search)
    return None if (result.unscoreable or result.tier is None) else result.tier


_CLASSIFIERS = {
    "SigmaHQ/sigma": lambda row: _classify_sigma(row["rule_text"], row["path"]),
    "elastic/detection-rules": lambda row: _classify_elastic(row["rule_text"]),
    "splunk/security_content": lambda row: _classify_splunk(row["rule_text"]),
}


@pytest.fixture(scope="module")
def stp_fixture() -> list[dict]:
    return json.loads((FIXTURES / "stp_validation_frozen.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def stp_reclassified(stp_fixture: list[dict]) -> list[dict]:
    """Re-run mechanic's REAL, current classifier (core Sigma path +
    quarantined text path) against every frozen row - this is the
    "recompute" that makes the lock meaningful: it exercises live
    production code against fixed input, not fixed input against a fixed
    cached output."""
    out = []
    for row in stp_fixture:
        tier = _CLASSIFIERS[row["owner_repo"]](row)
        out.append({**row, "mechanic_tier": tier})
    return out


def test_stp_fixture_matches_recorded_composition(stp_fixture: list[dict]):
    """n=72, exactly the main+network row count RESULTS.md reports - if
    this drifts, the fixture itself was regenerated wrong, not a
    classifier change."""
    assert len(stp_fixture) == 72


def test_stp_reclassification_produces_no_unscoreable_rows(stp_reclassified: list[dict]):
    """RESULTS.md's 72-row correlation used only rows mechanic could
    actually tier - if a future change makes any of these 72 real rules
    suddenly unscoreable, that is itself drift worth failing loudly on."""
    unscoreable = [r["name"] for r in stp_reclassified if r["mechanic_tier"] is None]
    assert not unscoreable, f"rows that used to classify now don't: {unscoreable}"


def test_stp_rank_correlation_locked(stp_reclassified: list[dict]):
    mech_ranks = [TIER_RANK[r["mechanic_tier"]] for r in stp_reclassified]
    stp_scores = [r["analytic_score"] for r in stp_reclassified]

    tau, tau_p = stats.kendalltau(mech_ranks, stp_scores)
    rho, rho_p = stats.spearmanr(mech_ranks, stp_scores)

    assert tau == pytest.approx(0.3523, abs=0.001), f"Kendall's tau-b drifted: {tau:.4f} (was 0.3523)"
    assert tau_p == pytest.approx(0.0013, abs=0.0005), f"tau-b p-value drifted: {tau_p:.4f} (was 0.0013)"
    assert rho == pytest.approx(0.3784, abs=0.001), f"Spearman's rho drifted: {rho:.4f} (was 0.3784)"
    assert rho_p == pytest.approx(0.0010, abs=0.0005), f"rho p-value drifted: {rho_p:.4f} (was 0.0010)"


def test_stp_mapped_kappa_locked(stp_reclassified: list[dict]):
    """Quadratic-weighted Cohen's kappa (Mapping A: STP level 3 -> Tool)
    against mechanic's tier, same weighting stp_stats.py (the original
    analysis) used - locks the 0.3077 figure (0.2653 after the
    script-content fragility fix, 0.316 before that - see this module's
    own docstring for the field-semantics fix that produced this figure)."""
    cats = ["IOC", "Artifact", "Tool", "TTP"]
    cat_idx = {c: i for i, c in enumerate(cats)}
    k = len(cats)
    table = np.zeros((k, k))
    for r in stp_reclassified:
        stp_level = r["analytic_score"]
        mech = r["mechanic_tier"]
        if stp_level == 1:
            mapped = mech if mech in ("IOC", "Artifact") else "Artifact"
        else:
            mapped = _MAPPING_A[stp_level]
        table[cat_idx[mapped], cat_idx[mech]] += 1

    n = table.sum()
    row_sums = table.sum(axis=1)
    col_sums = table.sum(axis=0)
    expected = np.outer(row_sums, col_sums) / n
    w = np.array([[(i - j) ** 2 for j in range(k)] for i in range(k)])
    w = w / w.max()
    observed_disagreement = (w * table).sum()
    expected_disagreement = (w * expected).sum()
    kappa = 1 - observed_disagreement / expected_disagreement

    assert kappa == pytest.approx(0.3077, abs=0.005), f"mapped quadratic-weighted kappa drifted: {kappa:.4f} (was 0.3077)"
