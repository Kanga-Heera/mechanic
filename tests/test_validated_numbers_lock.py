"""Hardening Part 4: regression-lock the numbers RESULTS.md reports as
VALIDATED, so a future change to the classifier or the churn engine can
never silently move them without a test noticing. Per the hardening
brief: these numbers are LOCKED, not recomputed or "improved" - every
assertion below reproduces a number RESULTS.md already reports and fails
if it drifts, never adjusts a tolerance or a fixture to chase a new value.

What's locked here, and how:

1. STP rank correlation, SIGMA-ONLY (Kendall's tau-b = 0.2841, p = 0.0112;
   Spearman's rho = 0.3056, p = 0.0101; mapped quadratic-weighted kappa =
   0.2249; n = 70) - against the SigmaHQ rows of the same frozen fixture
   used by the historical combined figure (see below), re-classified with
   ONLY core code (mechanic.fragility/mechanic.ast_repr/mechanic.loader -
   no import of anything quarantined). This is the CORE's own headline
   external-validation number as of the Sigma-only scoping pass - see
   docs/multiformat-experimental.md for exactly how this number relates to
   the historical 0.361 combined figure and why both are real, disclosed
   numbers rather than one silently replacing the other.

   RE-PINNED by the script-content fragility fix (RESULTS.md, "Bug fix:
   script-content field durability inversion") - was tau-b=0.3117/
   rho=0.3361/kappa=0.2821 before that fix. 3 of the 70 rows (all
   ScriptBlockText-based PowerShell rules, all previously Tool tier,
   MITRE score 2) moved to Artifact tier as a DIRECT, understood
   consequence of fixing a confirmed classification bug, not drift - see
   RESULTS.md Part 4 for the full investigation, including MITRE's own
   free-text justification for these exact rows ("ScriptBlockText
   searches are ... easy to evade with everyting being within adversary
   control"), which independently agrees with the fix. Still positive,
   still statistically significant - re-pinned deliberately, not reverted
   to protect the old number.

2. The three mechanical-commit figures (SigmaHQ 2,931 files in one
   commit, Elastic 1,064, Splunk 2,068) - these are immutable historical
   facts (a specific past commit touched N files), not time-relative, so
   they ARE exactly reproducible forever. Locked via
   `churn._mine_commits(..., single=<pinned hash>)` (a Part 4 hardening
   addition - single-commit mining, no full-history walk, so this stays
   fast) against the same full local clones DATASETS.md pins. SKIPPED
   (not failed) if a given clone isn't present at the expected path on
   this machine - the number is locked here, in this dev environment,
   without making the whole suite depend on ~50GB of external clones
   existing everywhere `pytest` runs. Discovery itself (`FORMATS`) stays
   format-agnostic in the core (staleness is not Sigma-scoped - see
   docs/core-vs-experiment.md), so this file's `--fmt elastic_toml`/
   `splunk_yaml` mining calls are unaffected by the multiformat quarantine.

3. The AND/OR combination fix's *behavior* (AND -> MIN, OR -> MAX) is
   already locked by tests/test_fragility.py
   (test_and_combination_takes_weaker_link,
   test_or_combination_takes_stronger_link) - not duplicated here,
   referenced so the Part 4 coverage is traceable from one place.

What is deliberately NOT locked bit-exact here, and why: the staleness
REPRODUCTION percentages (SigmaHQ 51.1%, Elastic 2.7%, Splunk 5.6% stale
>2yr) are computed relative to wall-clock "today" against live,
still-moving external repos - RESULTS.md itself says so explicitly ("these
numbers depend on wall-clock 'today'... as close a reproduction as should
be expected"). Asserting exact equality against a live external repo's
current HEAD would be testing something the project's own methodology
does not claim is stable, which would make this a flaky, dishonest lock,
not a real one. What IS stable and IS locked instead: the MECHANISM that
produces those percentages (mechanical-commit exclusion + organic-commit
staleness math) - tests/test_churn.py's synthetic-repo tests already do
exactly this, deterministically, on fixed dates; referenced here rather
than duplicated.

The historical COMBINED (SigmaHQ+Elastic+Splunk) 72-row STP lock -
tau-b=0.361, rho=0.392, kappa=0.316 - moved to
tests/experimental/test_multiformat_validated_numbers_lock.py, since
reproducing it requires the quarantined text-path classifier for the 1
Elastic + 1 Splunk row in the sample. It is unchanged, still locked, still
green - just no longer in the core's own test file, since the core can no
longer import what it needs to recompute it. See
docs/multiformat-experimental.md for the full accounting of what moved and
why neither number silently replaced the other.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mechanic import churn
from mechanic.discovery import FORMATS

FIXTURES = Path(__file__).parent / "fixtures"

# --- STP correlation lock (Sigma-only) --------------------------------------

pytest.importorskip("scipy", reason="STP regression-lock test needs scipy for Kendall's tau-b / Spearman's rho")
pytest.importorskip("numpy", reason="STP regression-lock test needs numpy for the mapped-kappa contingency table")

import numpy as np  # noqa: E402
from scipy import stats  # noqa: E402

from mechanic import ast_repr, fragility, loader  # noqa: E402
from mechanic.fragility import TIER_RANK  # noqa: E402

# STP doesn't itself distinguish level-1 into IOC vs Artifact; mechanic's
# own atom tier is accepted for either, same rule stp_stats.py (the
# original analysis script) used.
_MAPPING_A = {1: None, 2: "Tool", 3: "Tool", 4: "TTP", 5: "TTP"}


def _classify_sigma(text: str, path_hint: str) -> str | None:
    rules, failures = loader.parse_text(text, Path(path_hint))
    if failures or not rules:
        return None
    tree = ast_repr.build_ast(rules[0].rule)
    result = fragility.classify_rule(tree)
    return None if result.unscoreable else result.tier


@pytest.fixture(scope="module")
def stp_fixture() -> list[dict]:
    return json.loads((FIXTURES / "stp_validation_frozen.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def stp_sigma_only_reclassified(stp_fixture: list[dict]) -> list[dict]:
    """The SigmaHQ subset of the frozen fixture (70 of 72 rows), re-run
    against mechanic's REAL, current Sigma classifier - the core's own
    external-validation lock, with zero dependency on the quarantined
    Elastic/Splunk text-path code."""
    out = []
    for row in stp_fixture:
        if row["owner_repo"] != "SigmaHQ/sigma":
            continue
        tier = _classify_sigma(row["rule_text"], row["path"])
        out.append({**row, "mechanic_tier": tier})
    return out


def test_stp_fixture_sigma_subset_matches_recorded_composition(stp_fixture: list[dict]):
    """n=70 SigmaHQ rows out of 72 total - if this drifts, the fixture
    itself was regenerated wrong, not a classifier change."""
    sigma_rows = [r for r in stp_fixture if r["owner_repo"] == "SigmaHQ/sigma"]
    assert len(sigma_rows) == 70
    assert len(stp_fixture) == 72


def test_stp_sigma_only_reclassification_produces_no_unscoreable_rows(stp_sigma_only_reclassified: list[dict]):
    unscoreable = [r["name"] for r in stp_sigma_only_reclassified if r["mechanic_tier"] is None]
    assert not unscoreable, f"rows that used to classify now don't: {unscoreable}"


def test_stp_rank_correlation_sigma_only_locked(stp_sigma_only_reclassified: list[dict]):
    """The core's own headline external-validation figure, as of the
    Sigma-only scoping pass - see docs/multiformat-experimental.md for how
    this relates to the historical combined 0.361/0.392 figure."""
    mech_ranks = [TIER_RANK[r["mechanic_tier"]] for r in stp_sigma_only_reclassified]
    stp_scores = [r["analytic_score"] for r in stp_sigma_only_reclassified]

    tau, tau_p = stats.kendalltau(mech_ranks, stp_scores)
    rho, rho_p = stats.spearmanr(mech_ranks, stp_scores)

    assert tau == pytest.approx(0.2841, abs=0.001), f"Kendall's tau-b drifted: {tau:.4f} (was 0.2841)"
    assert tau_p == pytest.approx(0.0112, abs=0.001), f"tau-b p-value drifted: {tau_p:.4f} (was 0.0112)"
    assert rho == pytest.approx(0.3056, abs=0.001), f"Spearman's rho drifted: {rho:.4f} (was 0.3056)"
    assert rho_p == pytest.approx(0.0101, abs=0.001), f"rho p-value drifted: {rho_p:.4f} (was 0.0101)"


def test_stp_mapped_kappa_sigma_only_locked(stp_sigma_only_reclassified: list[dict]):
    """Quadratic-weighted Cohen's kappa (Mapping A: STP level 3 -> Tool),
    Sigma-only subset - locks the 0.2249 figure (was 0.2821 before the
    script-content fragility fix, see RESULTS.md Part 4)."""
    cats = ["IOC", "Artifact", "Tool", "TTP"]
    cat_idx = {c: i for i, c in enumerate(cats)}
    k = len(cats)
    table = np.zeros((k, k))
    for r in stp_sigma_only_reclassified:
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

    assert kappa == pytest.approx(0.2249, abs=0.005), f"mapped quadratic-weighted kappa drifted: {kappa:.4f} (was 0.2249)"


# --- mechanical-commit figures lock -----------------------------------------

_MECHANICAL_COMMITS = [
    pytest.param(
        Path("D:/sigma-research/sigma"),
        "sigma",
        "rules",
        "598d29f811c1859ba18e05b8c419cc94410c9a55",
        2931,
        "SigmaHQ 'Comply With v2 Spec Changes'",
        id="sigmahq",
    ),
    pytest.param(
        Path("D:/sigma-research/thirdparty/elastic-detection-rules"),
        "elastic_toml",
        "rules",
        "8993d1450bd6f843765e02c40d6c779337f30bbc",
        1064,
        "Elastic 'Add Supplemental Mitre Mappings'",
        id="elastic",
    ),
    pytest.param(
        Path("D:/sigma-research/thirdparty/splunk-security-content"),
        "splunk_yaml",
        "detections",
        "db8c7c8509b55374a324b6dc57a3f325e8685736",
        2068,
        "Splunk 'Initial commit of modified objects'",
        id="splunk",
    ),
]


@pytest.mark.parametrize("root,fmt,subdir,commit_hash,expected_count,label", _MECHANICAL_COMMITS)
def test_mechanical_commit_file_count_locked(root: Path, fmt: str, subdir: str, commit_hash: str, expected_count: int, label: str):
    if not (root / ".git").exists():
        pytest.skip(f"{label}: local clone not present at {root} on this machine - number locked where the clone exists")
    facts = churn._mine_commits(root, FORMATS[fmt], subdir_prefix=subdir, single=commit_hash)
    assert len(facts) == 1, f"{label}: expected exactly 1 commit-fact for a single pinned hash, got {len(facts)}"
    actual = len(facts[0].rule_paths_touched)
    assert actual == expected_count, (
        f"{label} ({commit_hash[:10]}): rule_files_touched drifted to {actual} (was {expected_count}) - "
        f"either the pinned commit's diff changed (should be impossible - git history is immutable) or "
        f"mechanic's own rule-file-touch counting logic changed behavior"
    )
