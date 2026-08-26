from pathlib import Path

from sigma.exceptions import SigmaRuleLocation
from sigma.rule import SigmaRule

from mechanic import ast_repr, loader, structural_detectors

SIGMA_REPO = Path("D:/sigma-research/sigma")


def _rule(detection: dict, logsource: dict | None = None) -> SigmaRule:
    d = {
        "title": "t",
        "id": "11111111-1111-1111-1111-111111111111",
        "status": "test",
        "logsource": logsource or {"category": "process_creation", "product": "windows"},
        "detection": detection,
        "level": "medium",
    }
    return SigmaRule.from_dict(d, source=SigmaRuleLocation(Path("x.yml")))


# ---------------------------------------------------------------------------
# FIELD_MISMATCH
# ---------------------------------------------------------------------------


def test_field_mismatch_canonical_rule_from_real_sigmahq_repo():
    """The one test the whole thesis stands or falls on."""
    path = SIGMA_REPO / "rules/windows/process_creation/proc_creation_win_renamed_binary_highly_relevant.yml"
    rules, failures = loader.load_file(path)
    assert failures == []
    tree = ast_repr.build_ast(rules[0].rule)
    result = structural_detectors.detect_field_mismatch(tree)
    assert result.triggered is True
    assert "pwsh" in result.detail or "Image" in result.node_path or "OriginalFileName" in result.node_path


def test_field_mismatch_negative_case_no_correspondence_fields():
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\cmd.exe", "CommandLine|contains": "whoami"},
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_field_mismatch(tree).triggered is False


def test_field_mismatch_negative_case_same_polarity_not_a_mismatch():
    """Image and OriginalFileName both asserted POSITIVELY (agreeing, not
    contradicting) must not trigger - this is normal tool-identification,
    not a rename-detection shape."""
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\certutil.exe", "OriginalFileName": "CertUtil.exe"},
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_field_mismatch(tree).triggered is False


def test_field_mismatch_does_not_overfire_on_unrelated_fieldref():
    """The cross-user fieldref pattern (User vs ParentUser) is a real
    signal but not an IDENTITY mismatch - must not trigger FIELD_MISMATCH."""
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\notepad.exe"},
            "filter_same_user": {"User|fieldref": "ParentUser"},
            "condition": "selection and not filter_same_user",
        }
    )
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_field_mismatch(tree).triggered is False


def test_field_mismatch_direct_fieldref_between_identity_fields():
    rule = _rule(
        {
            "selection": {"Image|fieldref": "OriginalFileName"},
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_field_mismatch(tree).triggered is True


# ---------------------------------------------------------------------------
# ABSENCE
# ---------------------------------------------------------------------------


def test_absence_null_field_is_own_criterion():
    rule = _rule(
        {
            "selection": {"CommandLine|contains": "powershell", "Signature": None},
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = structural_detectors.detect_absence(tree)
    assert result.triggered is True


def test_absence_negative_case_ordinary_exclusion_filter_not_absence():
    """selection (positive) and not filter (excluding known-good) is noise
    reduction, not an absence-based detection - must not trigger."""
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\rundll32.exe"},
            "filter": {"CommandLine|contains": "known_good_dll"},
            "condition": "selection and not filter",
        }
    )
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_absence(tree).triggered is False


def test_absence_all_negated_non_filter_selection():
    rule = _rule(
        {
            "selection_process": {"Image|endswith": "\\svchost.exe"},
            "selection_no_parent": {"ParentImage": None},
            "condition": "selection_process and selection_no_parent",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = structural_detectors.detect_absence(tree)
    assert result.triggered is True


# ---------------------------------------------------------------------------
# UNSCOREABLE
# ---------------------------------------------------------------------------


def test_unscoreable_not_triggered_for_normal_rule():
    rule = _rule({"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_unscoreable(tree).triggered is False


def test_unscoreable_not_triggered_for_absence_only_rule():
    """A null-check-only rule has leaves (null-kind) - it is ABSENCE's
    target case, not UNSCOREABLE's. Must land in ABSENCE, never in IOC or
    silently defaulted."""
    rule = _rule({"selection": {"Signature": None}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_unscoreable(tree).triggered is False
    assert structural_detectors.detect_absence(tree).triggered is True


# ---------------------------------------------------------------------------
# RARITY / CORRELATION (correlation-rule representation)
# ---------------------------------------------------------------------------


def test_rarity_and_correlation_trigger_on_correlation_rule():
    from sigma.correlations import SigmaCorrelationRule

    d = {
        "title": "Correlated",
        "id": "22222222-2222-2222-2222-222222222222",
        "correlation": {
            "type": "event_count",
            "rules": ["11111111-1111-1111-1111-111111111111"],
            "group-by": ["User"],
            "timespan": "5m",
            "condition": {"gte": 5},
        },
    }
    rule = SigmaCorrelationRule.from_dict(d, source=SigmaRuleLocation(Path("x.yml")))
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_rarity(tree).triggered is True
    assert structural_detectors.detect_correlation(tree).triggered is True
    assert structural_detectors.detect_unscoreable(tree).triggered is False


def test_rarity_not_triggered_on_standard_rule():
    rule = _rule({"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    assert structural_detectors.detect_rarity(tree).triggered is False
    assert structural_detectors.detect_correlation(tree).triggered is False
