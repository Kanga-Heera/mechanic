from pathlib import Path

from mechanic import loader

EXPECTED_LOAD_STAGE_CATEGORIES = {
    "bare_int_id",
    "correlation_as_standard_rule",
    "yaml_scanner_error",
    "yaml_composer_error",
    "yaml_parser_error",
    "null_date_split",
}


def test_mixed_batch_isolates_failures(rules_mixed_dir: Path):
    result = loader.load_ruleset(rules_mixed_dir, fmt="sigma")
    assert result.files_scanned == 10
    assert len(result.rules) == 7
    assert len(result.failures) == 3
    assert result.files_ok == 7
    assert result.files_failed == 3


def test_each_category_is_caught_and_categorized(rules_categories_dir: Path):
    result = loader.load_ruleset(rules_categories_dir, fmt="sigma")
    # valid_standard.yml + broken_null_reference.yml (loads fine, crashes later
    # at validate stage) both load successfully.
    assert len(result.rules) == 2
    categories_seen = {f.category for f in result.failures}
    assert categories_seen == EXPECTED_LOAD_STAGE_CATEGORIES
    # Run continues to completion - no exception escaped load_ruleset.
    assert result.files_scanned == 8


def test_null_reference_loads_but_crashes_validator(rules_categories_dir: Path):
    path = rules_categories_dir / "broken_null_reference.yml"
    rules, load_failures = loader.load_file(path)
    assert len(rules) == 1
    assert load_failures == []

    validate_failures = loader.validate_rules(rules)
    categories_seen = {f.category for f in validate_failures}
    assert "null_reference_typeerror" in categories_seen
    for f in validate_failures:
        assert f.stage == "validate"
        assert f.validator is not None


def test_valid_rule_has_no_failures(rules_categories_dir: Path):
    path = rules_categories_dir / "valid_standard.yml"
    rules, load_failures = loader.load_file(path)
    assert len(rules) == 1
    assert load_failures == []
    validate_failures = loader.validate_rules(rules)
    assert validate_failures == []


def test_failure_records_carry_file_and_hint(rules_categories_dir: Path):
    result = loader.load_ruleset(rules_categories_dir, fmt="sigma")
    for f in result.failures:
        assert f.file
        assert f.fix_hint
        assert f.stage in ("yaml_parse", "rule_construct", "validate")


def test_scan_result_to_dict_is_json_safe(rules_mixed_dir: Path):
    import json

    result = loader.load_ruleset(rules_mixed_dir, fmt="sigma")
    json.dumps(result.to_dict())  # must not raise
