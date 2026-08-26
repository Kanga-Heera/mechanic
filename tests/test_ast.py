from pathlib import Path

from sigma.exceptions import SigmaRuleLocation
from sigma.rule import SigmaRule

from mechanic import ast_repr


def _rule(detection: dict, logsource: dict | None = None, tags: list[str] | None = None) -> SigmaRule:
    d = {
        "title": "t",
        "id": "11111111-1111-1111-1111-111111111111",
        "status": "test",
        "logsource": logsource or {"category": "process_creation", "product": "windows"},
        "detection": detection,
        "level": "medium",
    }
    if tags:
        d["tags"] = tags
    return SigmaRule.from_dict(d, source=SigmaRuleLocation(Path("x.yml")))


def test_nested_and_or_not_polarity():
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\cmd.exe"},
            "filter_a": {"User": "SYSTEM"},
            "filter_b": {"ParentImage|endswith": "\\explorer.exe"},
            "condition": "selection and not (filter_a or filter_b)",
        }
    )
    tree = ast_repr.build_ast(rule)
    assert tree["type"] == "standard"

    leaves = {leaf["field"]: leaf for leaf in ast_repr.iter_leaves_of_rule(tree)}
    assert set(leaves) == {"Image", "User", "ParentImage"}

    # The positive branch stays unnegated.
    assert leaves["Image"]["negated"] is False
    # Both branches under "not (... or ...)" must be negated, regardless of
    # being inside an OR - this is exactly the shape that a naive classifier
    # (scoring atoms inside NOT clauses as positive matches) gets wrong.
    assert leaves["User"]["negated"] is True
    assert leaves["ParentImage"]["negated"] is True

    root = tree["conditions"][0]
    assert root["node"] == "AND"
    not_node = next(c for c in root["children"] if c["node"] == "NOT")
    assert not_node["negated"] is True
    or_node = not_node["children"][0]
    while or_node["node"] == "selection":
        or_node = or_node["child"]
    assert or_node["node"] == "OR"
    assert or_node["negated"] is True


def test_double_negation_cancels_out():
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\cmd.exe"},
            "filter": {"User": "SYSTEM"},
            "condition": "selection and not not filter",
        }
    )
    tree = ast_repr.build_ast(rule)
    leaves = list(ast_repr.iter_leaves_of_rule(tree))
    user_leaf = next(l for l in leaves if l.get("field") == "User")
    assert user_leaf["negated"] is False


def test_selections_are_named_nodes():
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\cmd.exe"},
            "filter_admin": {"User": "SYSTEM"},
            "condition": "selection and not filter_admin",
        }
    )
    tree = ast_repr.build_ast(rule)
    selections = {s["name"]: s for s in ast_repr.iter_selections_of_rule(tree)}
    assert selections["selection"]["kind"] == "selection"
    assert selections["filter_admin"]["kind"] == "filter"
    assert selections["filter_admin"]["negated"] is True


def test_renamed_binary_cross_field_pattern():
    """The canonical SigmaHQ pattern Stage 2 must detect: Image (path-based)
    vs. OriginalFileName (PE-metadata-based) cross-field comparison, used to
    catch a binary that's been renamed on disk."""
    rule = _rule(
        {
            "selection": {
                "Image|endswith": "\\svchost.exe",
                "OriginalFileName": "NOTEPAD.EXE",
            },
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    leaves = {leaf["field"]: leaf for leaf in ast_repr.iter_leaves_of_rule(tree)}
    assert leaves["Image"]["value"] == "\\svchost.exe"
    assert leaves["Image"]["operators"] == ["endswith"]
    assert leaves["OriginalFileName"]["value"] == "NOTEPAD.EXE"
    assert leaves["OriginalFileName"]["operators"] == []
    # Both fields are asserted positively in the same AND-linked selection -
    # the cross-field comparison the classifier needs to see is two sibling
    # leaves, neither negated, under the same parent.
    assert leaves["Image"]["negated"] is False
    assert leaves["OriginalFileName"]["negated"] is False

    root = tree["conditions"][0]
    while root["node"] == "selection":
        root = root["child"]
    assert root["node"] == "AND"
    assert len(root["children"]) == 2


def test_all_modifier_group_and_multi_value_or():
    rule = _rule(
        {
            "selection": {
                "Image|endswith|all": ["\\a.exe", "\\b.exe"],
                "CommandLine|contains": ["foo", "bar"],
            },
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    root = tree["conditions"][0]
    while root["node"] == "selection":
        root = root["child"]
    assert root["node"] == "AND"

    image_group = next(
        c
        for c in root["children"]
        if c["node"] == "AND" and any(l.get("field") == "Image" for l in c["children"])
    )
    assert image_group["operators"] == ["all"]
    assert {l["value"] for l in image_group["children"]} == {"\\a.exe", "\\b.exe"}

    cmd_group = next(
        c
        for c in root["children"]
        if c["node"] == "OR" and any(l.get("field") == "CommandLine" for l in c["children"])
    )
    assert {l["value"] for l in cmd_group["children"]} == {"foo", "bar"}


def test_ast_is_json_serializable():
    import json

    rule = _rule(
        {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
        tags=["attack.execution", "attack.t1059"],
    )
    tree = ast_repr.build_ast(rule)
    assert tree["attack_tags"] == ["attack.execution", "attack.t1059"]
    json.dumps(tree)  # must not raise


def test_correlation_rule_minimal_representation():
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
    assert tree["type"] == "correlation"
    assert "conditions" not in tree
