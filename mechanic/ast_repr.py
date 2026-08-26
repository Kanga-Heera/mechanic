"""Rule AST representation (Component 3).

Converts a successfully-loaded Sigma rule into a syntax-independent tree:
selections/filters as named nodes, AND/OR/NOT as structure, field/operator/
literal triples as leaves, with an explicit polarity flag on every leaf.

This is representation-only infrastructure for Stage 2 - no scoring, no
classification, no judgement about rule quality lives here.

Prior art: ARMS (Ghaffarzadegan, Concordia MASc thesis, April 2026) converts
Sigma rules to an AST for mutation-based testing. The conversion idea is the
same; the purpose here (a stable substrate for a maintenance-triage classifier
in Stage 2) is different, and this implementation is independent of ARMS's.

Rather than hand-writing a condition-string parser, this module reuses
pySigma's own pyparsing-based grammar (`sigma.conditions`) and its already-
resolved `SigmaDetection`/`SigmaDetectionItem` structures, requesting the
*non*-postprocessed parse tree (`SigmaCondition.parse(postprocess=False)`) so
named selections/filters stay intact as nodes instead of being fully expanded
inline, then converts that pyparsing tree into a small, stable, JSON-safe dict
shape of our own.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional, Union

from sigma.conditions import (
    ConditionAND,
    ConditionIdentifier,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.modifiers import SigmaRegularExpressionModifier, reverse_modifier_mapping
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaDetections, SigmaRule
from sigma.types import SigmaString

SCHEMA_VERSION = 1

AstNode = dict[str, Any]


# ---------------------------------------------------------------------------
# Leaf construction
# ---------------------------------------------------------------------------


def _to_plain(value: Any, is_regex: bool) -> Any:
    if is_regex and isinstance(value, SigmaString):
        return value.to_plain(True)
    return value.to_plain()


def _modifier_ids(item: SigmaDetectionItem) -> list[str]:
    return [reverse_modifier_mapping[m.__name__] for m in item.modifiers]


def _leaf(
    field: Optional[str], operators: list[str], value: Any, negated: bool
) -> AstNode:
    node: AstNode = {
        "node": "leaf",
        "kind": "keyword" if field is None else "field_value",
        "operators": operators,
        "value": value,
        "negated": negated,
    }
    if field is not None:
        node["field"] = field
    return node


def _null_leaf(field: Optional[str], operators: list[str], negated: bool) -> AstNode:
    return {
        "node": "leaf",
        "kind": "keyword_null" if field is None else "field_null",
        "operators": operators,
        "field": field,
        "negated": negated,
    }


def build_detection_item_node(item: SigmaDetectionItem, ambient_negated: bool) -> AstNode:
    """A SigmaDetectionItem is one YAML key: value (or bare value) entry. Its own
    `negated` flag (rarely set directly from YAML, but honored if a processing
    pipeline set it) combines with the ambient NOT-count from the condition
    tree via XOR to produce the leaf's final polarity."""
    negated = ambient_negated ^ bool(item.negated)
    operators = _modifier_ids(item)
    is_regex = SigmaRegularExpressionModifier in item.modifiers
    values = item.original_value or []

    if len(values) == 0:
        return _null_leaf(item.field, operators, negated)
    if len(values) == 1:
        return _leaf(item.field, operators, _to_plain(values[0], is_regex), negated)

    # Multiple values: OR-linked by default, AND-linked if the `all` modifier
    # was used. Represent the group explicitly and keep 'all' as the group's
    # operator rather than repeating it on every literal leaf.
    group_op = "AND" if item.value_linking is ConditionAND else "OR"
    leaf_operators = [op for op in operators if op != "all"]
    group_operators = [op for op in operators if op == "all"]
    children = [
        _leaf(item.field, leaf_operators, _to_plain(v, is_regex), negated) for v in values
    ]
    return {
        "node": group_op,
        "negated": negated,
        "operators": group_operators,
        "children": children,
    }


def build_detection_node(detection: SigmaDetection, ambient_negated: bool) -> AstNode:
    """A SigmaDetection is either a flat set of detection items (OR- or AND-
    linked, per Sigma's dict/list-of-dicts authoring rules) or a nested list
    of sub-detections. Recurse either way and collapse single-child groups."""
    children = [
        build_detection_item_node(item, ambient_negated)
        if isinstance(item, SigmaDetectionItem)
        else build_detection_node(item, ambient_negated)
        for item in detection.detection_items
    ]
    if len(children) == 1:
        return children[0]
    group_op = "AND" if detection.item_linking is ConditionAND else "OR"
    return {"node": group_op, "negated": ambient_negated, "children": children}


def _selection_kind(name: str) -> str:
    return "filter" if name.lower().startswith("filter") else "selection"


def build_selection_node(name: str, detections: SigmaDetections, ambient_negated: bool) -> AstNode:
    detection = detections.detections[name]
    return {
        "node": "selection",
        "name": name,
        "kind": _selection_kind(name),
        "negated": ambient_negated,
        "child": build_detection_node(detection, ambient_negated),
    }


# ---------------------------------------------------------------------------
# Condition-tree conversion (AND / OR / NOT / selector / identifier)
# ---------------------------------------------------------------------------


def build_condition_node(
    cond: Union[ConditionItem, Any], detections: SigmaDetections, ambient_negated: bool = False
) -> AstNode:
    if isinstance(cond, ConditionNOT):
        return {
            "node": "NOT",
            "negated": not ambient_negated,
            "children": [build_condition_node(cond.args[0], detections, not ambient_negated)],
        }
    if isinstance(cond, ConditionAND):
        return {
            "node": "AND",
            "negated": ambient_negated,
            "children": [
                build_condition_node(arg, detections, ambient_negated) for arg in cond.args
            ],
        }
    if isinstance(cond, ConditionOR):
        return {
            "node": "OR",
            "negated": ambient_negated,
            "children": [
                build_condition_node(arg, detections, ambient_negated) for arg in cond.args
            ],
        }
    if isinstance(cond, ConditionSelector):
        identifiers = cond.resolve_referenced_detections(detections)
        return {
            "node": "SELECTOR",
            "quantifier": cond.args[0],
            "pattern": cond.pattern,
            "negated": ambient_negated,
            "children": [
                build_selection_node(ident.identifier, detections, ambient_negated)
                for ident in identifiers
            ],
        }
    if isinstance(cond, ConditionIdentifier):
        return build_selection_node(cond.identifier, detections, ambient_negated)
    raise TypeError(f"Unrecognized condition node type: {type(cond).__name__}")


# ---------------------------------------------------------------------------
# Rule-level conversion
# ---------------------------------------------------------------------------


def _logsource_dict(rule: SigmaRule) -> dict[str, Optional[str]]:
    ls = rule.logsource
    return {"product": ls.product, "category": ls.category, "service": ls.service}


def _tag_strings(rule: SigmaRule) -> list[str]:
    tags = []
    for t in rule.tags or []:
        name = getattr(t, "name", None)
        namespace = getattr(t, "namespace", None)
        tags.append(f"{namespace}.{name}" if namespace else str(name))
    return tags


def build_ast(rule: Union[SigmaRule, SigmaCorrelationRule]) -> AstNode:
    """Build the stable, serializable AST for one rule.

    Correlation rules have no detection tree (they reference other rules by
    id/name) and are represented minimally - Stage 2's AST-consuming logic
    should check `type` before expecting `conditions`.
    """
    if isinstance(rule, SigmaCorrelationRule):
        corr_type = str(rule.type) if rule.type is not None else None
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "correlation",
            "id": str(rule.id) if rule.id is not None else None,
            "title": rule.title,
            "correlation_type": corr_type,
        }

    tags = _tag_strings(rule)
    conditions = [
        build_condition_node(sc.parse(postprocess=False), rule.detection)
        for sc in rule.detection.parsed_condition
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "type": "standard",
        "id": str(rule.id) if rule.id is not None else None,
        "title": rule.title,
        "logsource": _logsource_dict(rule),
        "tags": tags,
        "attack_tags": [t for t in tags if t.startswith("attack.")],
        "conditions": conditions,
    }


# ---------------------------------------------------------------------------
# Traversal API
# ---------------------------------------------------------------------------


def iter_leaves(node: AstNode) -> Iterator[AstNode]:
    """Depth-first iteration over every leaf (field_value/keyword/*_null) node
    reachable from `node` (or from any of a rule-AST's `conditions` roots)."""
    if node.get("node") == "leaf":
        yield node
        return
    if "child" in node:
        yield from iter_leaves(node["child"])
    for child in node.get("children", []):
        yield from iter_leaves(child)


def iter_selections(node: AstNode) -> Iterator[AstNode]:
    """Depth-first iteration over every named selection/filter node."""
    if node.get("node") == "selection":
        yield node
        yield from iter_selections(node["child"])
        return
    if "child" in node:
        yield from iter_selections(node["child"])
    for child in node.get("children", []):
        yield from iter_selections(child)


def iter_leaves_of_rule(rule_ast: AstNode) -> Iterator[AstNode]:
    for root in rule_ast.get("conditions", []):
        yield from iter_leaves(root)


def iter_selections_of_rule(rule_ast: AstNode) -> Iterator[AstNode]:
    for root in rule_ast.get("conditions", []):
        yield from iter_selections(root)


def is_negated(node: AstNode) -> bool:
    """Query a node's computed polarity. True means the node sits inside a
    negated/exclusion branch (an odd number of enclosing NOTs, XORed with any
    detection-item-level `negated` flag)."""
    return bool(node.get("negated", False))
