"""Structural pattern detectors (Stage 2, Part 2a) - the core new work.

v1 scored a rule's tier as the max tier over its literal atoms. Its single
most important, non-list-fixable failure mode: durability frequently lives
in a RELATIONSHIP BETWEEN FIELDS, not in any one literal. Canonical case:
`proc_creation_win_renamed_binary_highly_relevant.yml` fires when `Image`
MISMATCHES `OriginalFileName`/`Description` - every individual atom is an
ordinary .exe string, so an atom-max classifier scores it Tool. It is (by
hand-label) the most durable rule in the SigmaHQ corpus. No wordlist fixes
this - it requires reading the AST.

Each detector here takes a rule's AST (`ast_repr.build_ast` output) and
returns a `DetectorResult(triggered, node_path, detail)` - `node_path` is a
human-readable breadcrumb into the tree (e.g. "conditions[0].selection.
filter") so every promotion this produces is explainable, not a black box.
Detectors are independent and additive (`mechanic/mechanic/categories.py`'s
own pluggable-registry pattern, mirrored here): `DETECTORS` is an ordered
list; adding a new one means appending to it, nothing else changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from mechanic import ast_repr

AstNode = dict[str, Any]

IDENTITY_METADATA_FIELDS = {
    "originalfilename",
    "description",
    "product",
    "internalname",
    "companyname",
    "signature",
    "publisher",
}
IDENTITY_PATH_FIELDS = {
    "image",
    "parentimage",
    "targetfilename",
    "currentimage",
    "sourceimage",
    "grandparentimage",
    "previousimage",
}

_PATH_SEPS = ("\\", "/")
_KNOWN_EXTS = (".exe", ".dll", ".sys", ".c", ".com", ".scr")


@dataclass
class DetectorResult:
    triggered: bool
    node_path: str = ""
    detail: str = ""


def _basename_token(value: Any) -> Optional[str]:
    if not isinstance(value, str) or not value:
        return None
    s = value
    for sep in _PATH_SEPS:
        s = s.split(sep)[-1]
    s_low = s.lower()
    for ext in _KNOWN_EXTS:
        if s_low.endswith(ext):
            s_low = s_low[: -len(ext)]
            break
    return s_low or None


def _all_leaves(rule_ast: AstNode) -> list[AstNode]:
    return list(ast_repr.iter_leaves_of_rule(rule_ast))


def _last_segment(field: Optional[str]) -> str:
    if not field:
        return ""
    return field.rsplit(".", 1)[-1].lower()


# ---------------------------------------------------------------------------
# FIELD_MISMATCH - strongest durability signal known. Promote to TTP.
# ---------------------------------------------------------------------------


def detect_field_mismatch(rule_ast: AstNode) -> DetectorResult:
    leaves = _all_leaves(rule_ast)

    metadata_leaves = [l for l in leaves if _last_segment(l.get("field")) in IDENTITY_METADATA_FIELDS]
    path_leaves = [l for l in leaves if _last_segment(l.get("field")) in IDENTITY_PATH_FIELDS]

    # (a) Parallel-enumeration mismatch: a metadata-identity leaf and a
    # path-identity leaf with DIFFERING polarity (one asserted positively,
    # one under a NOT) whose literal values share a basename token - the
    # "claims to be X (positively) but isn't named X (the negated filter
    # covers being named X)" shape of the canonical rule.
    for m in metadata_leaves:
        m_tok = _basename_token(m.get("value"))
        if not m_tok:
            continue
        for p in path_leaves:
            if bool(m.get("negated")) == bool(p.get("negated")):
                continue  # same polarity - not a mismatch/exclusion shape
            p_tok = _basename_token(p.get("value"))
            if p_tok and p_tok == m_tok:
                return DetectorResult(
                    True,
                    node_path=f"{m.get('field')} vs {p.get('field')}",
                    detail=(
                        f"metadata field {m.get('field')!r}={m.get('value')!r} and path field "
                        f"{p.get('field')!r}={p.get('value')!r} share basename {m_tok!r} under "
                        "opposite polarity - claims-to-be-X-but-not-named-X (renamed binary) shape"
                    ),
                )

    # (b) Direct fieldref comparison between two identity-describing fields
    # (Image compared directly to OriginalFileName, not the parallel-list
    # shape above). Deliberately narrow: a `fieldref` between two NON-identity
    # fields (e.g. User vs ParentUser, a same-user check) is a different
    # signal and must NOT be promoted here - that's exactly what over-firing
    # this detector on every fieldref would do.
    for leaf in leaves:
        if "fieldref" not in (leaf.get("operators") or []):
            continue
        referenced = leaf.get("value")
        field_a = _last_segment(leaf.get("field"))
        field_b = _last_segment(referenced) if isinstance(referenced, str) else ""
        identity_fields = IDENTITY_METADATA_FIELDS | IDENTITY_PATH_FIELDS
        if field_a in identity_fields and field_b in identity_fields and field_a != field_b:
            return DetectorResult(
                True,
                node_path=f"{leaf.get('field')} fieldref {referenced}",
                detail=f"direct field-to-field identity comparison: {leaf.get('field')} vs {referenced}",
            )

    return DetectorResult(False)


# ---------------------------------------------------------------------------
# ABSENCE - fires on something NOT being present (missing signature, empty
# field, null value, required-but-absent parent). Distinct from an ordinary
# NOT-exclusion filter (noise reduction, not detection logic).
# ---------------------------------------------------------------------------


def detect_absence(rule_ast: AstNode) -> DetectorResult:
    """An ordinary exclusion filter removes known-good instances of an
    otherwise-positive match (`selection and not filter_known_good`) - the
    POSITIVE selection is what's actually detecting something, the NOT is
    noise reduction on top of it. A genuine absence-based detection has NO
    positive, independent selection driving it: the only (or the dominant)
    condition IS a null/missing/negated-existence check, standing on its
    own rather than trimming a separately-established selection.

    Operationalized as: a `*_null`/`keyword_null` leaf (Sigma's explicit
    "field is absent/null" leaf kind), OR a negated leaf whose sibling
    selection group has no OTHER non-negated leaf asserting a concrete
    positive match - i.e. the negation isn't filtering down a positive hit,
    it IS the hit.
    """
    for root in rule_ast.get("conditions", []):
        for sel in ast_repr.iter_selections(root):
            if sel.get("kind") == "filter":
                continue  # named `filter*` selections are the noise-reduction
                # convention this detector must not fire on by construction.
            child_leaves = list(_iter_leaves_under(sel.get("child")))
            # A YAML `field: null`/`field:` (no value) leaf comes through
            # ast_repr as EITHER kind field_null/keyword_null (truly empty
            # value list) OR as an ordinary field_value leaf whose `value` is
            # Python None (pySigma treats `key: null` as one explicit null
            # value, not zero values) - both are the same "field is absent"
            # assertion from a detection standpoint and must both count here.
            null_leaves = [
                l
                for l in child_leaves
                if l.get("kind") in ("field_null", "keyword_null")
                or (l.get("kind") == "field_value" and l.get("value") is None)
            ]
            for nl in null_leaves:
                return DetectorResult(
                    True,
                    node_path=f"selection {sel.get('name')}",
                    detail=f"non-filter selection {sel.get('name')!r} asserts field "
                    f"{nl.get('field')!r} is null/absent as its own detection criterion",
                )
            positive = [l for l in child_leaves if not l.get("negated")]
            negated = [l for l in child_leaves if l.get("negated")]
            if negated and not positive:
                return DetectorResult(
                    True,
                    node_path=f"selection {sel.get('name')}",
                    detail=f"non-filter selection {sel.get('name')!r} consists entirely of negated "
                    "leaves with no independent positive match to filter down - the absence IS the "
                    "detection, not noise reduction on a positive hit",
                )
    return DetectorResult(False)


def _iter_leaves_under(node: Optional[AstNode]):
    if node is None:
        return
    yield from ast_repr.iter_leaves(node)


# ---------------------------------------------------------------------------
# RARITY - statistical/threshold-based (count, aggregation, frequency,
# first-seen, outlier). Base Sigma expresses this via correlation rules.
# ---------------------------------------------------------------------------


def detect_rarity(rule_ast: AstNode) -> DetectorResult:
    if rule_ast.get("type") == "correlation":
        corr_type = (rule_ast.get("correlation_type") or "").lower()
        if corr_type in ("event_count", "value_count", "temporal_ordered", "temporal"):
            return DetectorResult(
                True, node_path="correlation", detail=f"correlation rule of type {corr_type!r}"
            )
        return DetectorResult(True, node_path="correlation", detail="correlation rule (type unspecified)")
    return DetectorResult(False)


# ---------------------------------------------------------------------------
# CORRELATION - logic spanning multiple events / temporal relationships.
# Base Sigma expresses this only via correlation rules.
# ---------------------------------------------------------------------------


def detect_correlation(rule_ast: AstNode) -> DetectorResult:
    if rule_ast.get("type") == "correlation":
        return DetectorResult(True, node_path="correlation", detail="rule IS a correlation rule")
    return DetectorResult(False)


# ---------------------------------------------------------------------------
# UNSCOREABLE - no literal atoms at all (pure aggregation/ML/probability
# rules). Must land in their own bucket, never scored as fragile-by-default.
# ---------------------------------------------------------------------------


def detect_unscoreable(rule_ast: AstNode) -> DetectorResult:
    """Zero leaves of ANY kind (not just field_value) - a rule with only
    null/absence-check leaves (`field_null`/`keyword_null`) is NOT
    unscoreable, it's ABSENCE's target case and must reach that detector,
    not be short-circuited here. Genuinely leaf-free standard Sigma rules
    are rare (a valid rule needs a condition over something) but this is the
    Sigma-side safety net; Elastic's ML/pure-threshold rules (the 7+106
    rules this bucket is mainly for) never reach this module at all - they
    have no Sigma AST to build in the first place and are flagged unscoreable
    in the Elastic-specific atom extractor instead."""
    if rule_ast.get("type") == "correlation":
        return DetectorResult(False)  # correlation rules are handled/tiered separately
    leaves = _all_leaves(rule_ast)
    if not leaves:
        return DetectorResult(True, node_path="conditions", detail="rule has zero leaves of any kind")
    return DetectorResult(False)


DETECTORS: list[tuple[str, Callable[[AstNode], DetectorResult]]] = [
    ("UNSCOREABLE", detect_unscoreable),
    ("FIELD_MISMATCH", detect_field_mismatch),
    ("ABSENCE", detect_absence),
    ("RARITY", detect_rarity),
    ("CORRELATION", detect_correlation),
]


def run_all_detectors(rule_ast: AstNode) -> dict[str, DetectorResult]:
    return {name: fn(rule_ast) for name, fn in DETECTORS}
