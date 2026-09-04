"""Free-text query language atom extraction + fragility classification:
EQL/KQL/ES|QL (Elastic) and SPL (Splunk).

Stage 1 built an AST ONLY for Sigma (via pySigma's own parser - there is no
EQL/SPL grammar anywhere in this codebase, and building a real one is out of
scope for Stage 2). This module is the necessarily-weaker sibling to
`fragility.py`: same tier-scoring principle (protected literals, cross-
platform tool names, IOC patterns), applied over REGEX-EXTRACTED atoms
instead of a real parse tree.

Two things are structurally different from the Sigma path, and both are
disclosed rather than glossed over:

  - Negation is a best-effort heuristic (`!=` operators, and atoms found
    textually inside a `not (...)` / `NOT (...)` span), not a real parser's
    polarity flag. It is still strictly better than v1, which had NO
    negation awareness for these two languages at all.
  - FIELD_MISMATCH is approximated by the same token-overlap-under-opposite-
    polarity logic `structural_detectors.py` uses for Sigma's real AST, but
    computed over the flat (field, value, negated) atom list instead of a
    tree - `ABSENCE`/`RARITY`/`CORRELATION` are NOT attempted here (they need
    real tree/aggregation-pipeline structure this module doesn't have); a
    rule that only qualifies via one of those three is scored purely at the
    atom level here and will legitimately disagree with a hand label that
    credits the structural pattern - reported as such in Part 2c.

Every result carries `confidence` capped at "medium" (never "high") for
exactly this reason - see RESULTS.md's re-validation numbers for whether
that discount is generous or stingy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from mechanic.fragility import TIER_RANK, classify_atom, _is_eventid_or_syscall_field as is_eventid_or_syscall_field
from mechanic.protected_literals import rule_is_cloud_audit_context
from mechanic.structural_detectors import IDENTITY_METADATA_FIELDS, IDENTITY_PATH_FIELDS, _basename_token

# Elastic ECS field aliases for the same identity concepts Sigma names
# Image/OriginalFileName/Description - added on top of the Sigma-side sets
# since ECS uses different field names for the same idea.
_ECS_IDENTITY_METADATA_FIELDS = IDENTITY_METADATA_FIELDS | {
    "original_file_name",
    "pe.original_file_name",
    "code_signature.subject_name",
    "code_signature.signing_id",
}
_ECS_IDENTITY_PATH_FIELDS = IDENTITY_PATH_FIELDS | {"name", "executable", "parent.name", "parent.executable"}


@dataclass
class TextAtom:
    field: str
    value: str
    negated: bool


# ---------------------------------------------------------------------------
# Elastic EQL/KQL/ES|QL
# ---------------------------------------------------------------------------

_ELASTIC_FIELD = r"[A-Za-z_][A-Za-z0-9_.\[\]]*"
_ELASTIC_ATOM_RE = re.compile(
    rf'({_ELASTIC_FIELD})\s*(:|==|!=|like~?|:~|in\b|regex~?)\s*'
    rf'(\((?:[^()]*)\)|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^\s,()]+)',
    re.IGNORECASE,
)
_QUOTED_ITEM_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')
_BARE_ITEM_RE = re.compile(r'[^\s,()"\']+')
_ELASTIC_KEYWORDS = {"and", "or", "not", "where", "sequence", "by", "with", "maxspan"}


def _split_list(inner: str) -> list[str]:
    items = [m.group(1) if m.group(1) is not None else m.group(2) for m in _QUOTED_ITEM_RE.finditer(inner)]
    if not items:
        items = [m.group(0) for m in _BARE_ITEM_RE.finditer(inner)]
    return items


def _not_group_spans(text: str, not_keyword: str) -> list[tuple[int, int]]:
    """Best-effort span-finder for `not (...)` / `NOT (...)`, via paren
    depth-tracking from each `not (` occurrence to its matching close paren.
    Textual, not a real parser - approximate by construction."""
    spans = []
    for m in re.finditer(rf"\b{not_keyword}\s*\(", text, re.IGNORECASE):
        start = m.end() - 1  # position of the opening '('
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    spans.append((start, i + 1))
                    break
    return spans


def _in_any_span(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in spans)


def extract_elastic_atoms(query: str) -> tuple[list[TextAtom], bool]:
    if not query or not query.strip():
        return [], False
    not_spans = _not_group_spans(query, "not")
    atoms: list[TextAtom] = []
    for m in _ELASTIC_ATOM_RE.finditer(query):
        field, op, val = m.group(1), m.group(2), m.group(3)
        if field.lower() in _ELASTIC_KEYWORDS:
            continue
        negated = op == "!=" or _in_any_span(m.start(), not_spans)
        if val.startswith("(") and val.endswith(")"):
            for item in _split_list(val[1:-1]):
                atoms.append(TextAtom(field, item, negated))
        else:
            atoms.append(TextAtom(field, val.strip("\"'"), negated))
    return atoms, len(atoms) > 0


# ---------------------------------------------------------------------------
# Splunk SPL (macro-resolved text expected - see churn/macro handling from
# Phase 0; Stage 2 re-validation resolves macros the same way before calling
# this, reusing that already-validated logic rather than re-deriving it)
# ---------------------------------------------------------------------------

_SPL_FIELD = r"[A-Za-z_][A-Za-z0-9_.]*"
_SPL_ATOM_RE = re.compile(
    rf'({_SPL_FIELD})\s*(=|!=|IN\s*)\s*(\((?:[^()]*)\)|"(?:[^"\\]|\\.)*"|[^\s,()]+)', re.IGNORECASE
)
_SPL_KEYWORDS = {"as", "by", "from", "where", "over", "output", "outputnew"}


def extract_splunk_atoms(resolved_search_text: str) -> tuple[list[TextAtom], bool]:
    if not resolved_search_text or not resolved_search_text.strip():
        return [], False
    not_spans = _not_group_spans(resolved_search_text, "NOT")
    atoms: list[TextAtom] = []
    for m in _SPL_ATOM_RE.finditer(resolved_search_text):
        field, op, val = m.group(1), m.group(2), m.group(3)
        if field.lower() in _SPL_KEYWORDS:
            continue
        negated = op.strip() == "!=" or _in_any_span(m.start(), not_spans)
        if val.startswith("(") and val.endswith(")"):
            for item in _split_list(val[1:-1]):
                atoms.append(TextAtom(field, item, negated))
        else:
            atoms.append(TextAtom(field, val.strip('"'), negated))
    return atoms, len(atoms) > 0


# ---------------------------------------------------------------------------
# Approximate FIELD_MISMATCH over a flat atom list (no tree available)
# ---------------------------------------------------------------------------


# RARITY, SPL-specific: unlike Sigma (where this pattern is confined to
# correlation-rule TYPE, already handled structurally) and unlike Elastic EQL
# (sequence/join is a query-language KEYWORD, not free-floating text), SPL
# expresses statistical/threshold logic inline as an ordinary comparison
# against a count/distinct-count variable (`dc_dest < 10`, `count >= 10`) -
# explicitly called out in the Stage 2 spec ("in Splunk SPL they are common
# inline"). Deliberately narrow: only a count/dc_* variable compared against
# a NUMBER counts - `count` appearing as a bare stats function name (which is
# nearly every SPL search) is not itself a rarity signal.
_SPL_RARITY_RE = re.compile(r"\b(dc_\w+|dc\([^)]*\)|count)\s*(<=|>=|<|>|!=)\s*\d+")


def detect_rarity_spl(raw_resolved_text: str) -> bool:
    return bool(_SPL_RARITY_RE.search(raw_resolved_text))


def detect_field_mismatch_atoms(atoms: list[TextAtom]) -> bool:
    metadata = [a for a in atoms if a.field.rsplit(".", 1)[-1].lower() in _ECS_IDENTITY_METADATA_FIELDS]
    path = [a for a in atoms if a.field.rsplit(".", 1)[-1].lower() in _ECS_IDENTITY_PATH_FIELDS]
    for m in metadata:
        m_tok = _basename_token(m.value)
        if not m_tok:
            continue
        for p in path:
            if m.negated == p.negated:
                continue
            p_tok = _basename_token(p.value)
            if p_tok and p_tok == m_tok:
                return True
    return False


@dataclass
class TextRuleClassification:
    tier: Optional[str]
    unscoreable: bool
    structural_findings: list[str]
    confidence: str  # capped at "medium"/"low" - see module docstring


def classify_text_rule(
    atoms: list[TextAtom],
    parsed_ok: bool,
    use_structural: bool = True,
    lists_mode: str = "v2",
    raw_text: Optional[str] = None,
    pre_resolution_text: Optional[str] = None,
) -> TextRuleClassification:
    """`use_structural`/`lists_mode` mirror `fragility.classify_rule`'s
    ablation parameters exactly (see that function's docstring for what each
    `lists_mode` value means) - real callers always want the defaults.
    Neither v1 state ever had FIELD_MISMATCH/RARITY at all (both are new in
    Stage 2), so both are gated on `use_structural` alone here too, same as
    the Sigma-side ablation.

    `raw_text` (the resolved SPL search / EQL query, pre-tokenization) is
    optional and used ONLY for `detect_rarity_spl` - the one structural check
    that needs to see comparison operators against count variables directly,
    which the flat atom list doesn't preserve. Omit it (Elastic callers do)
    to skip that check entirely rather than guess.

    `pre_resolution_text` (Splunk only - the search text BEFORE macro
    resolution) is optional and used ONLY to widen cloud-audit context
    detection to macro reference NAMES, not just resolved field/value pairs.
    See RESULTS.md's CIM finding: Splunk's CIM/macro layer routinely strips
    the platform marker a rule's DATA depends on (e.g. `` `okta_..._filter`
    `` / `` `kube_audit` ``) before the resolved search ever reaches atom
    extraction - the marker still exists, just in the macro's NAME rather
    than its expansion. This applies the SAME `CLOUD_AUDIT_CONTEXT_RE` used
    everywhere else in this module to an additional text source, not a
    hand-list of specific macro names.
    """
    if not parsed_ok or not atoms:
        return TextRuleClassification(None, True, [], "low")

    from mechanic import legacy_v1

    if lists_mode != "v2":
        is_protected_fn = (
            legacy_v1.is_protected_v1_documented if lists_mode == "v1_documented" else legacy_v1.is_protected_v1
        )
        classify_atom_fn = (
            legacy_v1.classify_atom_v1_documented if lists_mode == "v1_documented" else legacy_v1.classify_atom_v1
        )
        # v1 fidelity for the ATOM-scoring path: no negation-awareness (all
        # atoms, not just positive), legacy tool/protected-literal lists.
        # FIELD_MISMATCH/RARITY are separate, list-independent structural
        # checks - gated on `use_structural` alone, same as the Sigma-side
        # ablation, so "structural ON, lists OFF" is a real, distinct arm.
        field_mismatch = use_structural and detect_field_mismatch_atoms(atoms)
        rarity = use_structural and raw_text is not None and detect_rarity_spl(raw_text)
        cloud_context = legacy_v1.rule_is_cloud_audit_context([(a.field, a.value) for a in atoms])
        atom_tiers = []
        for a in atoms:
            if is_protected_fn(a.field, a.value, cloud_context):
                atom_tiers.append("TTP")
            else:
                atom_tiers.append(classify_atom_fn(a.field, a.value))
        # Same rarity-vs-tool-selector distinction as the v2 path below.
        rarity_is_independent_signal = rarity and "Tool" not in atom_tiers
        if field_mismatch or rarity_is_independent_signal:
            finding = "FIELD_MISMATCH" if field_mismatch else "RARITY"
            return TextRuleClassification("TTP", False, [finding], "medium")
        tier = max(atom_tiers, key=lambda t: legacy_v1.TIER_RANK[t]) if atom_tiers else None
        return TextRuleClassification(tier, False, [], "medium")

    positive = [a for a in atoms if not a.negated]
    field_mismatch = use_structural and detect_field_mismatch_atoms(atoms)
    rarity = use_structural and raw_text is not None and detect_rarity_spl(raw_text)

    cloud_context = rule_is_cloud_audit_context([(a.field, a.value) for a in atoms])
    if not cloud_context and pre_resolution_text:
        from mechanic.protected_literals import CLOUD_AUDIT_CONTEXT_RE

        cloud_context = bool(CLOUD_AUDIT_CONTEXT_RE.search(pre_resolution_text))

    # Same EventID/syscall structural gate as fragility.py's Sigma path:
    # excluded as a data-source selector when other positive atoms also
    # drive the rule; kept as the substantive criterion when it's the only
    # positive content there is (e.g. Elastic's `auditd.data.syscall in
    # ("init_module", "finit_module")`, which IS the entire rule).
    non_eventid_positive = [a for a in positive if not is_eventid_or_syscall_field(a.field)]
    eventid_is_sole_criterion = bool(positive) and not non_eventid_positive

    atom_tiers = []
    for a in positive:
        if is_eventid_or_syscall_field(a.field) and not eventid_is_sole_criterion:
            atom_tiers.append("IOC")
            continue
        atom_tiers.append(classify_atom(a.field, a.value, cloud_context).tier)

    # RARITY vs. "rarity OF a tool's use": a count/dc_* threshold wrapped
    # around an otherwise ordinary Tool-tier selector (e.g. `count >= 10`
    # gating `icacls.exe`/`cacls.exe`/`xcacls.exe` usage) isn't an
    # independent behavioral signal - the durability, such as it is, is
    # still "don't use icacls a lot," defeated by switching tools, same as
    # without the threshold. Only treat rarity as ITS OWN substantive
    # signal (promote to TTP) when no atom already resolved to Tool tier -
    # i.e. the threshold is standing on an otherwise generic/Artifact-tier
    # condition (e.g. "any process rarely seen across hosts"), which is
    # exactly what makes it durable. Found via splunk `Excessive Usage Of
    # Cacls App` (hand=Tool) vs `Detect Rare Executables` (hand=TTP) -
    # the same RARITY regex, two different correct answers.
    rarity_is_independent_signal = rarity and "Tool" not in atom_tiers

    if field_mismatch or rarity_is_independent_signal:
        tier = "TTP"
        findings = ["FIELD_MISMATCH"] if field_mismatch else ["RARITY"]
    elif atom_tiers:
        tier = max(atom_tiers, key=lambda t: TIER_RANK[t])
        findings = []
    else:
        return TextRuleClassification(None, False, [], "medium")  # insufficient information

    return TextRuleClassification(tier, False, findings, "medium")
