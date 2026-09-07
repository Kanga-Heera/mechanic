"""Structural fragility classifier, v2 (Stage 2, Part 2).

v1 tokenized rules into literal atoms and scored the rule as the max tier
among them (IOC < Artifact < Tool < TTP). Measured against 30-rule/repo hand
labels (seed 42): kappa 0.412, 36/38 disagreements under-scoring. Five causes
identified (see RESULTS.md); v2 addresses all five:

  1. Cross-platform tool names   -> `mechanic.refdata` (LOLBAS/GTFOBins/
                                     LOOBins/ATT&CK, not a hand list).
  2. Protected literals from a
     principle, not examples      -> `mechanic.protected_literals`.
  3. EventID/syscall structural
     test, not a blanket exclude  -> `_is_eventid_or_syscall_field` below,
                                     gated on whether OTHER non-eventid
                                     leaves exist in the same rule.
  4. Negation-blindness           -> atom classification skips leaves where
                                     `leaf["negated"]` is true; they're
                                     exclusions, not matches, and must not
                                     inflate the tier the same way a real
                                     match would.
  5. Structural blindness (the
     one that matters)            -> `mechanic.structural_detectors`,
                                     checked BEFORE atom-level scoring.

A SIXTH cause, found later, during the STP (Summiting the Pyramid)
external-validation pass in RESULTS.md, after all five above had already
shipped and been re-validated multiple times over: the rule-level
combination rule itself was wrong. STP's own documented methodology
combines multiple observables as `AND -> MIN(A, B)`, `OR -> MAX(A, B)` - an
AND-linked analytic is only as robust as its WEAKEST linked observable,
since the adversary need only defeat one of them; an OR-linked analytic is
at least as robust as its STRONGEST, since the adversary must defeat all of
them to evade it. This module's rule_tier used to be `max()` over every
positive atom in the whole rule, regardless of AND/OR structure - correct
for OR-linked rules, systematically wrong (over-scoring) for AND-linked
ones, which is the common case (a Sigma `selection:` block combines its
`field: value` pairs via implicit AND). Measured directly against MITRE's
own STP-scored analytics: Kendall's tau against the external standard moved
from -0.009 (noise) under the old flat-max design to +0.300 (p=0.008,
significant) under the corrected AND=MIN/OR=MAX walk, on the same 70 rules -
see RESULTS.md's STP validation section for the full investigation. Fixed
via `_combine_ast_tier`, which walks the AST directly instead of flattening
to a leaf list first.

A SEVENTH cause, found by a single hand-test of one real rule after all six
above had already shipped and been re-validated: `is_tool_value` decided an
atom's Tool tier from the matched STRING alone (a catalog hit, or the
`_CMDLET_RE`/`_EXE_RE` shape patterns), with no notion that the FIELD the
match occurs in can itself invert what a tool-shaped string means. A known
value in a binary-identity field (`Image`, `OriginalFileName`) is durable -
renaming the running binary is the only evasion, which is exactly the
FIELD_MISMATCH detector's canonical case above. The SAME shape of match in
an attacker-authored free-text field is NOT durable: the attacker writes
that text and can reword/obfuscate it indefinitely while keeping the
underlying behaviour, so a cmdlet-shaped substring there says nothing about
which tool ran, only about what the attacker happened to type. `ScriptBlockText`
(Sigma `logsource.category: ps_script`, Windows PowerShell Script Block
Logging, Event ID 4104) is the clean, unambiguous case: it is the verbatim,
un-resolved source text of the script as written, so `ScriptBlockText|
contains: 'Invoke-WebRequest'` is defeated by writing `iwr` instead - no
tool switch required, just a one-character alias. Originally fixed AD HOC
via a single-field special case (`_SCRIPT_CONTENT_FIELD_NAMES`/
`field_carries_script_content`, gating off `is_tool_value`'s signal paths
for that one field name) - see RESULTS.md, "Bug fix: script-content field
durability inversion" for that original investigation and the STP
re-validation it moved.

An EIGHTH cause, the same bug in the OPPOSITE direction, found immediately
after the seventh was generalized (see below): `GrantedAccess='0x1010'`
(the LSASS credential-dumping access-mask case - `docs/stp-alignment.md`'s
own cited STP Level 4 example, `TargetImage=lsass.exe` + `GrantedAccess`)
scored Artifact tier - wrongly COSMETIC. `0x1010`/`0x1410` are Windows'
own access-control bitmask values (PROCESS_VM_READ | PROCESS_QUERY_
(LIMITED_)INFORMATION - see Microsoft's "Process Security and Access
Rights" docs, the same source SigmaHQ's own canonical LSASS rules cite);
they are not an attacker's stylistic choice, they ARE the capability being
requested - changing the bit pattern forfeits the access, unlike renaming a
file. The classifier had no notion that a field's value can be FUNCTIONALLY
REQUIRED rather than freely chosen, the mirror image of cause seven's
missing notion (a field's value can be FRAGILE regardless of what string it
is).

**Both the seventh and eighth causes are the SAME bug**: an atom's tier was
decided from `value` alone, when it must be decided from `(field, value)`
TOGETHER, because the FIELD determines whether a value is a functional
constraint, attacker-authored text, a durable binary identity, a
data-source label, or a truly free literal. Fixed with ONE mechanism
covering both directions (and two more roles beyond them) instead of a
second ad-hoc special case: `mechanic.field_semantics` - a small, bounded,
DOCUMENTED registry mapping FIELD -> ROLE (`BINARY_IDENTITY`,
`ATTACKER_AUTHORED_TEXT`, `FUNCTIONAL_CONSTRAINT`, `DATA_SOURCE_SELECTOR`,
default `GENERIC`), resolved BEFORE surface-form classification and
governing what it does. The seventh cause's original ad-hoc mechanism
(`_SCRIPT_CONTENT_FIELD_NAMES`/`field_carries_script_content`) is REMOVED
entirely and re-expressed as the `ATTACKER_AUTHORED_TEXT` role - same
behavior, one registry instead of a parallel special case that the next
domain-specific field would otherwise need its own copy of. See
`mechanic/field_semantics.py`'s module docstring for the full field-by-role
registry, provenance per field, and which candidate fields were considered
and deliberately left `GENERIC` rather than guessed - or
[`docs/field-semantics.md`](../docs/field-semantics.md) for the same
material as reference documentation, plus the Part 4/5 validation results
(explanation-completeness fix, STP re-validation) not repeated here. A
THIRD, independent
consequence of this same registry (Part 2 of the brief that introduced it):
when a literal matches NO known signal at all (not protected, not IOC-
shaped, not a registered field role, not tool-vocabulary-shaped) it no
longer silently asserts "Artifact, high confidence, cosmetic" - see
`classify_atom`'s final fallback branch.

ORDER OF OPERATIONS per rule:
  1. UNSCOREABLE?            -> own bucket, no tier assigned.
  2. Any structural detector
     triggered (FIELD_MISMATCH,
     ABSENCE, RARITY,
     CORRELATION)?           -> tier = TTP, atom scoring still computed and
                                 reported for transparency but does not
                                 override the structural promotion.
  3. Otherwise: walk the AST (AND -> MIN, OR -> MAX, SELECTOR quantifier
     "1"/"any" -> MAX else MIN, filters and negated leaves excluded from the
     combination entirely - see `_combine_ast_tier`) rather than a flat max
     over every positive leaf. Multiple `conditions` roots (rare) are each
     walked independently and combined via MAX (each is an independent
     firing path). No positive leaves survive -> "insufficient information"
     rather than a guessed tier (an all-negated rule that ABSENCE didn't
     already catch is a shape this classifier doesn't understand, not a
     rule this classifier should force a Tool/Artifact guess onto).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from mechanic import ast_repr, field_semantics, protected_literals, refdata, structural_detectors

AstNode = dict[str, Any]

# These four tiers are an independently-arrived-at approximation of MITRE's
# Summiting the Pyramid (STP) v4.0 five-level Analytic Robustness model, not
# an original taxonomy - IOC/Artifact both correspond to STP's Level 1
# (Ephemeral Values); Tool collapses STP's Level 2 (Adversary-Brought Tool)
# and Level 3 (Pre-Existing Tools); TTP collapses STP's Level 4 (Some
# Implementations) and Level 5 (Full Technique). Every level quoted, cited,
# and mapped in detail, including why each collapse is a deliberate
# simplification rather than an oversight: docs/stp-alignment.md.
TIER_RANK = {"IOC": 0, "Artifact": 1, "Tool": 2, "TTP": 3}
RANK_TO_TIER = {v: k for k, v in TIER_RANK.items()}

_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CMDLET_RE = re.compile(
    r"\b(?:invoke|new|get|set|add|remove|start|stop|import|export|write|read|enable|disable)-[a-z][a-z0-9]+\b",
    re.I,
)
_EXE_RE = re.compile(r"\b[a-z0-9_\-]+\.exe\b", re.I)

def _is_eventid_or_syscall_field(field_name: Optional[str]) -> bool:
    """Despite the name (kept for continuity with existing call sites and
    tests predating a generalization made before `field_semantics.py`
    existed - `mechanic.experimental.multiformat.text_fragility` imports
    this exact name directly and must keep working unchanged), this is a
    thin wrapper over the field-semantics registry's `DATA_SOURCE_SELECTOR`
    role - see `field_semantics.py` for the actual field sets and their
    provenance, not duplicated here."""
    return field_semantics.field_role(field_name) == field_semantics.DATA_SOURCE_SELECTOR


def is_raw_ioc(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return bool(_HASH_RE.match(value)) or bool(_IPV4_RE.match(value))


def _basename(value: str) -> str:
    s = value
    for sep in ("\\", "/"):
        s = s.split(sep)[-1]
    return s.lower()


_EXEC_EXT_RE = re.compile(r"\.(exe|dll|sh|py|ps1|bat|cmd|com|scr|msi|vbs|jar)$", re.I)
_SHORT_TOOL_NAME_MIN_LEN = 3  # below this, require an executable-context marker (see below)


def _has_executable_context(value: str) -> bool:
    """A path separator or a recognized executable extension - the two
    signals that this token is being used as a process/image/file name
    rather than appearing incidentally as an ordinary short word. Added
    after Part 2c's hand-label re-validation found broadening the tool
    vocabulary to 2,032 names (GTFOBins includes bare 1-2 character entries
    like `at`, `R`) caused several over-scores in long, enumeration-heavy
    Splunk `eval`/`case` chains where a short word incidentally matched."""
    return ("\\" in value) or ("/" in value) or bool(_EXEC_EXT_RE.search(value))


# FIELD CONTEXT, not name length, is the right axis for the tool-vocabulary
# catalog lookup specifically. Length-based suppression (above) correctly
# had zero measured effect on the 90-rule set (see RESULTS.md Task 4) -
# investigating why found the real over-scores are LONGER words (`security`,
# `replace`, `url`) that are genuine LOLBAS/LOOBins/ATT&CK entries colliding
# with ordinary field values (a Windows EventLog `Channel=security`, a regex-
# substitution argument, a URL field) that have nothing to do with a process.
# A catalog lookup should only run at all when the FIELD plausibly carries a
# process/image/command-line value - name length doesn't discriminate that,
# field identity does. `field_semantics.field_role` == BINARY_IDENTITY is
# that field-identity test now (formerly this module's own
# `_PROCESS_CONTEXT_FIELD_NAMES`/`field_carries_process_context` - moved
# into the shared registry, same field set, same normalization, see
# `field_semantics.py` for the full list and provenance).


def _tool_shaped_ignoring_field_context(value: Any) -> bool:
    """The raw tool-vocabulary signal (catalog OR pattern match), with
    every field-role gate removed. NEVER used to assign a tier -
    `is_tool_value` (which applies the gates) is the only function that
    does that. Used only so an ATTACKER_AUTHORED_TEXT-field atom that got
    forced to Artifact still gets told apart, in its `reason`, from an atom
    that was never going to be tool-shaped in the first place - see
    `classify_atom`."""
    if not isinstance(value, str) or not value:
        return False
    if _CMDLET_RE.search(value):
        return True
    if _EXE_RE.search(value):
        return True
    return refdata.is_known_tool_name(_basename(value))


def is_tool_value(value: Any, field: Optional[str] = None) -> bool:
    if not isinstance(value, str) or not value:
        return False
    role = field_semantics.field_role(field)
    if role == field_semantics.ATTACKER_AUTHORED_TEXT:
        # Attacker-authored text (field_semantics.py) - neither signal path
        # below is trustworthy here: a catalog/pattern hit says the
        # attacker's TEXT happens to mention a tool-shaped string, not that
        # a specific tool ran. Falls through to classify_atom's Artifact
        # default (with its own, specific explanation - see the
        # attacker_authored_script_content_field branch there).
        return False
    if role == field_semantics.BINARY_IDENTITY:
        basename = _basename(value)
        if refdata.is_known_tool_name(basename):
            if len(basename) >= _SHORT_TOOL_NAME_MIN_LEN or _has_executable_context(value):
                return True
            # else: fall through - a short name with no executable-context
            # marker is suppressed even within a binary-identity field.
    # CMDLET_RE/EXE_RE are pattern-shaped matches (a value that itself LOOKS
    # like "Invoke-Something" or "foo.exe"), not a word-list lookup against
    # thousands of catalog entries - the field-context ambiguity that
    # motivates gating the catalog lookup doesn't apply to these THE SAME
    # WAY (an ordinary word colliding with a catalog entry), so they stay
    # unconditional with respect to THAT concern - but they are still
    # subject to the ATTACKER_AUTHORED_TEXT gate above, which is a different
    # axis entirely (not "does this word collide with the catalog", but "did
    # the attacker author this text").
    if _CMDLET_RE.search(value):
        return True
    if _EXE_RE.search(value):
        return True
    return False


@dataclass
class AtomClassification:
    field: Optional[str]
    value: Any
    tier: str
    reason: str
    # "high" (default) for every atom classified via a recognized signal
    # (a protected literal, a data-source selector, a raw IOC pattern, a
    # functional-constraint field, attacker-authored-text handling, or a
    # real tool/catalog/pattern match) - "medium" ONLY for the final,
    # no-known-signal-matched fallback in `classify_atom` (the honest
    # floor: mechanic doesn't know what an unrecognized value means, so it
    # must not claim "cosmetic" with the same confidence as a value it
    # actually recognizes). Deliberately a SEPARATE axis from
    # `priority.FragilitySignal.confidence` (which measures whether AST
    # parsing/combination succeeded at all, not per-atom semantic
    # certainty about a value mechanic DID manage to classify) - conflating
    # "we parsed this rule" with "we're sure this specific value means what
    # we think it means" is exactly the kind of overclaim this field exists
    # to stop making.
    semantic_confidence: str = "high"


@dataclass
class RuleClassification:
    tier: Optional[str]  # None if unscoreable or insufficient information
    unscoreable: bool
    insufficient_information: bool
    structural_findings: list[str]  # detector names that triggered
    structural_detail: dict[str, str]  # detector name -> explanation
    atoms: list[AtomClassification]
    cloud_audit_context: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "unscoreable": self.unscoreable,
            "insufficient_information": self.insufficient_information,
            "structural_findings": self.structural_findings,
            "structural_detail": self.structural_detail,
            "atoms": [
                {
                    "field": a.field,
                    "value": a.value,
                    "tier": a.tier,
                    "reason": a.reason,
                    "semantic_confidence": a.semantic_confidence,
                }
                for a in self.atoms
            ],
            "cloud_audit_context": self.cloud_audit_context,
        }


def classify_atom(field_name: Optional[str], value: Any, cloud_context: bool) -> AtomClassification:
    """Field-aware: resolves `field_semantics.field_role(field_name)` BEFORE
    any surface-form (value-shape) classification, and the role governs
    what happens next - see `mechanic/field_semantics.py`'s module
    docstring for why this must be `(field, value)` together, not `value`
    alone (the seventh/eighth-cause bug this replaces, `fragility.py`'s own
    module docstring)."""
    protected, reason = protected_literals.is_protected(field_name or "", value, cloud_context)
    if protected:
        return AtomClassification(field_name, value, "TTP", reason)

    role = field_semantics.field_role(field_name)

    if role == field_semantics.DATA_SOURCE_SELECTOR:
        # Structural test (not a blanket exclude): handled by the caller,
        # which knows whether OTHER non-selector leaves exist in this rule.
        # Here we only report the raw tier a bare literal-match would imply.
        return AtomClassification(field_name, value, "Artifact", "eventid_or_syscall_field")

    if is_raw_ioc(value):
        return AtomClassification(field_name, value, "IOC", "raw_ioc_pattern")

    if role == field_semantics.FUNCTIONAL_CONSTRAINT:
        # The FIELD carries the durability, not this specific value - see
        # field_semantics.py's FUNCTIONAL_CONSTRAINT docstring (the LSASS
        # GrantedAccess case). ANY positive match here is treated as
        # durable (TTP) regardless of which exact value it is, unlike
        # BINARY_IDENTITY below, which still needs a real tool/catalog
        # match on the value.
        return AtomClassification(field_name, value, "TTP", "functional_constraint_field")

    if role == field_semantics.ATTACKER_AUTHORED_TEXT and _tool_shaped_ignoring_field_context(value):
        # Would have scored Tool by string shape alone - forced to Artifact
        # because the field is attacker-authored text (field_semantics.py),
        # with a reason distinct from the generic literal default so
        # callers (priority.py's narrative) can explain WHY, not just
        # report the demoted tier.
        return AtomClassification(field_name, value, "Artifact", "attacker_authored_script_content_field")

    if is_tool_value(value, field_name):
        return AtomClassification(field_name, value, "Tool", "known_tool_name_or_cmdlet_or_exe_pattern")

    # No known signal matched AT ALL: not a protected literal, not a
    # data-source selector, not IOC-shaped, not a functional-constraint
    # field, not attacker-authored-text-shaped, not a recognized
    # tool/catalog/pattern match. Artifact is still the right DEFAULT tier
    # (nothing here earned a higher one) - but mechanic does not know what
    # this specific value actually means, and must not assert that it does.
    # This is the honest floor for the unbounded tail of domain-specific
    # values field_semantics.py's bounded, documented registry doesn't (and
    # by design never will fully) cover - semantic_confidence drops to
    # "medium", and the reason says "unrecognized," never "cosmetic."
    return AtomClassification(
        field_name, value, "Artifact", "unrecognized_literal_no_known_signal", semantic_confidence="medium"
    )


def _leaf_value_for_classification(leaf: AstNode) -> Any:
    return leaf.get("value")


def _combine_ast_tier(
    node: AstNode, cloud_context: bool, eventid_is_sole_criterion: bool
) -> Optional[int]:
    """Walk the AST directly and combine per STP's own documented rule:
    AND -> MIN(children), OR -> MAX(children). Returns a TIER_RANK int, or
    None if this subtree contributes nothing to the combination (a filter,
    a negated leaf, or a non-substantive EventID/syscall selector - all
    excluded from the walk entirely, not folded in as a low value, so they
    can't spuriously drag an AND's MIN down to IOC the way including them
    with a low placeholder tier would).
    """
    kind = node.get("node")

    if kind == "leaf":
        if node.get("negated"):
            return None
        if node.get("kind") not in ("field_value", "keyword"):
            return None
        f, v = node.get("field"), node.get("value")
        if _is_eventid_or_syscall_field(f):
            if not eventid_is_sole_criterion:
                return None  # boilerplate data-source selector - excluded, not IOC-floored
            return TIER_RANK[classify_atom(f, v, cloud_context).tier]
        return TIER_RANK[classify_atom(f, v, cloud_context).tier]

    if kind == "selection":
        if node.get("kind") == "filter":
            return None  # filters are noise reduction, not detection logic - STP's own rule too
        return _combine_ast_tier(node["child"], cloud_context, eventid_is_sole_criterion)

    if kind == "AND":
        vals = [
            v
            for v in (
                _combine_ast_tier(c, cloud_context, eventid_is_sole_criterion) for c in node.get("children", [])
            )
            if v is not None
        ]
        return min(vals) if vals else None

    if kind == "OR":
        vals = [
            v
            for v in (
                _combine_ast_tier(c, cloud_context, eventid_is_sole_criterion) for c in node.get("children", [])
            )
            if v is not None
        ]
        return max(vals) if vals else None

    if kind == "NOT":
        return None  # the whole subtree is negated - excluded, same as a negated leaf

    if kind == "SELECTOR":
        # "1 of x*"/"any of x*" is OR semantics (MAX); "all of x*" or a
        # specific numeric count ("2 of x*") is treated as AND-like (MIN) -
        # needing multiple still means defeating any ONE of the required
        # set breaks the match, the same vulnerability AND has.
        quant = node.get("quantifier")
        vals = [
            v
            for v in (
                _combine_ast_tier(c, cloud_context, eventid_is_sole_criterion) for c in node.get("children", [])
            )
            if v is not None
        ]
        if not vals:
            return None
        return max(vals) if quant in ("1", "any") else min(vals)

    return None


def classify_rule(
    rule_ast: AstNode, use_structural: bool = True, lists_mode: str = "v2", combine_mode: str = "and_or_aware"
) -> RuleClassification:
    """`use_structural`/`lists_mode` exist ONLY for Part 2c's ablation study -
    real callers always want the defaults (`use_structural=True,
    lists_mode="v2"` == the actual v2 classifier). `lists_mode`:

      "v2"           - the real v2 lists (this module + protected_literals.py
                       + refdata.py).
      "v1_documented" - the state that actually produced the documented
                       kappa=0.412 baseline: last-dotted-segment matching and
                       context-gating already fixed, but v1's narrow
                       (example-derived) protected-literal categories,
                       Windows-only tool list, blanket EventID/syscall
                       exclusion, and no negation-awareness. This is the
                       correct "list fixes OFF" comparator for isolating
                       structural detection's marginal contribution.
      "v1_prefix"    - one step EARLIER than the documented baseline: exact
                       (not last-segment) field-name matching, the bug the
                       dotted-path fix corrected. Kept for the "how much
                       further back would this go" arm, clearly distinguished
                       from "v1_documented" - see `legacy_v1.py`'s docstring
                       for why conflating these two was a real ablation bug.

    `combine_mode`: "and_or_aware" (default, correct) walks the AST per
    STP's own AND=MIN/OR=MAX rule. "flat_max" reproduces the ORIGINAL v2
    bug (max over every positive atom regardless of AND/OR structure) -
    kept only for the RESULTS.md before/after comparison this fix's own
    validation needed, never the default for real use.
    """
    if lists_mode != "v2":
        return _classify_rule_v1_lists(rule_ast, use_structural, lists_mode)

    detectors = structural_detectors.run_all_detectors(rule_ast)

    if detectors["UNSCOREABLE"].triggered:
        return RuleClassification(
            tier=None,
            unscoreable=True,
            insufficient_information=False,
            structural_findings=["UNSCOREABLE"],
            structural_detail={"UNSCOREABLE": detectors["UNSCOREABLE"].detail},
            atoms=[],
            cloud_audit_context=False,
        )

    structural_hits = (
        [name for name in ("FIELD_MISMATCH", "ABSENCE", "RARITY", "CORRELATION") if detectors[name].triggered]
        if use_structural
        else []
    )
    structural_detail = {name: detectors[name].detail for name in structural_hits}

    all_leaves = list(ast_repr.iter_leaves_of_rule(rule_ast)) if rule_ast.get("type") != "correlation" else []
    positive_leaves = [
        l for l in all_leaves if not l.get("negated") and l.get("kind") in ("field_value", "keyword")
    ]

    cloud_context = protected_literals.rule_is_cloud_audit_context(
        [(l.get("field") or "", l.get("value")) for l in all_leaves]
    )

    # EventID/syscall structural gate: excluded (contributes only IOC-floor,
    # not its literal-match Artifact tier) when OTHER, non-eventid positive
    # leaves also drive the rule; NOT excluded (kept as the rule's own
    # substantive criterion) when it's the only positive content there is.
    non_eventid_positive = [l for l in positive_leaves if not _is_eventid_or_syscall_field(l.get("field"))]
    eventid_is_sole_criterion = bool(positive_leaves) and not non_eventid_positive

    atoms: list[AtomClassification] = []
    for leaf in positive_leaves:
        f = leaf.get("field")
        v = _leaf_value_for_classification(leaf)
        if _is_eventid_or_syscall_field(f) and not eventid_is_sole_criterion:
            atoms.append(AtomClassification(f, v, "IOC", "eventid_or_syscall_data_source_selector_excluded"))
            continue
        atoms.append(classify_atom(f, v, cloud_context))

    if structural_hits:
        tier = "TTP"
    elif combine_mode == "flat_max":
        tier = max(atoms, key=lambda a: TIER_RANK[a.tier]).tier if atoms else None
    else:
        # AND/OR-aware: walk each condition root independently (AND->MIN,
        # OR->MAX per STP's own rule), then MAX across roots - multiple
        # `conditions` entries are independent firing paths, not one
        # AND/OR structure spanning across them.
        condition_roots = rule_ast.get("conditions", []) if rule_ast.get("type") != "correlation" else []
        root_ranks = [
            v
            for v in (
                _combine_ast_tier(root, cloud_context, eventid_is_sole_criterion) for root in condition_roots
            )
            if v is not None
        ]
        tier = RANK_TO_TIER[max(root_ranks)] if root_ranks else None

    return RuleClassification(
        tier=tier,
        unscoreable=False,
        insufficient_information=(tier is None),
        structural_findings=structural_hits,
        structural_detail=structural_detail,
        atoms=atoms,
        cloud_audit_context=cloud_context,
    )


def _classify_rule_v1_lists(rule_ast: AstNode, use_structural: bool, lists_mode: str) -> RuleClassification:
    from mechanic import legacy_v1

    is_protected_fn = (
        legacy_v1.is_protected_v1_documented if lists_mode == "v1_documented" else legacy_v1.is_protected_v1
    )
    classify_atom_fn = (
        legacy_v1.classify_atom_v1_documented if lists_mode == "v1_documented" else legacy_v1.classify_atom_v1
    )

    detectors = structural_detectors.run_all_detectors(rule_ast)
    if detectors["UNSCOREABLE"].triggered:
        return RuleClassification(
            tier=None,
            unscoreable=True,
            insufficient_information=False,
            structural_findings=["UNSCOREABLE"],
            structural_detail={"UNSCOREABLE": detectors["UNSCOREABLE"].detail},
            atoms=[],
            cloud_audit_context=False,
        )

    structural_hits = (
        [name for name in ("FIELD_MISMATCH", "ABSENCE", "RARITY", "CORRELATION") if detectors[name].triggered]
        if use_structural
        else []
    )
    structural_detail = {name: detectors[name].detail for name in structural_hits}

    # v1 bug, preserved: ALL leaves considered, negation ignored entirely.
    all_leaves = list(ast_repr.iter_leaves_of_rule(rule_ast)) if rule_ast.get("type") != "correlation" else []
    field_value_leaves = [l for l in all_leaves if l.get("kind") in ("field_value", "keyword")]
    cloud_context = legacy_v1.rule_is_cloud_audit_context([(l.get("field") or "", l.get("value")) for l in all_leaves])

    atoms: list[AtomClassification] = []
    for leaf in field_value_leaves:
        f, v = leaf.get("field"), leaf.get("value")
        if is_protected_fn(f or "", v, cloud_context):
            atoms.append(AtomClassification(f, v, "TTP", "v1_protected_literal"))
        else:
            atoms.append(AtomClassification(f, v, classify_atom_fn(f or "", v), "v1_atom_classify"))

    if structural_hits:
        tier = "TTP"
    elif atoms:
        tier = max(atoms, key=lambda a: legacy_v1.TIER_RANK[a.tier]).tier
    else:
        tier = None

    return RuleClassification(
        tier=tier,
        unscoreable=False,
        insufficient_information=(tier is None),
        structural_findings=structural_hits,
        structural_detail=structural_detail,
        atoms=atoms,
        cloud_audit_context=cloud_context,
    )
