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
tool switch required, just a one-character alias. The existing field-context
logic (`_PROCESS_CONTEXT_FIELD_NAMES`, the Task 8 fix that stopped Splunk
over-scoring) only ever asked "is this a process/image/commandline identity
field" vs. "unrelated" - it had no third category for "this field is raw
text the attacker authored." Fixed via `_SCRIPT_CONTENT_FIELD_NAMES` /
`field_carries_script_content`, which gates OFF both of `is_tool_value`'s
signal paths (catalog lookup AND the two pattern regexes) for that field,
and a dedicated `classify_atom` branch that gives the resulting Artifact-tier
atom its own explanation rather than the generic literal-string default - see
the comment on `_SCRIPT_CONTENT_FIELD_NAMES` below for exactly which other
candidate fields (CommandLine, ps_module's Payload/ContextInfo, ps_classic's
Data) were considered and deliberately left out, and why. See RESULTS.md,
"Bug fix: script-content field durability inversion" for the full
investigation, including the STP re-validation this fix moved.

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

from mechanic import ast_repr, protected_literals, refdata, structural_detectors

AstNode = dict[str, Any]

TIER_RANK = {"IOC": 0, "Artifact": 1, "Tool": 2, "TTP": 3}
RANK_TO_TIER = {v: k for k, v in TIER_RANK.items()}

_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CMDLET_RE = re.compile(
    r"\b(?:invoke|new|get|set|add|remove|start|stop|import|export|write|read|enable|disable)-[a-z][a-z0-9]+\b",
    re.I,
)
_EXE_RE = re.compile(r"\b[a-z0-9_\-]+\.exe\b", re.I)

_EVENTID_SYSCALL_EXACT = {"eventid", "eventcode", "event.code", "syscall", "auditd.data.syscall"}
# Generalized beyond EventID/syscall after the AND/OR combination fix
# surfaced the same failure mode for a different family of fields: a
# DATA-SOURCE-IDENTIFICATION field says WHICH platform/service/API emitted
# an event - it is not something the adversary independently varies (using
# the EC2 API to disable EBS encryption unavoidably sets eventSource to
# ec2.amazonaws.com; there is no adversary choice being evaded there,
# unlike a renamable filename). Under the corrected AND=MIN combination,
# leaving these fields un-excluded meant every AND-linked cloud-audit rule
# got dragged down to its data-source-selector's generic Artifact tier
# instead of its actual substantive (often TTP-tier, protected) action
# field - found immediately when the AND/OR fix was first run against the
# LLM development set (19/30 SigmaHQ rules flipped, nearly all cloud-audit
# rules) and confirmed to be this exact mechanism, not revealed label bias,
# before accepting the result - see RESULTS.md.
_EVENTID_SYSCALL_LAST_SEGMENT = {
    "eventid", "eventcode", "syscall",
    "eventsource",  # AWS CloudTrail's service-identifier field (ec2.amazonaws.com, ...)
    "provider",  # Elastic's event.provider (same AWS-service-identifier role as eventSource)
    "dataset",  # ECS data_stream.dataset - which integration produced the event
    "sourcetype",  # Splunk's own data-source-type identifier
}


def _is_eventid_or_syscall_field(field_name: Optional[str]) -> bool:
    """Despite the name (kept for continuity with existing call sites and
    tests predating this generalization), this now covers the broader
    "data-source selector, not adversary-controlled" category - see the
    comment on `_EVENTID_SYSCALL_LAST_SEGMENT` above."""
    f = (field_name or "").lower()
    if f in _EVENTID_SYSCALL_EXACT:
        return True
    return f.rsplit(".", 1)[-1] in _EVENTID_SYSCALL_LAST_SEGMENT


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
# field identity does. Covers Sysmon-style PascalCase (Image, CommandLine,
# NewProcessName, ParentImage), ECS (process.name, process.command_line,
# process.parent.executable), and Splunk CIM snake_case (Processes.process,
# Processes.process_name, Processes.original_file_name) uniformly by
# normalizing away case and underscores before comparing.
_PROCESS_CONTEXT_FIELD_NAMES = {
    "image", "parentimage", "targetimage", "currentimage", "sourceimage",
    "grandparentimage", "previousimage", "newprocessname",
    "originalfilename", "processname", "parentprocessname",
    "process", "parentprocess", "executable", "parentexecutable",
    "commandline", "parentcommandline", "processcommandline",
    "name",  # bare ECS `process.name`/`process.parent.name` last segment
    # Linux auditd EXECVE-record convention: a0 is argv[0] (the executable
    # name), exe/comm are the full executable path / short command name -
    # a DIFFERENT naming convention for the same "this is the process"
    # concept, caught by a regression this fix itself introduced
    # (`lnx_auditd_unzip_hidden_zip_files_steganography.yml` keys on `a0`).
    "a0", "exe", "comm",
}


def _normalize_field_last_segment(field: Optional[str]) -> str:
    seg = (field or "").rsplit(".", 1)[-1].lower()
    return seg.replace("_", "")


def field_carries_process_context(field: Optional[str]) -> bool:
    return _normalize_field_last_segment(field) in _PROCESS_CONTEXT_FIELD_NAMES


# ATTACKER-AUTHORED SCRIPT CONTENT is a different axis from process context
# above, and inverts the same tool-vocabulary signal instead of just gating
# it on/off: a cmdlet/tool-shaped substring in one of these fields is text
# the attacker wrote, not evidence of which tool ran, so it must NOT earn
# Tool tier the way the identical string would in a binary-identity field.
#
# `scriptblocktext` is the field this was found against, and the only one
# included here with full confidence:
#
#   - Sigma `logsource.category: ps_script` (Windows PowerShell Script
#     Block Logging, Event ID 4104) logs the VERBATIM, un-resolved source
#     text of the script as written - Microsoft's own documentation for
#     this feature describes it as capturing script blocks "as they are
#     executed", not a normalized/alias-resolved record. `Invoke-WebRequest`
#     appearing in ScriptBlockText is defeated by writing `iwr` (a built-in
#     alias) instead - no tool switch, a one-character rename.
#   - Checked empirically against two real, independently-sourced rule
#     corpora (hayabusa-rules' vendored SigmaHQ mirror + its own builtin
#     set, ~5,000 rules total, at the time this was written): every single
#     rule using a field literally named `ScriptBlockText` (186/186) has
#     `logsource.category: ps_script` - this field name carries no
#     collision risk with an unrelated meaning in real-world rules.
#
# Candidate fields considered and deliberately NOT included here - each is
# a disclosed scope decision, not an oversight:
#
#   - `CommandLine`/`ParentCommandLine`/`ProcessCommandLine`: genuinely
#     mixed - argv[0] (a real binary path/identity, already reached via
#     `field_carries_process_context`'s catalog-lookup branch, validated by
#     the FIELD_MISMATCH canonical case this fix must not regress) sits in
#     the same string as attacker-authored arguments. This module has no
#     argv parser to split the two apart, and guessing which portion a
#     `|contains` match landed in would be exactly the kind of unprincipled,
#     per-rule guess Part 2's design brief warned against - left as a
#     disclosed gap for future work with real argv-aware parsing, not
#     silently swept into this fix.
#   - `Payload`/`ContextInfo` (Sigma `logsource.category: ps_module`,
#     PowerShell Module Logging, Event ID 4103): superficially the same
#     shape as ScriptBlockText, but PowerShell's module-logging pipeline
#     resolves an invoked cmdlet's ALIAS to its real name before logging
#     it (`CommandInvocation(Get-WmiObject)` is what gets written even if
#     the attacker typed `gwmi`) - a cmdlet-name substring match here is
#     NOT trivially defeated by the same alias-rename trick that breaks a
#     ScriptBlockText match, so treating it identically would be a guess
#     dressed up as the same fix, not the same fix. Left untouched pending
#     its own dedicated investigation of what module logging actually
#     resolves and what it doesn't (e.g. raw .NET method calls bypass
#     module logging's ParameterBinding entirely, a real but different
#     evasion this module does not currently reason about).
#   - `Data` (Sigma `logsource.category: ps_classic`/`ps_classic_start`,
#     classic PowerShell transcript/host-start logging, Event ID 400/800):
#     the same free-text-content argument applies in principle, but unlike
#     ScriptBlockText the bare field name `Data` is NOT unambiguous - the
#     same empirical corpus check above found 18 real rules using a field
#     named `Data` under `service: application` (unrelated Windows
#     Application-log events) and 2 more under `service:
#     msexchange-management`, neither of which carries attacker-authored
#     script content. Gating on `Data` by name alone would misclassify
#     those. Doing this correctly needs the field-name check to also see
#     the rule's logsource category, which classify_atom does not have
#     threaded through today - left as a disclosed, uncovered gap rather
#     than guessed at.
_SCRIPT_CONTENT_FIELD_NAMES = {"scriptblocktext"}


def field_carries_script_content(field: Optional[str]) -> bool:
    return _normalize_field_last_segment(field) in _SCRIPT_CONTENT_FIELD_NAMES


def _tool_shaped_ignoring_field_context(value: Any) -> bool:
    """The raw tool-vocabulary signal (catalog OR pattern match), with
    every field-context gate removed. NEVER used to assign a tier -
    `is_tool_value` (which applies the gates) is the only function that
    does that. Used only so a script-content-field atom that got forced to
    Artifact still gets told apart, in its `reason`, from an atom that was
    never going to be tool-shaped in the first place - see `classify_atom`."""
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
    if field_carries_script_content(field):
        # Attacker-authored script text (see _SCRIPT_CONTENT_FIELD_NAMES
        # above) - neither signal path below is trustworthy here: a
        # catalog/pattern hit says the attacker's script TEXT happens to
        # mention a tool-shaped string, not that a specific tool ran.
        # Falls through to classify_atom's Artifact default (with its own,
        # specific explanation - see the
        # attacker_authored_script_content_field branch there).
        return False
    if field_carries_process_context(field):
        basename = _basename(value)
        if refdata.is_known_tool_name(basename):
            if len(basename) >= _SHORT_TOOL_NAME_MIN_LEN or _has_executable_context(value):
                return True
            # else: fall through - a short name with no executable-context
            # marker is suppressed even within a process-context field.
    # CMDLET_RE/EXE_RE are pattern-shaped matches (a value that itself LOOKS
    # like "Invoke-Something" or "foo.exe"), not a word-list lookup against
    # thousands of catalog entries - the field-context ambiguity that
    # motivates gating the catalog lookup doesn't apply to these THE SAME
    # WAY (an ordinary word colliding with a catalog entry), so they stay
    # unconditional with respect to THAT concern - but they are still
    # subject to the script-content gate above, which is a different axis
    # entirely (not "does this word collide with the catalog", but "did the
    # attacker author this text").
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
                {"field": a.field, "value": a.value, "tier": a.tier, "reason": a.reason} for a in self.atoms
            ],
            "cloud_audit_context": self.cloud_audit_context,
        }


def classify_atom(field_name: Optional[str], value: Any, cloud_context: bool) -> AtomClassification:
    protected, reason = protected_literals.is_protected(field_name or "", value, cloud_context)
    if protected:
        return AtomClassification(field_name, value, "TTP", reason)
    if _is_eventid_or_syscall_field(field_name):
        # Structural test (not a blanket exclude): handled by the caller,
        # which knows whether OTHER non-eventid leaves exist in this rule.
        # Here we only report the raw tier a bare literal-match would imply.
        return AtomClassification(field_name, value, "Artifact", "eventid_or_syscall_field")
    if is_raw_ioc(value):
        return AtomClassification(field_name, value, "IOC", "raw_ioc_pattern")
    if field_carries_script_content(field_name) and _tool_shaped_ignoring_field_context(value):
        # Would have scored Tool by string shape alone - forced to Artifact
        # because the field is attacker-authored script content (see
        # _SCRIPT_CONTENT_FIELD_NAMES), with a reason distinct from the
        # generic literal default so callers (priority.py's narrative) can
        # explain WHY, not just report the demoted tier.
        return AtomClassification(field_name, value, "Artifact", "attacker_authored_script_content_field")
    if is_tool_value(value, field_name):
        return AtomClassification(field_name, value, "Tool", "known_tool_name_or_cmdlet_or_exe_pattern")
    return AtomClassification(field_name, value, "Artifact", "literal_string_or_path_default")


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
