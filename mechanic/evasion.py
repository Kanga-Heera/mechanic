"""Stage 3 Phase 2, Part 1: deterministic evasion transformer (Uetz et al.,
"You Cannot Escape Me," USENIX Sec 2024).

Implements the paper's five evasion technique classes as deterministic
STRING TRANSFORMS applied to the literal a rule's fragile atom keys on:

  1. character_insertion      - insert characters a command interpreter
                                 ignores (here: a backtick, PowerShell's
                                 escape character) into a matched keyword.
  2. synonymous_substitution   - swap a flag/argument for a known
                                 equivalent form (-enc / -EncodedCommand,
                                 -c / -Command, ...).
  3. omission                  - drop a redundant path prefix or a
                                 quote/whitespace wrapper while preserving
                                 the same underlying command.
  4. reordering                - swap two adjacent whitespace-separated
                                 tokens where argument order isn't fixed.
  5. recoding                  - case-toggle the literal (Windows paths and
                                 most shell keywords are matched
                                 case-insensitively, so a case-varied form
                                 is often still functionally identical).

WHICH ATOM: `fragile_atoms_for_rule` reuses `mechanic.fragility.classify_rule`
- the SAME classifier mechanic already runs for triage - to find the atom(s)
tied for the rule's own (AND=MIN/OR=MAX) tier. This module never re-derives
fragility scoring; it only asks the existing classifier which atom(s) are
weakest and generates candidate evasions of THOSE.

FIELD-CATEGORY GATING (the "don't invent fake evasions" guard): the five
techniques above are about how a COMMAND INTERPRETER parses a command line -
they have no real-world meaning applied to a raw IOC (an IP address has no
"case"; inserting a backtick into a DestinationIp field doesn't correspond
to any packet an attacker could actually send) or to a protocol/OS-defined
protected literal (a registry autorun path is not shell-parsed at all).
Candidates are therefore only generated for fields mechanic's own
`fragility.field_carries_process_context` already recognizes as
command/process-shaped, split further into two sub-categories:

  "commandline"    - CommandLine/ParentCommandLine/ProcessCommandLine: text
                      actually parsed by a shell/interpreter. All five
                      techniques apply.
  "path_identity"  - Image/OriginalFileName/TargetFilename/etc: an opaque
                      filesystem path or file identity, not shell-parsed.
                      Only recoding applies (case-insensitive filesystems
                      make a case-varied path a real, if usually neutral,
                      variant) - character insertion/synonym/omission/
                      reordering on a bare filename would require an
                      actually different file on disk, which is a
                      structural rename evasion, not a syntax trick, and
                      is deliberately OUT of this transformer's scope (see
                      docs/stage3-phase2-status.md).
  everything else  - zero candidates. This is what makes a raw IOC field
                      (DestinationIp, a file hash) or a protected literal
                      (a registry autorun key, an AD schema attribute name)
                      correctly yield no candidates at all, not candidates
                      that the harness then has to discard - see Part 2's
                      validation tests.

THE HARNESS DECIDES, NOT THIS MODULE: `generate_evasions` (and the
convenience of the field-category gate above) only produces CANDIDATES.
`confirm_real_evasions` is the only function allowed to call something a
genuine evasion, and it does so by running the candidate through
`mechanic.verify.evaluate()` against the ORIGINAL rule: a candidate the
original rule still fires on is discarded (not a real evasion of it); a
candidate that comes back UNVERIFIABLE is also discarded, never silently
promoted to "evaded" on an untrusted zero - the same trusted/unverifiable
discipline as everywhere else in this project.

HONESTY LIMIT, stated once here and repeated wherever results using this
module are reported: these five techniques define both the evasions this
module can generate AND, implicitly, what a repair verified against them
has actually been shown to resist. A PASS against `mechanic.gate` using
only these mechanical evasions is verified against a known, bounded evasion
space - not against a creative human adversary. This is exactly why
requesting Uetz et al.'s own external, expert-crafted evasion corpus
remains worth doing later (see docs/stage3-harness-evaluation.md, Task 5,
and docs/stage3-phase2-status.md) - it is a different, larger evasion space
than anything generated here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any, Optional, Union

from mechanic import ast_repr, fragility, loader
from mechanic import verify as rverify

TECHNIQUE_CHAR_INSERTION = "character_insertion"
TECHNIQUE_SYNONYM = "synonymous_substitution"
TECHNIQUE_OMISSION = "omission"
TECHNIQUE_REORDERING = "reordering"
TECHNIQUE_RECODING = "recoding"

ALL_TECHNIQUES = [
    TECHNIQUE_CHAR_INSERTION,
    TECHNIQUE_SYNONYM,
    TECHNIQUE_OMISSION,
    TECHNIQUE_REORDERING,
    TECHNIQUE_RECODING,
]


class EvasionError(Exception):
    """Setup/usage problems only (bad rule file, correlation rule, ...) -
    never raised because a technique simply produced zero candidates, which
    is a normal, expected outcome for many field/literal combinations."""


# ---------------------------------------------------------------------------
# Fragile-atom lookup (reuses mechanic.fragility - does not re-derive it)
# ---------------------------------------------------------------------------


@dataclass
class FragileAtom:
    field: Optional[str]
    value: Any
    tier: str
    reason: str


def fragile_atoms_for_rule(rule_path: Union[str, Path]) -> tuple[list[FragileAtom], Optional[str]]:
    """The atom(s) tied for the rule's own overall tier under
    `fragility.classify_rule`'s AND=MIN/OR=MAX walk - the weakest link an
    adversary would target first and a repair must strengthen. Returns
    ([], None) for an unscoreable/insufficient-information rule (nothing to
    target)."""
    rule_path = Path(rule_path)
    rules, failures = loader.load_file(rule_path)
    if failures:
        f = failures[0]
        raise EvasionError(f"{rule_path}: failed to load ({f.category}: {f.message})")
    if not rules:
        raise EvasionError(f"{rule_path}: no rule documents found")
    lr = rules[0]
    if lr.rule_type != "standard":
        raise EvasionError(f"{rule_path}: correlation rules are not supported")

    tree = ast_repr.build_ast(lr.rule)
    classification = fragility.classify_rule(tree)
    if classification.tier is None:
        return [], None
    fragile = [
        FragileAtom(a.field, a.value, a.tier, a.reason)
        for a in classification.atoms
        if a.tier == classification.tier
    ]
    return fragile, classification.tier


# ---------------------------------------------------------------------------
# Field-category gating
# ---------------------------------------------------------------------------

_COMMAND_LINE_LAST_SEGMENTS = {"commandline", "parentcommandline", "processcommandline"}


def _field_category(field_name: Optional[str]) -> str:
    seg = fragility._normalize_field_last_segment(field_name)
    if seg in _COMMAND_LINE_LAST_SEGMENTS:
        return "commandline"
    if seg in fragility._PROCESS_CONTEXT_FIELD_NAMES:
        return "path_identity"
    return "other"


_TECHNIQUE_ALLOWED_CATEGORIES = {
    TECHNIQUE_CHAR_INSERTION: {"commandline"},
    TECHNIQUE_SYNONYM: {"commandline"},
    TECHNIQUE_OMISSION: {"commandline"},
    TECHNIQUE_REORDERING: {"commandline"},
    TECHNIQUE_RECODING: {"commandline", "path_identity"},
}


# ---------------------------------------------------------------------------
# Per-technique candidate generators - each takes the matched literal string
# and returns a list of distinct transformed strings (never including the
# input unchanged).
# ---------------------------------------------------------------------------

_ALPHA_RUN_RE = re.compile(r"[A-Za-z]+")


def _char_insertion_candidates(literal: str) -> list[str]:
    """Backtick-fragment each alphabetic run of plausible keyword length
    (2-8 chars) - e.g. 'IEX' -> 'I`E`X', PowerShell's own escape character,
    ignored by the parser and reassembled before execution. One candidate
    per eligible run, substituted back into its original position."""
    out: list[str] = []
    seen = set()
    for m in _ALPHA_RUN_RE.finditer(literal):
        run = m.group()
        if not (2 <= len(run) <= 8):
            continue
        inserted = "`".join(list(run))
        if inserted == run:
            continue
        cand = literal[: m.start()] + inserted + literal[m.end() :]
        if cand not in seen and cand != literal:
            seen.add(cand)
            out.append(cand)
    return out


_SYNONYM_PAIRS = [
    ("-enc", "-EncodedCommand"),
    ("-e", "-EncodedCommand"),
    ("-nop", "-NonInteractive"),
    ("-noni", "-NonInteractive"),
    ("-c", "-Command"),
    ("-command", "-Command"),
    ("-ep", "-ExecutionPolicy"),
    ("-executionpolicy", "-ExecutionPolicy"),
    ("-w", "-WindowStyle"),
    ("-windowstyle", "-WindowStyle"),
    ("-sta", "-STA"),
    ("-file", "-File"),
]
_SYNONYM_MAP: dict[str, set[str]] = {}
for _a, _b in _SYNONYM_PAIRS:
    _SYNONYM_MAP.setdefault(_a.lower(), set()).add(_b)
    _SYNONYM_MAP.setdefault(_b.lower(), set()).add(_a)


def _synonym_candidates(literal: str) -> list[str]:
    """Whitespace-tokenize the literal; for each token with a known
    flag/argument synonym, substitute it (preserving every other token
    exactly) and rejoin with single spaces."""
    tokens = literal.split(" ")
    out: list[str] = []
    seen = set()
    for i, tok in enumerate(tokens):
        subs = _SYNONYM_MAP.get(tok.lower())
        if not subs:
            continue
        for s in sorted(subs):
            new_tokens = list(tokens)
            new_tokens[i] = s
            cand = " ".join(new_tokens)
            if cand != literal and cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


_PATH_PREFIX_RE = re.compile(r"^[A-Za-z]:\\(?:[^\\]+\\)+")


def _omission_candidates(literal: str) -> list[str]:
    """Drop a leading Windows path prefix, or a matching quote wrapper, or
    collapse doubled internal whitespace - redundant characters that don't
    change what actually runs."""
    out: list[str] = []
    seen = set()

    def _add(cand: str) -> None:
        if cand and cand != literal and cand not in seen:
            seen.add(cand)
            out.append(cand)

    m = _PATH_PREFIX_RE.match(literal)
    if m:
        _add(literal[m.end() :])
    if len(literal) >= 2 and literal[0] == literal[-1] and literal[0] in ("'", '"'):
        _add(literal[1:-1])
    collapsed = re.sub(r" {2,}", " ", literal)
    _add(collapsed)
    return out


def _reordering_candidates(literal: str) -> list[str]:
    """Swap each pair of adjacent whitespace-separated tokens - argument
    order isn't fixed for most CLI tools' flags."""
    tokens = literal.split(" ")
    if len(tokens) < 2:
        return []
    out: list[str] = []
    seen = set()
    for i in range(len(tokens) - 1):
        swapped = list(tokens)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        cand = " ".join(swapped)
        if cand != literal and cand not in seen:
            seen.add(cand)
            out.append(cand)
    return out


def _recoding_candidates(literal: str) -> list[str]:
    """Case-toggle the literal two ways: alternating upper/lower, and a
    plain swapcase. No-ops (no alphabetic characters at all) yield
    nothing, which is what correctly excludes e.g. bare numeric/IP
    literals without needing a separate special case for them."""
    if not any(c.isalpha() for c in literal):
        return []
    alt_chars = []
    upper_next = True
    for c in literal:
        if c.isalpha():
            alt_chars.append(c.upper() if upper_next else c.lower())
            upper_next = not upper_next
        else:
            alt_chars.append(c)
    alternating = "".join(alt_chars)
    swapped = literal.swapcase()
    out = []
    for cand in (alternating, swapped):
        if cand != literal and cand not in out:
            out.append(cand)
    return out


_GENERATORS = {
    TECHNIQUE_CHAR_INSERTION: _char_insertion_candidates,
    TECHNIQUE_SYNONYM: _synonym_candidates,
    TECHNIQUE_OMISSION: _omission_candidates,
    TECHNIQUE_REORDERING: _reordering_candidates,
    TECHNIQUE_RECODING: _recoding_candidates,
}


def generate_candidate_literals(field_name: Optional[str], literal: str) -> dict[str, list[str]]:
    """technique -> candidate transformed literals, restricted to the
    techniques applicable to this field's category (see module docstring).
    Never includes the input literal itself. Empty dict is a normal,
    expected result for a field/literal this transformer has nothing
    applicable to try against."""
    if not isinstance(literal, str) or not literal:
        return {}
    category = _field_category(field_name)
    out: dict[str, list[str]] = {}
    for technique, generator in _GENERATORS.items():
        if category not in _TECHNIQUE_ALLOWED_CATEGORIES[technique]:
            continue
        cands = [c for c in generator(literal) if c and c != literal]
        if cands:
            out[technique] = cands
    return out


# ---------------------------------------------------------------------------
# Candidate events
# ---------------------------------------------------------------------------


@dataclass
class EvasionVariant:
    technique: str
    field: str
    original_literal: str
    new_literal: str
    event: dict
    provenance: str

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "field": self.field,
            "original_literal": self.original_literal,
            "new_literal": self.new_literal,
            "provenance": self.provenance,
        }


def _substitute_in_value(value: Any, old_literal: str, new_literal: str) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if value == old_literal:
        return new_literal
    if old_literal and old_literal in value:
        return value.replace(old_literal, new_literal, 1)
    return None


def generate_evasions(
    field_name: str,
    literal: str,
    template_event: dict,
    *,
    techniques: Optional[list[str]] = None,
) -> list[EvasionVariant]:
    """Candidate evasions of one (field, literal) atom against one template
    malicious event. `template_event[field_name]` must be a string
    containing `literal` (exactly, or as a substring) - if it isn't, this
    atom can't be exercised against this template and yields nothing
    (mechanic-generated repairs are expected to supply a template whose
    field value is actually built from the atom; this is checked, not
    assumed). Returns [] rather than raising when nothing applies - a
    normal, expected outcome for many (field, literal) pairs, see module
    docstring."""
    if field_name not in template_event:
        return []
    value = template_event[field_name]
    if not isinstance(value, str) or not isinstance(literal, str):
        return []
    candidates = generate_candidate_literals(field_name, literal)
    variants: list[EvasionVariant] = []
    for technique, lits in candidates.items():
        if techniques and technique not in techniques:
            continue
        for new_lit in lits:
            new_value = _substitute_in_value(value, literal, new_lit)
            if new_value is None or new_value == value:
                continue
            new_event = dict(template_event)
            new_event[field_name] = new_value
            variants.append(
                EvasionVariant(
                    technique=technique,
                    field=field_name,
                    original_literal=literal,
                    new_literal=new_lit,
                    event=new_event,
                    provenance=f"mechanical[{technique}]: {field_name} {literal!r} -> {new_lit!r}",
                )
            )
    return variants


# ---------------------------------------------------------------------------
# Harness confirmation - THE HARNESS DECIDES, never this module's own opinion
# ---------------------------------------------------------------------------


@dataclass
class ConfirmedEvasion:
    variant: EvasionVariant
    outcome: rverify.EventOutcome


def confirm_real_evasions(
    original_rule_path: Union[str, Path],
    variants: list[EvasionVariant],
    *,
    pipeline: Optional[Path] = None,
    rsigma_bin: Optional[Path] = None,
) -> tuple[list[ConfirmedEvasion], list[dict]]:
    """Run every candidate through mechanic.verify.evaluate() against the
    ORIGINAL rule. A candidate is a confirmed evasion only if the result is
    TRUSTED and the original does NOT fire on it. Anything else (still
    fires, or unverifiable) is discarded with a stated reason - never
    silently promoted, never silently dropped without a trace."""
    if not variants:
        return [], []
    events = [v.event for v in variants]
    report = rverify.evaluate(original_rule_path, events, pipeline=pipeline, rsigma_bin=rsigma_bin)
    confirmed: list[ConfirmedEvasion] = []
    discarded: list[dict] = []
    for v, o in zip(variants, report.outcomes):
        if o.status == "unverifiable":
            discarded.append({"variant": v.to_dict(), "reason": f"unverifiable: {'; '.join(o.reasons)}"})
        elif o.fired:
            discarded.append(
                {"variant": v.to_dict(), "reason": "the original rule still fires on this candidate - not a genuine evasion of it"}
            )
        else:
            confirmed.append(ConfirmedEvasion(v, o))
    return confirmed, discarded


def generate_confirmed_evasions_for_rule(
    rule_path: Union[str, Path],
    template_event: dict,
    *,
    pipeline: Optional[Path] = None,
    rsigma_bin: Optional[Path] = None,
    techniques: Optional[list[str]] = None,
):
    """End-to-end convenience for gate condition 1: find the rule's own
    fragile atom(s) via mechanic.fragility, generate mechanical candidate
    evasions of each against `template_event`, confirm each against the
    ORIGINAL rule via the harness, and return ready-to-use
    `gate.LabeledEvent(kind="evasion", ...)` items for the confirmed ones
    only.

    Returns (labeled_evasions, discarded, fragile_atoms, rule_tier) - the
    discarded list and the fragile-atom list are always returned too (never
    silently dropped) so callers/reports can show what was tried and why it
    didn't count, not just what worked."""
    from mechanic import gate as rgate  # local import: gate imports verify, not this module - no cycle either way

    fragile, tier = fragile_atoms_for_rule(rule_path)
    all_variants: list[EvasionVariant] = []
    for atom in fragile:
        if atom.field is None or not isinstance(atom.value, str):
            continue
        all_variants.extend(generate_evasions(atom.field, atom.value, template_event, techniques=techniques))
    confirmed, discarded = confirm_real_evasions(rule_path, all_variants, pipeline=pipeline, rsigma_bin=rsigma_bin)
    labeled = [rgate.LabeledEvent(c.variant.event, "evasion", c.variant.provenance) for c in confirmed]
    return labeled, discarded, fragile, tier
