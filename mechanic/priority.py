"""Priority / triage (Stage 3, Part 3): explainable review-ordering that
combines behavioral staleness (Part 1) with fragility tier (Part 2).

Part 3's original premise was that these two signals should be FUSED into a
single combined priority score. That premise was made conditional, in
advance, on Task 7's correlation experiment (see RESULTS.md, "Task 7"
section) actually finding an association that survives an age control.

Task 7's result, run on SigmaHQ (n=3,141, externally validated tiers) and
Elastic (n=1,830, secondary, text-path tiers not externally validated;
Splunk pending, see the practical-obstacles section for why):

  - SigmaHQ: whatever tiny, barely-significant association exists
    (Cramer's V=0.056, Fisher's exact p=0.070 not significant) is in the
    WRONG direction relative to the registered prediction and evaporates
    once age is partialled out (partial Spearman rho=0.007, p=0.685).
  - Elastic: a real, moderate association that DOES survive an
    age-stratified Cochran-Mantel-Haenszel test (p=0.019) -- but in the
    OPPOSITE direction to the registered prediction (revised rules skew
    MORE fragile, not less), and its own continuous gradient measure
    (Spearman rho=0.001) shows no effect and also vanishes under
    age-partialling.
  - No population supports the registered prediction surviving an age
    control.

Per the interpretation fixed in advance, this is branch (b): no reliable
combined-score-supporting association. This module therefore does NOT
compute a single fused priority number, and no `--weight` style knob exists
here to average two things Task 7 found don't reliably move together (in
one corpus they move in opposite directions from what would justify
combining them). Both signals stay individually useful and are presented
side by side, sorted for practical scanning, with triage HYPOTHESES offered
as Stage 3 hypotheses to be tested in later work -- never as conclusions,
and never as a verdict on any individual rule ("review this," not "this is
bad").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable, Optional

from mechanic import ast_repr, churn, fragility, loader, semantic_diff
from mechanic.discovery import discover_files

TIER_RANK = fragility.TIER_RANK  # IOC=0, Artifact=1, Tool=2, TTP=3
FRAGILE_TIERS = {"IOC", "Artifact", "Tool"}  # matches Task 7's own 2x2 collapse (non-fragile = TTP alone)

# Fragility/tiering/priority are SIGMA-ONLY in the core - see
# docs/core-vs-experiment.md and docs/multiformat-experimental.md for the
# scoping decision and why. Staleness (churn.py/semantic_diff.py) stays
# format-agnostic; only this module's fragility/priority layer is scoped.
SIGMA_ONLY_FRAGILITY_MESSAGE = (
    "Mechanic core analyses Sigma rules; Elastic/Splunk structural analysis is "
    "experimental and not part of the validated core - see docs/multiformat-experimental.md."
)


class UnsupportedFormatError(ValueError):
    """Raised by `compute_triage` for any `fmt` other than "sigma" - fragility,
    tiering, and priority are Sigma-only in the core (see
    SIGMA_ONLY_FRAGILITY_MESSAGE above). This is NOT a churn.ChurnError: it
    is refused before any git mining or staleness computation happens at
    all, not a failure encountered while computing something - a caller
    that wants Elastic/Splunk fragility/triage should call
    `mechanic.experimental.multiformat.triage.compute_multiformat_triage`
    directly instead, with its lower external-validation bar disclosed."""

    def __init__(self, fmt: str):
        self.fmt = fmt
        super().__init__(f"{SIGMA_ONLY_FRAGILITY_MESSAGE} (requested fmt={fmt!r})")


@dataclass
class FragilitySignal:
    tier: Optional[str]
    confidence: str  # "high" | "medium" | "low"
    and_or_corrected: bool
    unscoreable: bool
    unscoreable_reason: Optional[str]
    structural_findings: list[str]
    structural_detail: dict[str, str]
    atoms: list[dict[str, Any]]
    caveat: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "confidence": self.confidence,
            "and_or_corrected": self.and_or_corrected,
            "unscoreable": self.unscoreable,
            "unscoreable_reason": self.unscoreable_reason,
            "structural_findings": self.structural_findings,
            "structural_detail": self.structural_detail,
            "atoms": self.atoms,
            "caveat": self.caveat,
        }


def _sigma_fragility(path: Path) -> FragilitySignal:
    try:
        rules, failures = loader.load_file(path)
    except Exception as e:  # pragma: no cover - defensive, matches loader's own crash handling
        return FragilitySignal(None, "low", True, True, f"failed to load: {e}", [], {}, [], None)
    if failures or not rules:
        reason = failures[0].message if failures else "no rule documents found in file"
        return FragilitySignal(None, "low", True, True, reason, [], {}, [], None)
    try:
        tree = ast_repr.build_ast(rules[0].rule)
        result = fragility.classify_rule(tree)
    except Exception as e:
        # A rule can load successfully (valid YAML, valid SigmaRule construction)
        # and still fail here - e.g. pySigma's condition parser rejects the
        # deprecated pipe (`| count`/`| near`) syntax at AST-build time, not at
        # load time. One malformed rule must not crash triage for the whole
        # corpus - Stage 1's entire premise was exactly this kind of fault
        # isolation, and Part 3 must not regress it. Reported as unscoreable
        # with the real exception message, not silently skipped or guessed.
        return FragilitySignal(None, "low", True, True, f"AST build/classify failed: {e}", [], {}, [], None)
    atoms = [{"field": a.field, "value": a.value, "tier": a.tier, "reason": a.reason} for a in result.atoms]
    if result.unscoreable:
        return FragilitySignal(
            None, "low", True, True, "structural UNSCOREABLE: " + result.structural_detail.get("UNSCOREABLE", ""),
            result.structural_findings, result.structural_detail, atoms, None,
        )
    if result.tier is None:
        return FragilitySignal(
            None, "low", True, True,
            "insufficient information: no positive (non-negated, non-filter) leaves to classify",
            result.structural_findings, result.structural_detail, atoms, None,
        )
    return FragilitySignal(
        result.tier, "high", True, False, None,
        result.structural_findings, result.structural_detail, atoms, None,
    )


# Elastic/Splunk's own fragility builders (classify_elastic_file/
# classify_splunk_file) used to live here as `_elastic_fragility`/
# `_splunk_fragility` - moved, unchanged, to
# mechanic/experimental/multiformat/multiformat_fragility.py as part of
# scoping the core to Sigma-only (see docs/multiformat-experimental.md).
# `build_triage_report` below is the reusable engine that module composes
# with its own fragility functions; `compute_triage` is the Sigma-only
# entry point every core caller (CLI, GUI) actually uses.


@dataclass
class RuleSignals:
    file: str
    # staleness (Part 1 / Part 1-semantic-diff)
    behavioral_commit_count: Optional[int]
    never_revised: bool
    days_since_behavioral_change: Optional[int]
    age_days: Optional[int]
    staleness_classification_confidence: Optional[str]  # confidence in the commit->behavioral/cosmetic split
    # fragility (Part 2)
    fragility: FragilitySignal
    # derived
    triage_hypotheses: list[str] = field(default_factory=list)

    @property
    def tier_rank(self) -> Optional[int]:
        return TIER_RANK.get(self.fragility.tier) if self.fragility.tier else None

    @property
    def priority(self) -> Priority:
        """CRITICAL/HIGH/MEDIUM/LOW, always paired with the (tier,
        staleness band) cell that produced it - see `compute_priority`."""
        return compute_priority(self)

    @property
    def narrative(self) -> str:
        """Human-readable justification, in prose, for where this rule sits.
        This is the output a SOC engineer actually reads - `mechanic explain`
        leads with this; the field/value tables that follow are the backing
        detail for someone who wants to verify it, not the primary output.
        Every sentence traces to a specific field on this record - nothing
        here is invented commentary."""
        sentences: list[str] = []

        if self.never_revised:
            age = f"{self.age_days} days ago" if self.age_days is not None else "at an unknown date"
            sentences.append(
                f"This rule's detection logic has never been revised since it was created ({age}) - "
                f"every change since then, if any, has been to metadata, formatting, or tests, not to "
                f"what the rule actually matches."
            )
        else:
            sentences.append(
                f"This rule's detection logic has been behaviorally revised {self.behavioral_commit_count} "
                f"time(s), most recently {self.days_since_behavioral_change} days ago."
            )

        f = self.fragility
        if f.unscoreable:
            sentences.append(f"Fragility could not be assessed: {f.unscoreable_reason}.")
            return " ".join(sentences)

        tier_meaning = {
            "IOC": "a raw indicator (a hash, an IP address) that an attacker can change without altering "
            "their actual behavior at all - the least durable kind of match possible",
            "Artifact": "a generic literal (a file path, a string) not tied to any specific tool - an "
            "attacker can typically evade it with a small, cosmetic change",
            "Tool": "a specific named tool or utility - evading it requires an attacker to actually switch "
            "tools, not just rename or reword something",
            "TTP": "a technique-level pattern that is hard to change without abandoning the technique "
            "itself - the most durable kind of match mechanic recognizes",
        }.get(f.tier, f.tier or "unknown")
        sentences.append(f"Its fragility tier is {f.tier}: it matches on {tier_meaning}.")

        if f.confidence == "high":
            sentences.append(
                "This tier was assigned with high confidence: mechanic fully parsed the rule's logic as a "
                "structured syntax tree and combined its conditions using the AND/OR-aware rule validated "
                "against MITRE's Summiting the Pyramid methodology."
            )
        else:
            sentences.append(
                f"This tier was assigned with only {f.confidence} confidence: mechanic could not build a "
                f"real parse tree for this rule's query language, so its logic was approximated from "
                f"regex-extracted fragments of text instead."
            )
        if f.caveat:
            sentences.append(
                "Because of that, this tier does NOT use the AND/OR combination correction that external "
                "validation (against MITRE's STP methodology) showed to be necessary - the correction "
                "requires a real parse tree to walk, which does not exist for this rule's language here. "
                "Treat this tier as less trustworthy than a Sigma/AST-derived one."
            )

        if f.structural_findings:
            sentences.append(
                f"A structural pattern was detected ({', '.join(f.structural_findings)}), which on its own "
                f"is treated as the most durable (TTP) tier regardless of the literal values involved."
            )
        elif f.atoms:
            # Show the atom(s) that actually DROVE the assigned tier, not just
            # the first N in list order - for an AND-linked rule the tier is
            # the MIN across atoms, so an early, higher-tier atom (e.g. an
            # excluded EventID selector) is not what explains the result.
            # Falls back to the first two atoms only if none match (e.g. the
            # tier came from a SELECTOR/OR combination this simple filter
            # doesn't reconstruct) - explicitly weaker phrasing in that case
            # so the sentence never claims a driving atom it didn't verify.
            driving = [a for a in f.atoms if a.get("tier") == f.tier]
            # Prefer a real content match over a placeholder floor value (e.g.
            # "eventid_or_syscall_data_source_selector_excluded" is a
            # structural stand-in, not something an attacker "matches" in any
            # meaningful sense) - sort those to the back rather than let them
            # crowd out the atom that actually explains the tier to a reader.
            driving.sort(key=lambda a: 1 if "excluded" in (a.get("reason") or "") else 0)
            if driving:
                shown = driving[:2]
                verb = "The tier comes from matching on"
            else:
                shown = f.atoms[:2]
                verb = "Contributing values include (not necessarily the ones that set the final tier)"
            parts = []
            for a in shown:
                label = f"{a.get('field')}={a.get('value')!r}"
                if a.get("tier"):
                    label += f" (classified {a['tier']})"
                parts.append(label)
            sentences.append(f"{verb}: {'; '.join(parts)}.")

        if self.triage_hypotheses:
            labels = ", ".join(self.triage_hypotheses)
            sentences.append(
                f"Given both signals together, this rule matches the untested Stage 3 hypothesis label(s) "
                f"'{labels}' - a candidate worth a closer look for that reason, not a conclusion about the "
                f"rule's actual quality."
            )

        sentences.append("Review this - none of the above is a verdict that the rule is broken.")
        return " ".join(sentences)

    @property
    def short_reason(self) -> str:
        """One line, not a paragraph: the specific thing that earned this
        rule its spot in the ranked `triage` table, so an engineer scanning
        the list doesn't have to run `explain` on every row just to find
        out why it's there. Same underlying signal `narrative` uses (the
        driving atom, or a structural finding, or the unscoreable reason)
        condensed to fit a table column."""
        f = self.fragility
        if f.unscoreable:
            reason = f.unscoreable_reason or "could not be scored"
            return reason if len(reason) <= 70 else reason[:67] + "..."
        if f.structural_findings:
            return f"structural: {', '.join(f.structural_findings)}"
        driving = [a for a in f.atoms if a.get("tier") == f.tier]
        driving.sort(key=lambda a: 1 if "excluded" in (a.get("reason") or "") else 0)
        shown = driving[:1] or f.atoms[:1]
        if shown:
            a = shown[0]
            label = f"{a.get('field')}={a.get('value')!r}"
            return label if len(label) <= 70 else label[:67] + "..."
        return f"tier {f.tier}" if f.tier else "no driving atom identified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "narrative": self.narrative,
            "short_reason": self.short_reason,
            "staleness": {
                "behavioral_commit_count": self.behavioral_commit_count,
                "never_revised": self.never_revised,
                "days_since_behavioral_change": self.days_since_behavioral_change,
                "age_days": self.age_days,
                "classification_confidence": self.staleness_classification_confidence,
                "is_stale": _is_stale(self),
            },
            "fragility": self.fragility.to_dict(),
            "is_fragile": _is_fragile(self),
            "needs_attention": _is_fragile(self) and _is_stale(self),
            "priority": self.priority.to_dict(),
            "triage_hypotheses": self.triage_hypotheses,
        }


def _is_stale(sig: RuleSignals) -> bool:
    """Same threshold (`churn.STALE_DAYS`, 730 days / 2yr) and the same
    "> 2yr since the relevant last-touch date" shape as churn.py's own
    validated `pct_stale_over_2yr` metric (RESULTS.md) - applied here to
    the triage-enriched *behavioral* staleness field rather than raw
    organic-commit staleness, since that is the field triage/explain
    already show. This does not recompute or redefine the locked metric;
    it reuses its threshold at the per-rule level for the one-line
    summary and the `--json` `needs_attention` flag."""
    days = sig.age_days if sig.never_revised else sig.days_since_behavioral_change
    return days is not None and days > churn.STALE_DAYS


def _is_fragile(sig: RuleSignals) -> bool:
    return sig.fragility.tier in FRAGILE_TIERS


# ---------------------------------------------------------------------------
# Priority: an explicit 2-axis MATRIX, never a fused score.
#
# Task 7's pre-registered correlation experiment (module docstring above,
# RESULTS.md) found no association between staleness and fragility that
# survives an age control on the one externally-validated corpus - the
# reason this module has never combined the two axes into one number. A
# priority *label* is still useful for triage, so it is computed as a
# transparent LOOKUP over the two axes (a rule's cell in a fixed table),
# never as a formula that blends them - the axes that produced a label are
# always shown alongside it (see `Priority.to_dict`), and the table itself
# is the single, inspectable source of truth below, not buried in code.
# ---------------------------------------------------------------------------

STALENESS_BANDS = ("stale_over_2yr", "aging_6mo_to_2yr", "fresh_under_6mo")
PRIORITY_LABELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Row order matters and is deliberate: IOC first (worst), TTP last (best) -
# this matches TIER_RANK's own ordering (IOC=0 .. TTP=3) and the tier
# semantics already documented everywhere else in this module (see
# `RuleSignals.narrative`'s `tier_meaning`: IOC is "the least durable kind
# of match possible", TTP "the most durable kind of match mechanic
# recognizes") and the external STP validation itself (RESULTS.md: Kendall's
# tau-b = 0.361, p = 0.0010 - mechanic's tier rank tracks MITRE's own
# analytic-robustness score in this direction, not the reverse). A rule
# matching only on a raw, swappable IOC AND left untouched for 2+ years is
# the single most urgent combination this tool can surface: maximally
# evadable, and nobody has looked at it in years - that is the CRITICAL
# cell, not TTP-tier (mechanic's most durable, hardest-to-evade match).
PRIORITY_MATRIX: dict[tuple[str, str], str] = {
    ("IOC", "stale_over_2yr"): "CRITICAL",
    ("IOC", "aging_6mo_to_2yr"): "HIGH",
    ("IOC", "fresh_under_6mo"): "MEDIUM",
    ("Artifact", "stale_over_2yr"): "CRITICAL",
    ("Artifact", "aging_6mo_to_2yr"): "HIGH",
    ("Artifact", "fresh_under_6mo"): "MEDIUM",
    ("Tool", "stale_over_2yr"): "HIGH",
    ("Tool", "aging_6mo_to_2yr"): "MEDIUM",
    ("Tool", "fresh_under_6mo"): "LOW",
    ("TTP", "stale_over_2yr"): "MEDIUM",
    ("TTP", "aging_6mo_to_2yr"): "LOW",
    ("TTP", "fresh_under_6mo"): "LOW",
}


def staleness_band(sig: RuleSignals) -> Optional[str]:
    """One of STALENESS_BANDS, or None if staleness genuinely can't be
    determined (no creation date could be resolved for this rule - never
    silently defaulted to a band). Same threshold constants the rest of
    the module already uses (`churn.STALE_DAYS` = 730d/2yr,
    `churn.RECENT_DAYS` = 182d/6mo) - not new, not redefined."""
    days = sig.age_days if sig.never_revised else sig.days_since_behavioral_change
    if days is None:
        return None
    if days > churn.STALE_DAYS:
        return "stale_over_2yr"
    if days < churn.RECENT_DAYS:
        return "fresh_under_6mo"
    return "aging_6mo_to_2yr"


@dataclass
class Priority:
    """A rule's priority, ALWAYS carrying the two axis values that produced
    it - `label` must never be read or displayed without `tier`/`band`
    alongside it (the CLI and GUI both enforce this; see `to_dict`)."""

    label: Optional[str]  # CRITICAL | HIGH | MEDIUM | LOW | None (uncertain)
    tier: Optional[str]
    staleness_band: Optional[str]
    lower_confidence: bool  # True for text-path (Elastic/Splunk) tiers
    uncertain: bool  # True whenever `label` should NOT be trusted at face value
    uncertainty_reason: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "tier": self.tier,
            "staleness_band": self.staleness_band,
            "lower_confidence": self.lower_confidence,
            "uncertain": self.uncertain,
            "uncertainty_reason": self.uncertainty_reason,
        }


def compute_priority(sig: RuleSignals) -> Priority:
    """Look up `sig`'s cell in PRIORITY_MATRIX - a pure function of the two
    already-computed axes, nothing recomputed or estimated. Uncertainty
    (an unscoreable rule, or a staleness band that can't be determined) is
    surfaced as `uncertain=True` with a stated reason and `label=None`,
    never smoothed into a confident-looking label - the same discipline
    the Stage 3 gate's `fully_exercised` flag applies to repair
    verdicts, applied here to priority instead."""
    f = sig.fragility
    band = staleness_band(sig)
    lower_confidence = bool(f.caveat)

    if f.unscoreable or f.tier is None:
        return Priority(
            label=None,
            tier=None,
            staleness_band=band,
            lower_confidence=lower_confidence,
            uncertain=True,
            uncertainty_reason=f.unscoreable_reason or "fragility tier could not be assigned",
        )
    if band is None:
        return Priority(
            label=None,
            tier=f.tier,
            staleness_band=None,
            lower_confidence=lower_confidence,
            uncertain=True,
            uncertainty_reason="staleness band unknown: no creation date could be resolved for this rule",
        )
    label = PRIORITY_MATRIX[(f.tier, band)]
    return Priority(
        label=label,
        tier=f.tier,
        staleness_band=band,
        lower_confidence=lower_confidence,
        uncertain=False,
        uncertainty_reason=None,
    )


def priority_matrix_schema() -> dict[str, Any]:
    """The matrix itself, in a shape a GUI legend (or any other consumer)
    can render directly without hard-coding the cell values a second
    time - `mechanic triage --json`'s top-level `priority_matrix` key is
    exactly this."""
    tiers_worst_to_best = ["IOC", "Artifact", "Tool", "TTP"]
    return {
        "tiers_worst_to_best": tiers_worst_to_best,
        "staleness_bands_stale_to_fresh": list(STALENESS_BANDS),
        "labels_worst_to_best": list(PRIORITY_LABELS),
        "cells": [
            {"tier": tier, "staleness_band": band, "label": PRIORITY_MATRIX[(tier, band)]}
            for tier in tiers_worst_to_best
            for band in STALENESS_BANDS
        ],
        "rationale": (
            "Priority is a lookup over two independent, separately-reported axes "
            "(fragility tier x staleness band), never a blended/fused score - Task 7's "
            "pre-registered correlation experiment found no association between them "
            "that survives an age control (RESULTS.md), so a formula combining them "
            "would manufacture false precision. IOC is the worst (least durable) "
            "fragility tier and TTP the best (most durable), matching mechanic's "
            "STP-validated tier ordering (Kendall's tau-b = 0.361, p = 0.0010)."
        ),
        # Same fact as `rationale` above, said in plain language for a UI
        # legend - not a different rule, just a shorter one. Kept separate
        # so the technical `rationale` (asserted on by
        # tests/test_priority_matrix.py) never has to trade precision for
        # readability, or vice versa.
        "rationale_plain": (
            "Two separate signals, never combined into one score: HOW the rule matches "
            "(fragility - can an attacker dodge it by changing one detail?) and "
            "WHEN it was last actually revised (staleness). We tested whether these "
            "two move together and found they don't, so averaging or weighting them "
            "into a single number would just be a guess dressed up as a metric. "
            "Worst fragility is a raw indicator (IP, hash, filename) that's trivial "
            "to swap out; best is behavior an attacker can't easily avoid without "
            "changing what they actually do."
        ),
    }


@dataclass
class TriageReport:
    root: str
    fmt: str
    mechanical_threshold: float
    rule_count: int
    scoreable: list[RuleSignals]
    unscoreable: list[RuleSignals]
    disclosure: str
    # Passed through from churn.StalenessReport (see churn.py's
    # `_assess_history_health`) - "healthy" unless the repo's mined history
    # was too thin for the staleness/never-revised signals above to be
    # reliable. Never blocks triage from running; purely a caveat.
    history_health: str = "healthy"
    history_health_reasons: list[str] = field(default_factory=list)

    def one_line_summary(self) -> str:
        """"N rules, X fragile, Y stale, Z need attention (fragile AND
        stale)" - the single line meant to be readable by someone who has
        never opened this repo's docs. Counted over ALL discovered rules
        (scoreable + unscoreable); unscoreable rules can still be "stale"
        (staleness doesn't depend on fragility having succeeded) but are
        never "fragile" (no tier was assigned, on purpose - never
        defaulted) and so never count toward "need attention" either."""
        all_rules = self.scoreable + self.unscoreable
        n = len(all_rules)
        fragile = sum(1 for r in all_rules if _is_fragile(r))
        stale = sum(1 for r in all_rules if _is_stale(r))
        need_attention = sum(1 for r in all_rules if _is_fragile(r) and _is_stale(r))
        return f"{n} rules, {fragile} fragile, {stale} stale, {need_attention} need attention (fragile AND stale)"

    def bucket_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.scoreable:
            for h in r.triage_hypotheses:
                counts[h] = counts.get(h, 0) + 1
        return counts

    def priority_breakdown(self) -> dict[str, int]:
        """Counts of CRITICAL/HIGH/MEDIUM/LOW across every discovered rule
        (scoreable + unscoreable), plus how many have no label at all
        because priority was genuinely uncertain (an unscoreable rule, or
        an unresolvable staleness band) - never folded silently into one
        of the four labels. Always sums to `rule_count`."""
        counts: dict[str, int] = {label: 0 for label in PRIORITY_LABELS}
        counts["UNCERTAIN"] = 0
        for r in self.scoreable + self.unscoreable:
            p = r.priority
            if p.uncertain or p.label is None:
                counts["UNCERTAIN"] += 1
            else:
                counts[p.label] += 1
        return counts

    def sorted_scoreable(self, ordering: str = "tier_first") -> list[RuleSignals]:
        """Practical scan order, NOT a validated priority score (see module
        docstring: Task 7 found no association reliable enough to fuse these
        into one number, so there is no weight to tune - `ordering` picks
        between two clearly-labelled, unweighted sort strategies instead,
        which is what "alternative weighting" collapses to once a fused
        numeric score isn't the design).

        `"tier_first"` (default): fragility tier rank ascending (IOC first)
        as the primary key -- chosen because tier is the only axis with any
        external validation (STP) behind it -- then never-revised first,
        then longest-stale first, as tie-breaks.

        `"staleness_first"`: the alternative ordering -- never-revised first,
        then longest-stale first, as the PRIMARY key, with tier rank only as
        a tie-break. Reported in RESULTS.md's threshold/ordering-sensitivity
        section via rank correlation against `"tier_first"`, the same way an
        alternative weighting's effect would be reported if a combined score
        existed.

        `"priority_first"`: sorts by the PRIORITY MATRIX label
        (CRITICAL..LOW, uncertain last) - still not a fused score, just a
        third unweighted lookup-based ordering, since the label is itself a
        pure lookup over the same two axes (see `compute_priority`), not a
        new number."""
        if ordering == "staleness_first":
            return sorted(
                self.scoreable,
                key=lambda r: (
                    0 if r.never_revised else 1,
                    -(r.days_since_behavioral_change or r.age_days or 0),
                    r.tier_rank if r.tier_rank is not None else 99,
                ),
            )
        if ordering == "priority_first":
            label_rank = {label: i for i, label in enumerate(PRIORITY_LABELS)}
            return sorted(
                self.scoreable,
                key=lambda r: (
                    label_rank.get(r.priority.label, 99),
                    r.tier_rank if r.tier_rank is not None else 99,
                    0 if r.never_revised else 1,
                    -(r.days_since_behavioral_change or r.age_days or 0),
                ),
            )
        return sorted(
            self.scoreable,
            key=lambda r: (
                r.tier_rank if r.tier_rank is not None else 99,
                0 if r.never_revised else 1,
                -(r.days_since_behavioral_change or r.age_days or 0),
            ),
        )

    def to_dict(self, top_n: Optional[int] = None, ordering: str = "tier_first") -> dict[str, Any]:
        ordered = self.sorted_scoreable(ordering=ordering)
        if top_n is not None:
            ordered = ordered[:top_n]
        return {
            "root": self.root,
            "fmt": self.fmt,
            "mechanical_threshold": self.mechanical_threshold,
            "ordering": ordering,
            "rule_count": self.rule_count,
            "scoreable_count": len(self.scoreable),
            "unscoreable_count": len(self.unscoreable),
            "summary": self.one_line_summary(),
            "bucket_counts": self.bucket_counts(),
            "priority_breakdown": self.priority_breakdown(),
            "priority_matrix": priority_matrix_schema(),
            "disclosure": self.disclosure,
            "history_health": self.history_health,
            "history_health_reasons": self.history_health_reasons,
            "rules": [r.to_dict() for r in ordered],
            "unscoreable": [r.to_dict() for r in self.unscoreable],
        }


_DISCLOSURE = (
    "This is a review-priority ORDERING, not a validated combined score. Task 7's "
    "pre-registered correlation experiment (RESULTS.md) found no association between "
    "behavioral staleness and fragility tier that survives an age control in any "
    "corpus tested -- where an association exists at all (Elastic, categorical test "
    "only), it runs opposite to what would justify fusing the two signals. The two "
    "axes are shown side by side and sorted for scanning convenience (fragility tier, "
    "the only externally-validated axis, first); nothing below is a verdict. "
    "Triage-hypothesis labels are Stage 3 hypotheses to be tested, not conclusions. "
    "Review this -- do not treat placement or a hypothesis label as 'this rule is bad.'"
)


def _hypotheses(behavioral_commit_count: Optional[int], never_revised: bool, tier: Optional[str], age_days: Optional[int]) -> list[str]:
    """Heuristic Stage 3 hypotheses from documented combinations of the two
    axes. Thresholds (churn.STALE_DAYS, its double) are arbitrary,
    unvalidated cutoffs chosen for plausibility, not derived from Task 7
    (which found no statistical basis to combine these axes at all). These
    are candidates for later testing, not findings."""
    hyps: list[str] = []
    if tier is None:
        return hyps
    is_fragile = tier in FRAGILE_TIERS
    is_old = (age_days or 0) > churn.STALE_DAYS
    is_very_old = (age_days or 0) > (2 * churn.STALE_DAYS)
    ever_revised = bool(behavioral_commit_count and behavioral_commit_count > 0)

    if is_fragile and ever_revised:
        hyps.append("likely-repairable")
    if never_revised and is_old:
        hyps.append("likely-needs-telemetry-check")
    if is_fragile and never_revised and is_very_old:
        hyps.append("likely-retire")
    return hyps


def build_triage_report(
    path: Path,
    fragility_fn: Callable[[Path], FragilitySignal],
    fmt: str = "sigma",
    mechanical_threshold: float = churn.DEFAULT_THRESHOLD,
    subdir: Optional[str] = None,
    as_of: Optional[date] = None,
    all_facts: Optional[list] = None,
    refresh: bool = False,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    mining_timeout: Optional[float] = None,
) -> TriageReport:
    """The reusable triage ENGINE: mines git history once (from a disk cache when
    available - see `churn.mine_commits_cached`), runs staleness + semantic
    diff (Part 1) and fragility classification (Part 2) per rule, and
    assembles the side-by-side (not combined) triage view.

    `fragility_fn` is the per-file classifier this engine calls for every
    discovered rule - the one axis this function does NOT hard-code, so it
    can be reused for more than Sigma. `compute_triage` below is the
    CORE's own, Sigma-only public entry point (every CLI/GUI call site uses
    that, never this function directly) - it always passes `_sigma_fragility`
    and refuses any other `fmt` before ever reaching here. The Elastic/Splunk
    quarantined experiment
    (`mechanic.experimental.multiformat.triage.compute_multiformat_triage`)
    is the only other caller, passing its own `classify_elastic_file`/
    `classify_splunk_file` instead - see docs/multiformat-experimental.md.
    This function has no opinion about which `fmt`/`fragility_fn` pairing is
    "supported"; that scoping decision lives entirely in `compute_triage`.

    `all_facts`, if given (e.g. because a caller is comparing several
    `mechanical_threshold` values against the same repo IN ONE PROCESS),
    skips mining entirely - avoids the exact 3x-redundant-mining mistake
    this project already found and fixed once in
    `part3_correlation_gather.py`. If not given, mining goes through
    `churn.mine_commits_cached`, which persists the result keyed by the
    repo's current HEAD commit, so repeated invocations ACROSS separate
    process runs (the CLI, or a restarted script) don't re-pay the mining
    cost either - this is what actually fixed the "10-minute stall on every
    restart" problem found while gathering Part 3's validation data.

    `refresh=True` forces `mine_commits_cached` to re-mine regardless of
    cache state (wired to `mechanic triage --refresh` / `mechanic explain
    --refresh`); ignored if `all_facts` is supplied directly.

    `progress_cb`, if given, is called `(stage, done, total, detail="")` at
    each real checkpoint - `("cache_hit"|"mining", n, 0)` during history
    mining (from `churn.mine_commits_cached`; `total` unknown, always 0),
    then `("staleness", 0, 1)`, then repeatedly `("semantic_diff", done,
    total, canonical_file)` through the per-touch behavioral diff pass (the
    dominant cost at corpus scale - ~93% of a full SigmaHQ run, see
    QUICKSTART.md's "honest timing note"), then repeatedly `("classifying",
    i, total_rules, rule_file)` through the per-rule fragility pass. `detail`
    is always the 4th positional arg but every stage before semantic_diff
    passes it implicitly via the callback's own default, so a callback
    defined as `def cb(stage, done, total, detail=""): ...` handles every
    call uniformly. A callback that raises out of a call aborts the whole
    computation at that checkpoint (the GUI uses this for its Stop button -
    see `mechanic/gui/server.py`); this function does nothing special with
    that beyond letting the exception propagate, same as any other error.

    `mining_timeout`, if given (seconds), bounds the mining pass with a hard
    wall-clock budget (`churn.MiningTimeoutError` on expiry) - see
    `churn._mine_with_timeout`. Ignored when `all_facts` is supplied
    directly (no mining happens in that case). `None` (default) behaves
    exactly as before this parameter existed - no timeout is applied.
    `None` by default, and every existing core CLI call site passes
    nothing, so behavior and output are byte-for-byte unchanged when it's
    not used.
    """
    root = Path(path)
    as_of = as_of or date.today()
    if all_facts is None:
        mining_cb = (lambda stage, n: progress_cb(stage, n, 0)) if progress_cb is not None else None
        all_facts = churn.mine_commits_cached(
            root, fmt, subdir=subdir, refresh=refresh, progress_cb=mining_cb, timeout=mining_timeout
        )
    if progress_cb is not None:
        progress_cb("staleness", 0, 1)
    staleness_report = churn.compute_staleness(root, fmt, mechanical_threshold, as_of=as_of, subdir=subdir, all_facts=all_facts)
    if progress_cb is not None:
        progress_cb("semantic_diff", 0, 1)
    diff_report = semantic_diff.compute_semantic_diff(
        root,
        fmt,
        mechanical_threshold,
        subdir=subdir,
        as_of=as_of,
        staleness_report=staleness_report,
        all_facts=all_facts,
        progress_cb=(
            (lambda done, total, detail: progress_cb("semantic_diff", done, total, detail))
            if progress_cb is not None
            else None
        ),
    )
    enriched = diff_report.staleness or staleness_report

    renamed_to = churn._build_renamed_to(all_facts)
    rules_root = (root / subdir) if subdir else root
    current_rel = {str(p.relative_to(root)).replace("\\", "/") for p in discover_files(rules_root, fmt)}
    earliest: dict[str, date] = {}
    for f in all_facts:
        for touched in f.rule_paths_touched:
            canonical = churn._resolve_canonical(touched, renamed_to)
            if canonical not in current_rel:
                continue
            if canonical not in earliest or f.author_date < earliest[canonical]:
                earliest[canonical] = f.author_date

    scoreable: list[RuleSignals] = []
    unscoreable: list[RuleSignals] = []
    total_rules = len(enriched.rules)
    for i, r in enumerate(enriched.rules):
        if progress_cb is not None and (i % 20 == 0 or i == total_rules - 1):
            progress_cb("classifying", i + 1, total_rules, r.file)
        full_path = root / r.file
        frag = fragility_fn(full_path)
        creation_date = earliest.get(r.file)
        age_days = (as_of - creation_date).days if creation_date else None
        never_revised = (r.behavioral_commit_count or 0) == 0
        sig = RuleSignals(
            file=r.file,
            behavioral_commit_count=r.behavioral_commit_count,
            never_revised=never_revised,
            days_since_behavioral_change=r.days_since_behavioral_change,
            age_days=age_days,
            staleness_classification_confidence=r.classification_confidence,
            fragility=frag,
        )
        if frag.unscoreable:
            unscoreable.append(sig)
        else:
            sig.triage_hypotheses = _hypotheses(sig.behavioral_commit_count, sig.never_revised, frag.tier, sig.age_days)
            scoreable.append(sig)

    return TriageReport(
        root=str(root),
        fmt=fmt,
        mechanical_threshold=mechanical_threshold,
        rule_count=len(enriched.rules),
        scoreable=scoreable,
        unscoreable=unscoreable,
        disclosure=_DISCLOSURE,
        history_health=staleness_report.history_health,
        history_health_reasons=staleness_report.history_health_reasons,
    )


def compute_triage(
    path: Path,
    fmt: str = "sigma",
    mechanical_threshold: float = churn.DEFAULT_THRESHOLD,
    subdir: Optional[str] = None,
    as_of: Optional[date] = None,
    all_facts: Optional[list] = None,
    refresh: bool = False,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    mining_timeout: Optional[float] = None,
) -> TriageReport:
    """The CORE's public triage entry point - every CLI (`mechanic triage`/
    `mechanic explain`) and GUI call site uses this, never `build_triage_report`
    directly. SIGMA-ONLY: fragility, tiering, and priority are validated
    against MITRE's STP methodology on Sigma's real AST (see RESULTS.md and
    docs/multiformat-experimental.md) and nowhere else, so any `fmt` other
    than `"sigma"` is refused immediately, before any git-history mining
    happens, with `UnsupportedFormatError` - never a silently-produced
    low-confidence tier dressed as a real one.

    Staleness (`mechanic staleness`, `churn.compute_staleness`) is
    deliberately NOT scoped this way - git history is real regardless of
    rule format, so that command stays format-agnostic. This function only
    scopes the fragility/tiering/priority layer triage adds on top - see
    docs/core-vs-experiment.md, "The staleness-vs-fragility scoping
    decision".

    Every parameter below is forwarded unchanged to `build_triage_report`
    (paired with the core's own `_sigma_fragility`) - see that function's
    docstring for what each one does; nothing about the Sigma computation
    itself changed by this split (it is the exact same code that used to run
    directly in this function's body).
    """
    if fmt != "sigma":
        raise UnsupportedFormatError(fmt)
    return build_triage_report(
        path,
        _sigma_fragility,
        fmt=fmt,
        mechanical_threshold=mechanical_threshold,
        subdir=subdir,
        as_of=as_of,
        all_facts=all_facts,
        refresh=refresh,
        progress_cb=progress_cb,
        mining_timeout=mining_timeout,
    )
