"""Stage 3 Part 3: the four-condition repair-verification gate.

Deterministic judge over mechanic.verify's harness. Given an original rule,
a repaired rule, a set of malicious events (both the original's own known
true positives and hand-authored/mechanical evasion variants of it, each
labeled with provenance), and a benign baseline, decides whether the repair:

  1. EVASIONS_CAUGHT        - repaired fires on evasions the original missed
  2. ORIGINAL_STILL_CAUGHT  - repaired still fires on the original's own TPs
  3. NO_NEW_FALSE_POSITIVES - repaired fires on no benign event the
                               original didn't already fire on
  4. INTENT_PRESERVED       - same logsource, same ATT&CK technique tags
                               (structural/metadata only - no RSigma call)

Any UNVERIFIABLE harness result inside a condition makes that condition
UNVERIFIABLE, and any UNVERIFIABLE condition makes the overall verdict
UNVERIFIABLE - never silently averaged into a PASS or FAIL. Conditions 1-3
go through mechanic.verify.evaluate() (the same trusted/unverifiable guard
Part 1 built); condition 4 is pure rule metadata.

Deliberate scope note: RSigma's own `rule tune` command independently
re-verifies "does every supplied TP still fire" as part of generating a
filter (confirmed live in docs/stage3-harness-evaluation.md, Task 2).
Condition 2 here goes through the harness's own evaluate() instead of
shelling out to `rule tune`, for one reason: `rule tune` exists to propose
and verify a *new suppression filter*, which needs a synthetic
false-positive set to do anything useful; invoking it here just to
re-confirm firing would mean fabricating FP events for no purpose, and
would run condition 2 through a different trust path than conditions 1 and
3. One harness, one guard, for all three event-based conditions - simpler
to reason about and to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional, Union

from mechanic import verify as rverify

EventLike = Union[dict, Path, str]


@dataclass
class LabeledEvent:
    event: EventLike
    kind: Literal["original_tp", "evasion"]
    provenance: str = ""


@dataclass
class ConditionResult:
    name: str
    status: Literal["trusted", "unverifiable"]
    passed: Optional[bool]  # None when status == "unverifiable", or when not applicable (no events supplied)
    applicable: bool = True
    evidence: dict = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "passed": self.passed,
            "applicable": self.applicable,
            "evidence": self.evidence,
            "reasons": self.reasons,
        }


@dataclass
class GateReport:
    original_rule: str
    repaired_rule: str
    conditions: list[ConditionResult]
    verdict: Literal["PASS", "FAIL", "UNVERIFIABLE"]

    def condition(self, name: str) -> ConditionResult:
        return next(c for c in self.conditions if c.name == name)

    @property
    def fully_exercised(self) -> bool:
        """False when at least one condition was `applicable=False` (no
        events of that kind were supplied) - a PASS reached with a
        not-applicable condition rested on FEWER checks than a normal PASS,
        and callers must not treat it the same. Found to matter concretely
        in Stage 3 Phase 2 Part 4: a rule whose only fragile atom is a raw
        IOC (e.g. DestinationIp) gets zero mechanically-generated evasions
        by design (mechanic.evasion only targets command-line-shaped
        fields - see its module docstring), so EVASIONS_CAUGHT comes back
        not-applicable and a repair that does NOT actually resist evasion
        (widening an IP to a /24) can reach an overall PASS purely on
        conditions 2-4. That PASS is real (nothing was faked), but it is
        NOT evidence the repair resists evasion - see
        docs/stage3-phase2-status.md."""
        return all(c.applicable for c in self.conditions)

    def to_dict(self) -> dict:
        return {
            "original_rule": self.original_rule,
            "repaired_rule": self.repaired_rule,
            "verdict": self.verdict,
            "fully_exercised": self.fully_exercised,
            "conditions": [c.to_dict() for c in self.conditions],
        }


# ---------------------------------------------------------------------------
# Shared batch-evaluation helper
# ---------------------------------------------------------------------------


def _evaluate_batch(
    rule_path: Path, items: list[EventLike], *, pipeline: Optional[Path] = None, rsigma_bin: Optional[Path] = None
) -> list[rverify.EventOutcome]:
    """Evaluate `rule_path` against a mixed list of events (JSON dicts
    and/or single-record EVTX Paths), preserving input order. Dict events
    are batched into one harness call; each EVTX path gets its own call
    (every EVTX fixture used in this phase is an independent single-record
    file - see mechanic/verify.py's module docstring for why multi-record
    EVTX isn't attempted yet)."""
    outcomes: list[Optional[rverify.EventOutcome]] = [None] * len(items)
    dict_indices = [i for i, it in enumerate(items) if isinstance(it, dict)]
    if dict_indices:
        dict_events = [items[i] for i in dict_indices]
        report = rverify.evaluate(rule_path, dict_events, pipeline=pipeline, rsigma_bin=rsigma_bin)
        for local_idx, global_idx in enumerate(dict_indices):
            outcomes[global_idx] = report.outcomes[local_idx]
    for i, it in enumerate(items):
        if isinstance(it, dict):
            continue
        report = rverify.evaluate(rule_path, Path(it), pipeline=pipeline, rsigma_bin=rsigma_bin)
        outcomes[i] = report.outcomes[0]
    return outcomes  # type: ignore[return-value]


def _all_trusted_fired(outcomes: list[rverify.EventOutcome]) -> tuple[Optional[bool], list[str]]:
    """(passed, reasons). passed is None iff at least one outcome was
    unverifiable - callers must surface the whole condition as
    unverifiable rather than trusting the rest of the batch."""
    bad = [o for o in outcomes if o.status == "unverifiable"]
    if bad:
        return None, [f"event #{o.index}: {'; '.join(o.reasons)}" for o in bad]
    not_fired = [o.index for o in outcomes if not o.fired]
    if not_fired:
        return False, [f"event(s) at index {not_fired} did not fire"]
    return True, []


# ---------------------------------------------------------------------------
# The four conditions
# ---------------------------------------------------------------------------


def evasions_caught(
    original: Path, repaired: Path, evasions: list[LabeledEvent], *, pipeline: Optional[Path] = None, rsigma_bin: Optional[Path] = None
) -> ConditionResult:
    events = [e.event for e in evasions]
    if not events:
        return ConditionResult("EVASIONS_CAUGHT", "trusted", None, applicable=False, reasons=["no evasion events supplied"])
    repaired_outcomes = _evaluate_batch(repaired, events, pipeline=pipeline, rsigma_bin=rsigma_bin)
    original_outcomes = _evaluate_batch(original, events, pipeline=pipeline, rsigma_bin=rsigma_bin)
    passed, reasons = _all_trusted_fired(repaired_outcomes)
    status = "unverifiable" if passed is None else "trusted"
    original_missed, _ = _all_trusted_fired(original_outcomes)
    if original_missed is not False and original_missed is not None:
        reasons.append(
            "WARNING: the original rule also fired on one or more of these events - "
            "they may not be genuine evasions of the original (construction issue, not a gate failure)"
        )
    evidence = {
        "count": len(events),
        "provenance": [e.provenance for e in evasions],
        "repaired_fired": [o.fired if o.status == "trusted" else None for o in repaired_outcomes],
        "original_fired": [o.fired if o.status == "trusted" else None for o in original_outcomes],
    }
    return ConditionResult("EVASIONS_CAUGHT", status, passed, evidence=evidence, reasons=reasons)


def original_still_caught(
    original: Path, repaired: Path, original_tps: list[LabeledEvent], *, pipeline: Optional[Path] = None, rsigma_bin: Optional[Path] = None
) -> ConditionResult:
    events = [e.event for e in original_tps]
    if not events:
        return ConditionResult(
            "ORIGINAL_STILL_CAUGHT", "trusted", None, applicable=False, reasons=["no original-true-positive events supplied"]
        )
    repaired_outcomes = _evaluate_batch(repaired, events, pipeline=pipeline, rsigma_bin=rsigma_bin)
    original_outcomes = _evaluate_batch(original, events, pipeline=pipeline, rsigma_bin=rsigma_bin)
    passed, reasons = _all_trusted_fired(repaired_outcomes)
    status = "unverifiable" if passed is None else "trusted"
    original_ok, original_reasons = _all_trusted_fired(original_outcomes)
    if original_ok is False:
        reasons.append(f"WARNING: the original rule itself did not fire on all declared TPs ({original_reasons}) - mislabeled fixture?")
    evidence = {
        "count": len(events),
        "provenance": [e.provenance for e in original_tps],
        "repaired_fired": [o.fired if o.status == "trusted" else None for o in repaired_outcomes],
        "original_fired": [o.fired if o.status == "trusted" else None for o in original_outcomes],
    }
    return ConditionResult("ORIGINAL_STILL_CAUGHT", status, passed, evidence=evidence, reasons=reasons)


def no_new_false_positives(
    original: Path, repaired: Path, benign: list[EventLike], *, pipeline: Optional[Path] = None, rsigma_bin: Optional[Path] = None
) -> ConditionResult:
    if not benign:
        return ConditionResult("NO_NEW_FALSE_POSITIVES", "trusted", None, applicable=False, reasons=["no benign events supplied"])
    repaired_outcomes = _evaluate_batch(repaired, benign, pipeline=pipeline, rsigma_bin=rsigma_bin)
    original_outcomes = _evaluate_batch(original, benign, pipeline=pipeline, rsigma_bin=rsigma_bin)
    bad = [o for o in repaired_outcomes + original_outcomes if o.status == "unverifiable"]
    if bad:
        return ConditionResult(
            "NO_NEW_FALSE_POSITIVES", "unverifiable", None, reasons=[f"event #{o.index}: {'; '.join(o.reasons)}" for o in bad]
        )
    new_fps = [i for i in range(len(benign)) if repaired_outcomes[i].fired and not original_outcomes[i].fired]
    pre_existing_fps = [i for i in range(len(benign)) if repaired_outcomes[i].fired and original_outcomes[i].fired]
    evidence = {
        "count": len(benign),
        "original_fp_count": sum(1 for o in original_outcomes if o.fired),
        "repaired_fp_count": sum(1 for o in repaired_outcomes if o.fired),
        "new_fps": new_fps,
        "pre_existing_fps_still_present": pre_existing_fps,
    }
    passed = len(new_fps) == 0
    reasons = [] if passed else [f"repaired rule fires on {len(new_fps)} benign event(s) the original did not: indices {new_fps}"]
    return ConditionResult("NO_NEW_FALSE_POSITIVES", "trusted", passed, evidence=evidence, reasons=reasons)


def intent_preserved(original: Path, repaired: Path) -> ConditionResult:
    """Pure structural/metadata check - no event set, no RSigma call."""
    try:
        original_info = rverify.load_rule_info(original)
        repaired_info = rverify.load_rule_info(repaired)
    except rverify.VerifyError as e:
        return ConditionResult("INTENT_PRESERVED", "unverifiable", None, reasons=[str(e)])
    logsource_match = original_info.logsource == repaired_info.logsource
    attack_match = set(original_info.attack_tags) == set(repaired_info.attack_tags)
    passed = logsource_match and attack_match
    reasons = []
    if not logsource_match:
        reasons.append(f"logsource changed: {original_info.logsource} -> {repaired_info.logsource}")
    if not attack_match:
        reasons.append(f"ATT&CK tags changed: {sorted(original_info.attack_tags)} -> {sorted(repaired_info.attack_tags)}")
    evidence = {
        "original_logsource": original_info.logsource,
        "repaired_logsource": repaired_info.logsource,
        "original_attack_tags": original_info.attack_tags,
        "repaired_attack_tags": repaired_info.attack_tags,
    }
    return ConditionResult("INTENT_PRESERVED", "trusted", passed, evidence=evidence, reasons=reasons)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def run_gate(
    original_rule: Union[str, Path],
    repaired_rule: Union[str, Path],
    malicious_events: list[LabeledEvent],
    benign_events: list[EventLike],
    *,
    pipeline: Optional[Path] = None,
    rsigma_bin: Optional[Path] = None,
) -> GateReport:
    original_rule, repaired_rule = Path(original_rule), Path(repaired_rule)
    evasions = [e for e in malicious_events if e.kind == "evasion"]
    original_tps = [e for e in malicious_events if e.kind == "original_tp"]

    conditions = [
        evasions_caught(original_rule, repaired_rule, evasions, pipeline=pipeline, rsigma_bin=rsigma_bin),
        original_still_caught(original_rule, repaired_rule, original_tps, pipeline=pipeline, rsigma_bin=rsigma_bin),
        no_new_false_positives(original_rule, repaired_rule, benign_events, pipeline=pipeline, rsigma_bin=rsigma_bin),
        intent_preserved(original_rule, repaired_rule),
    ]

    if any(c.status == "unverifiable" for c in conditions):
        verdict: Literal["PASS", "FAIL", "UNVERIFIABLE"] = "UNVERIFIABLE"
    elif any(c.passed is False for c in conditions):
        verdict = "FAIL"
    else:
        verdict = "PASS"
    return GateReport(original_rule=str(original_rule), repaired_rule=str(repaired_rule), conditions=conditions, verdict=verdict)
