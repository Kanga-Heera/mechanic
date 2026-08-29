"""Stage 3 Phase 3, Part 2: three outcomes, gate-enforced, never LLM-asserted.

`classify_repair()` is the ONLY function that decides what happened to a
proposed repair, and it decides via deterministic checks over
`mechanic.gate` and `mechanic.verify` - never by trusting the LLM's own
opinion of its output. The LLM (`mechanic.repair_generator`) has already
finished its one job (propose a rewrite, or say none is possible) before
this module ever runs; nothing here talks back to it.

Four possible outcomes (the fourth exists purely for defensive-parsing
bookkeeping, per the spec's "generation failures ... as their own
category"):

  GENERATION_FAILURE - the model's response wasn't a parseable rule and
    wasn't the no-repair sentinel either (or the "rule" it returned isn't
    actually loadable/valid Sigma). Not a crash, not a silent skip - a
    reported category of its own.

  RETIRE - no durable observable exists. Two ways to land here:
    (a) the model itself signaled NO_LOGIC_REPAIR_POSSIBLE - reported
        distinctly, since this is NOT gate-verified (there is no rewrite
        to run through the gate at all);
    (b) the model proposed a rewrite, but the gate did not certify it:
        either it FAILED a condition outright, or it PASSED with
        `gate.fully_exercised is False` - the Phase 2 R5 lesson, wired in
        from the first commit of this module: a repair whose durability
        check (EVASIONS_CAUGHT) was never exercised is not a proven
        repair, and for a not-fully-exercised PASS this is exactly where
        it routes, regardless of tier.

  TELEMETRY_REPAIR - the proposed rewrite parses as valid Sigma, but
    references a field this rule's own telemetry cannot provide. Detected
    DETERMINISTICALLY by reusing mechanic.verify's own schema/field-
    presence guard (the same guard from Stage 3 Part 1) against the rule's
    known true-positive event - never by asking the model whether its own
    field choice is realistic. Advice only: no rewrite is shipped for this
    outcome, and the gate is never even run (there's no point verifying a
    rewrite that can't observe its own claimed field).

  LOGIC_REPAIR - the ONLY success outcome: the model proposed a rewrite,
    it isn't a telemetry gap, and `mechanic.gate.run_gate()` returned
    verdict PASS with `fully_exercised` True. This is the same gate, the
    same conditions, and the same fully_exercised signal Stage 3 Phase 2
    Part 4 proved against five hand-made repairs - nothing new is trusted
    here, the LLM's proposal is just one more input to it.

CONDITION-1 EVASIONS COME FROM THE PHASE 2 TRANSFORMER, NEVER THE LLM. This
module calls `mechanic.evasion.generate_confirmed_evasions_for_rule()` -
the exact same deterministic, harness-confirmed generator Phase 2 built
and validated - to produce the evasion set the gate's EVASIONS_CAUGHT
condition checks the repair against. The repair-generating LLM never sees,
produces, or influences these evasions in any way; see
docs/stage3-phase3-independence.md for the by-inspection proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from mechanic import evasion, gate
from mechanic import verify as rverify
from mechanic.repair_generator import GeneratedRepair
from mechanic.verify import _tmp_dir  # reused, not reinvented - same tmp-dir discipline as verify.py itself

OUTCOME_LOGIC_REPAIR = "LOGIC_REPAIR"
OUTCOME_TELEMETRY_REPAIR = "TELEMETRY_REPAIR"
OUTCOME_RETIRE = "RETIRE"
OUTCOME_GENERATION_FAILURE = "GENERATION_FAILURE"


@dataclass
class RepairVerdict:
    outcome: str
    reason: str
    tier: Optional[str]
    fragile_atoms: list[dict]
    generated: dict
    gate_report: Optional[dict] = None
    telemetry_missing_fields: list[str] = field(default_factory=list)
    failed_conditions: list[str] = field(default_factory=list)
    mechanical_evasions_confirmed: int = 0
    mechanical_evasions_discarded: int = 0

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "tier": self.tier,
            "fragile_atoms": self.fragile_atoms,
            "generated": self.generated,
            "gate_report": self.gate_report,
            "telemetry_missing_fields": self.telemetry_missing_fields,
            "failed_conditions": self.failed_conditions,
            "mechanical_evasions_confirmed": self.mechanical_evasions_confirmed,
            "mechanical_evasions_discarded": self.mechanical_evasions_discarded,
        }


def classify_repair(
    original_rule_path: Union[str, Path],
    generated: GeneratedRepair,
    template_tp_event: dict,
    benign_events: list,
    *,
    pipeline: Optional[Path] = None,
    rsigma_bin: Optional[Path] = None,
    tmp_dir: Optional[Path] = None,
) -> RepairVerdict:
    original_rule_path = Path(original_rule_path)
    fragile, tier = evasion.fragile_atoms_for_rule(original_rule_path)
    fragile_dicts = [{"field": a.field, "value": a.value, "tier": a.tier, "reason": a.reason} for a in fragile]

    if generated.no_repair_signal:
        return RepairVerdict(
            outcome=OUTCOME_RETIRE,
            reason=(
                "the model signaled NO_LOGIC_REPAIR_POSSIBLE - there is no rewrite to run through the gate, so "
                "this outcome rests on the model's own claim of absence, NOT an independent gate verdict. "
                "Reported distinctly from a gate-confirmed RETIRE for exactly that reason."
            ),
            tier=tier,
            fragile_atoms=fragile_dicts,
            generated=generated.to_dict(),
        )

    if generated.proposed_rule_yaml is None:
        return RepairVerdict(
            outcome=OUTCOME_GENERATION_FAILURE,
            reason=generated.parse_note or "no proposed rule and no no-repair signal - off-contract model response",
            tier=tier,
            fragile_atoms=fragile_dicts,
            generated=generated.to_dict(),
        )

    with _tmp_dir(tmp_dir) as td:
        repaired_path = td / "proposed_repair.yml"
        repaired_path.write_text(generated.proposed_rule_yaml, encoding="utf-8")

        try:
            rverify.load_rule_info(repaired_path)
        except rverify.VerifyError as e:
            return RepairVerdict(
                outcome=OUTCOME_GENERATION_FAILURE,
                reason=f"proposed rule failed to load: {e}",
                tier=tier,
                fragile_atoms=fragile_dicts,
                generated=generated.to_dict(),
            )
        except Exception as e:  # noqa: BLE001 - model output is untrusted input; never let it crash the batch
            return RepairVerdict(
                outcome=OUTCOME_GENERATION_FAILURE,
                reason=f"proposed rule is not parseable ({type(e).__name__}): {e}",
                tier=tier,
                fragile_atoms=fragile_dicts,
                generated=generated.to_dict(),
            )

        # TELEMETRY_REPAIR: deterministic, via the harness's OWN
        # schema/field-presence guard (Stage 3 Part 1), never the model's
        # opinion of whether its chosen field is realistic.
        probe = rverify.evaluate(repaired_path, [template_tp_event], pipeline=pipeline, rsigma_bin=rsigma_bin, tmp_dir=td)
        probe_outcome = probe.outcomes[0]
        if probe_outcome.status == "unverifiable" and probe_outcome.missing_fields:
            return RepairVerdict(
                outcome=OUTCOME_TELEMETRY_REPAIR,
                reason=(
                    f"repaired rule references field(s) absent from this rule's telemetry: "
                    f"{probe_outcome.missing_fields} - advice only, no rewrite shipped"
                ),
                tier=tier,
                fragile_atoms=fragile_dicts,
                generated=generated.to_dict(),
                telemetry_missing_fields=probe_outcome.missing_fields,
            )

        # Condition-1 evasions: the Phase 2 deterministic transformer,
        # confirmed by the harness against the ORIGINAL rule - never
        # anything the repair-generating LLM produced or saw.
        labeled, discarded, _fragile_again, _tier_again = evasion.generate_confirmed_evasions_for_rule(
            original_rule_path, template_tp_event, pipeline=pipeline, rsigma_bin=rsigma_bin
        )
        malicious = [gate.LabeledEvent(template_tp_event, "original_tp", "rule's own known true positive")] + labeled
        report = gate.run_gate(
            original_rule_path, repaired_path, malicious, benign_events, pipeline=pipeline, rsigma_bin=rsigma_bin
        )

        failed_conditions = [c.name for c in report.conditions if c.passed is False]
        if report.verdict == "PASS" and report.fully_exercised:
            outcome = OUTCOME_LOGIC_REPAIR
            reason = "gate accepted the repair: all applicable conditions passed, fully exercised"
        else:
            outcome = OUTCOME_RETIRE
            reason = (
                f"gate did not certify a durable repair (verdict={report.verdict}, "
                f"fully_exercised={report.fully_exercised})"
                + (f" - failed condition(s): {failed_conditions}" if failed_conditions else "")
            )

        return RepairVerdict(
            outcome=outcome,
            reason=reason,
            tier=tier,
            fragile_atoms=fragile_dicts,
            generated=generated.to_dict(),
            gate_report=report.to_dict(),
            failed_conditions=failed_conditions,
            mechanical_evasions_confirmed=len(labeled),
            mechanical_evasions_discarded=len(discarded),
        )
