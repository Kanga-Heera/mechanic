"""Stage 3 Phase 3, Part 1: the LLM repair generator - tightly scoped.

This is the FIRST and ONLY probabilistic component anywhere in the
mechanic pipeline. Everything it plugs into is deterministic and already
proven with known-answer tests: the verification harness (mechanic.verify,
four silent-zero guards), the four-condition gate (mechanic.gate), the
Uetz-style evasion transformer (mechanic.evasion), multi-record EVTX
accounting, and gate.fully_exercised. The LLM proposes a rewrite onto that
proven ground; it never judges its own output - see mechanic.repair_outcome
for the deterministic classifier that does.

ANTI-CIRCULARITY, ENFORCED IN CODE, NOT JUST PROMPT WORDING: read
docs/kappa-provenance.md before touching this file if you haven't - it is
the cautionary tale this design exists to avoid (an LLM graded against its
own labels invisibly inflates its own success). The boundary here is
structural: `generate_repair()` and everything it calls
(`build_diagnosis`, `build_prompt`) take ONLY a rule path. There is no
parameter, no closure, no import anywhere in this module through which a
benign event set, an evasion variant, or a gate result could reach the
prompt - not "the prompt doesn't mention them," an actual absence of a
code path. `docs/stage3-phase3-independence.md` verifies this claim by
inspection, per the Phase 3 spec's Part 4.

WHAT THE GENERATOR CAN SEE: the rule's own YAML text, and its fragility
diagnosis (tier + fragile atom(s) + reason) via
`mechanic.evasion.fragile_atoms_for_rule` - reused directly, not
re-derived, exactly as mechanic.evasion itself reuses
`mechanic.fragility.classify_rule` rather than re-scoring fragility from
scratch.

WHAT THE GENERATOR RETURNS: exactly the output contract the spec
requires - `proposed_rule_yaml` (or None), the raw model text, and which
model/endpoint produced it. It does NOT return, and is never asked to
return, any judgement of its own repair's quality - that would be exactly
the self-grading the anti-circularity requirement forbids. Parsing the
model's response is defensive throughout: a malformed or off-contract
response is recorded as `parse_note` with `proposed_rule_yaml=None` and
`no_repair_signal=False`, which `mechanic.repair_outcome` treats as a
GENERATION_FAILURE, never a crash and never a silent skip.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from mechanic import evasion, llm_client

# The model must reply with EXACTLY this sentinel (on its own, optionally
# surrounded by whitespace/punctuation) when it judges no durable
# observable exists - never a rewrite AND a hedge in the same response.
NO_REPAIR_SENTINEL = "NO_LOGIC_REPAIR_POSSIBLE"

_SYSTEM_PROMPT = """You are a detection-engineering assistant. You will be shown one fragile \
Sigma detection rule and a diagnosis of exactly which part of it is fragile. Your only job is to \
propose ONE rewrite that keys the detection on a more durable observable while preserving the \
rule's original intent (same logsource, same attack technique) - OR to say plainly that no such \
rewrite is possible.

You are not being asked to judge whether your own rewrite is good, complete, or will pass any \
test. A separate, independent, deterministic system verifies every proposal you make against real \
detection-evaluation tooling; your rewrite's fate is decided there, not by you. Do not include any \
self-assessment, confidence claim, or explanation of why your rewrite should work.

Reply with EXACTLY ONE of the following two things, and nothing else:

1. A complete, valid Sigma rule in YAML, keeping the same `id`, the same `logsource`, and the same \
`tags` (ATT&CK technique tags) as the original, wrapped in a single ```yaml ... ``` fenced code \
block. Nothing before or after the fence.

2. If, and only if, no durable observable exists to rewrite this rule onto (for example: the rule's \
only fragile content is a raw indicator of compromise - an IP, domain, or hash - with no behavioral \
signal underneath it to generalize to), reply with exactly this token and nothing else:
NO_LOGIC_REPAIR_POSSIBLE
"""

_USER_PROMPT_TEMPLATE = """ORIGINAL RULE (id={rule_id}, title={title!r}):

```yaml
{rule_text}
```

FRAGILITY DIAGNOSIS (from mechanic's own structural fragility classifier, tier={tier}):
{atoms_block}

Propose your rewrite (or the NO_LOGIC_REPAIR_POSSIBLE token) now, per the format rules above."""


@dataclass
class RepairDiagnosis:
    rule_path: str
    rule_id: Optional[str]
    title: Optional[str]
    rule_text: str
    tier: Optional[str]
    fragile_atoms: list[dict]  # [{"field", "value", "tier", "reason"}, ...]


@dataclass
class GeneratedRepair:
    proposed_rule_yaml: Optional[str]
    raw_model_text: str
    model: str
    endpoint: str
    no_repair_signal: bool = False
    parse_note: Optional[str] = None
    # Populated only for reasoning models that expose a separate chain-of-
    # thought field (Groq's gpt-oss family does) - never used by any
    # decision logic anywhere in this pipeline, purely qualitative
    # reporting value (e.g. explaining WHY a model declined a case that
    # turned out to have a real repair - see docs/stage3-phase3-status.md).
    raw_reasoning: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "proposed_rule_yaml": self.proposed_rule_yaml,
            "raw_model_text": self.raw_model_text,
            "model": self.model,
            "endpoint": self.endpoint,
            "no_repair_signal": self.no_repair_signal,
            "parse_note": self.parse_note,
            "raw_reasoning": self.raw_reasoning,
        }


def build_diagnosis(rule_path: Union[str, Path]) -> RepairDiagnosis:
    """The ONLY thing this module reads about the rule: its own text, and
    mechanic's existing fragility diagnosis of it - reused via
    `mechanic.evasion.fragile_atoms_for_rule`, never re-derived. No event
    data of any kind is read here."""
    rule_path = Path(rule_path)
    rule_text = rule_path.read_text(encoding="utf-8")
    fragile, tier = evasion.fragile_atoms_for_rule(rule_path)
    # rule_id/title for the prompt header only - reuse verify's loader-backed
    # introspection rather than a second YAML parse of our own.
    from mechanic import verify as rverify

    info = rverify.load_rule_info(rule_path)
    return RepairDiagnosis(
        rule_path=str(rule_path),
        rule_id=info.rule_id,
        title=info.title,
        rule_text=rule_text,
        tier=tier,
        fragile_atoms=[{"field": a.field, "value": a.value, "tier": a.tier, "reason": a.reason} for a in fragile],
    )


def build_prompt(diagnosis: RepairDiagnosis) -> list[dict]:
    """Pure function: diagnosis in, chat messages out. No I/O, nothing else
    reachable from here - this is what makes the anti-circularity
    boundary inspectable in one place (docs/stage3-phase3-independence.md)."""
    if diagnosis.fragile_atoms:
        atoms_block = "\n".join(
            f"  - field={a['field']!r} value={a['value']!r} atom_tier={a['tier']} reason={a['reason']}"
            for a in diagnosis.fragile_atoms
        )
    else:
        atoms_block = "  (no scoreable fragile atom found)"
    user = _USER_PROMPT_TEMPLATE.format(
        rule_id=diagnosis.rule_id, title=diagnosis.title, rule_text=diagnosis.rule_text, tier=diagnosis.tier, atoms_block=atoms_block
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


_YAML_FENCE_RE = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def _extract_response(raw_text: str) -> tuple[Optional[str], bool, Optional[str]]:
    """(proposed_rule_yaml, no_repair_signal, parse_note). Defensive by
    construction: never raises on off-contract model output, always
    returns a classifiable result. Order of checks matters - a fenced YAML
    block always wins over an incidental substring match of the sentinel
    inside prose, since the model was told the fence is the only valid
    rewrite format."""
    text = raw_text.strip()
    fence_match = _YAML_FENCE_RE.search(text)
    if fence_match:
        return fence_match.group(1).strip(), False, None
    # No fence: accept the sentinel only as an (almost) bare token, not as
    # a coincidental substring of a longer explanation the model wasn't
    # supposed to give - stripping common trailing punctuation/quotes only.
    bare = text.strip(" \t\n\r.\"'`")
    if bare == NO_REPAIR_SENTINEL:
        return None, True, None
    if NO_REPAIR_SENTINEL in text:
        return None, False, (
            f"model's response contained the {NO_REPAIR_SENTINEL!r} token but was not an exact match "
            "(extra prose around it) - treating as off-contract, not as a confirmed no-repair signal"
        )
    return None, False, "model response contained neither a ```yaml fenced block nor the NO_LOGIC_REPAIR_POSSIBLE sentinel"


def generate_repair(
    rule_path: Union[str, Path],
    *,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key_env: str = llm_client.API_KEY_ENV,
    temperature: float = 0.2,
    max_tokens: int = 4000,
) -> GeneratedRepair:
    """The one and only LLM call in this entire pipeline. Takes a rule
    path, nothing else - see module docstring for why that's the whole
    anti-circularity guarantee in one function signature. Propagates
    mechanic.llm_client.LLMConfigError / LLMRequestError unchanged rather
    than catching them and fabricating a result: no key, or a failed
    request, means this function raises, never returns a made-up repair."""
    diagnosis = build_diagnosis(rule_path)
    messages = build_prompt(diagnosis)
    response = llm_client.chat_completion(
        messages, model=model, base_url=base_url, api_key_env=api_key_env, temperature=temperature, max_tokens=max_tokens
    )
    proposed, no_repair, note = _extract_response(response.text)
    raw_reasoning = None
    try:
        raw_reasoning = response.raw["choices"][0]["message"].get("reasoning")
    except (KeyError, IndexError, TypeError, AttributeError):
        pass  # not a reasoning model / unexpected shape - purely cosmetic, never fatal
    return GeneratedRepair(
        proposed_rule_yaml=proposed,
        raw_model_text=response.text,
        model=response.model,
        endpoint=response.endpoint,
        no_repair_signal=no_repair,
        parse_note=note,
        raw_reasoning=raw_reasoning,
    )
